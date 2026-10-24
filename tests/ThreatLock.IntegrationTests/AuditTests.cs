using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Time.Testing;
using Npgsql;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Audit;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.Infrastructure.Audit;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>The tamper-evident audit log (SPEC §11): what gets written, and what tampering looks like.</summary>
public class AuditTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    private static async Task<List<AuditEntryView>> ChainAsync(TestUser admin) =>
        (await admin.Client.GetFromJsonAsync<List<AuditEntryView>>("/api/admin/audit?limit=500", Ct))!;

    private static async Task<VerifyResult> VerifyAsync(TestUser admin, AnchorRequest? anchor = null)
    {
        var response = await admin.Client.PostAsJsonAsync("/api/admin/audit/verify", new VerifyRequest(anchor), Ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VerifyResult>(Ct))!;
    }

    /// <summary>
    /// Runs SQL as the PostgreSQL superuser, the way an insider with database access would, with
    /// triggers switched off for the session (<c>session_replication_role = replica</c>, superuser
    /// only): the append-only trigger stops the app, not them.
    /// </summary>
    private async Task SuperuserAsync(string sql, params object[] args)
    {
        await using var connection = new NpgsqlConnection(containers.Postgres.GetConnectionString());
        await connection.OpenAsync(Ct);
        await using (var bypass = new NpgsqlCommand("SET session_replication_role = replica", connection))
        {
            await bypass.ExecuteNonQueryAsync(Ct);
        }

        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var arg in args) command.Parameters.AddWithValue(arg);
        await command.ExecuteNonQueryAsync(Ct);
    }

    /// <summary>An org with a few audited actions: org created, logins, a user created, a policy change, an export.</summary>
    private async Task<TestUser> OrgWithHistoryAsync()
    {
        var owner = await Api.RegisterOrgAsync();
        var member = await Api.CreateUserAsync(owner, "Member");
        await PolicyTests.ChangeAsync(owner, p => p with { TrustedNetworks = ["203.0.113.0/24"] });
        (await member.Client.GetAsync("/api/notes/export", Ct)).EnsureSuccessStatusCode();
        return owner;
    }

    [Fact]
    public async Task Security_actions_build_a_chain_that_verifies()
    {
        var owner = await OrgWithHistoryAsync();

        var chain = await ChainAsync(owner);
        var actions = chain.Select(e => e.Action).ToList();
        Assert.Equal(AuditActions.OrgCreated, actions[0]);
        Assert.Equal(
            [AuditActions.OrgCreated, AuditActions.LoginSucceeded, AuditActions.UserCreated, AuditActions.LoginSucceeded,
             AuditActions.PolicyUpdated, AuditActions.NotesExported],
            actions);
        Assert.Equal(Enumerable.Range(1, chain.Count).Select(i => (long)i), chain.Select(e => e.Seq));
        Assert.Equal(new string('0', 64), chain[0].PrevHash);
        Assert.All(chain.Skip(1), (e, i) => Assert.Equal(chain[i].EntryHash, e.PrevHash));

        var result = await VerifyAsync(owner);
        Assert.Equal((true, chain.Count, chain[^1].EntryHash), (result.Ok, (int)result.Entries, result.Head));
    }

    [Fact]
    public async Task Entries_name_the_actor_and_never_hold_secrets()
    {
        var owner = await Api.RegisterOrgAsync("Asha");
        var member = await Api.CreateUserAsync(owner, "Member");

        var chain = await ChainAsync(owner);
        var created = chain.Single(e => e.Action == AuditActions.UserCreated);
        Assert.Equal((ActorTypes.Admin, "Asha", member.User.Id.ToString()), (created.ActorType, created.ActorName, created.TargetId));

        var everything = string.Join('\n', chain.Select(e => e.Details.GetRawText()));
        Assert.DoesNotContain(TestData.Password, everything, StringComparison.Ordinal);
        Assert.DoesNotContain(member.AccessToken, everything, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Concurrent_appends_never_fork_the_chain()
    {
        var owner = await Api.RegisterOrgAsync();
        await using var db = containers.Db();
        var audit = new AuditLog(db, TimeProvider.System);

        // Without the advisory lock, writers would read the same head and collide on seq.
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => audit.AppendAsync(
            new AuditRecord(owner.User.OrgId, ActorTypes.System, null, "test.concurrent", Details: new JsonObject { ["i"] = i }), Ct)));

        var result = await VerifyAsync(owner);
        Assert.True(result.Ok, $"{result.Reason} at {result.FirstBrokenSeq}");
        Assert.Equal(42, result.Entries);   // org created + owner login + 40
    }

    [Fact]
    public async Task An_idempotency_key_writes_one_entry_however_often_it_is_appended()
    {
        var owner = await Api.RegisterOrgAsync();
        await using var db = containers.Db();
        var audit = new AuditLog(db, TimeProvider.System);
        var record = new AuditRecord(owner.User.OrgId, ActorTypes.System, null, "test.once", IdempotencyKey: $"test:{Guid.NewGuid()}");

        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => audit.AppendAsync(record, Ct)));

        Assert.Single(results, r => r.Created);
        Assert.Single(results.Select(r => r.Seq).Distinct());
    }

    [Fact]
    public async Task The_table_refuses_updates_deletes_and_truncation_from_the_app()
    {
        var owner = await Api.RegisterOrgAsync();
        await using var db = containers.Db();

        foreach (var sql in new[]
        {
            "UPDATE audit_log SET action = 'x' WHERE org_id = $1",
            "DELETE FROM audit_log WHERE org_id = $1",
            "TRUNCATE audit_log",
        })
        {
            await using var command = db.CreateCommand(sql);
            if (sql.Contains("$1", StringComparison.Ordinal)) command.Parameters.AddWithValue(owner.User.OrgId);
            var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Ct));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }

        Assert.True((await VerifyAsync(owner)).Ok);
    }

    [Fact]
    public async Task Break_B5_an_edit_by_a_superuser_is_named_by_seq()
    {
        var owner = await OrgWithHistoryAsync();
        Assert.True((await VerifyAsync(owner)).Ok);

        // A superuser can switch triggers off for their session and rewrite history...
        await SuperuserAsync(
            """UPDATE audit_log SET details = '{"slug":"nothing-happened"}' WHERE org_id = $1 AND seq = 3""", owner.User.OrgId);

        // ...and nothing else notices: the row looks like any other. The chain does.
        var result = await VerifyAsync(owner);
        Assert.Equal((false, 3L, VerifyReasons.HashMismatch, 2L), (result.Ok, result.FirstBrokenSeq, result.Reason, result.Entries));
    }

    [Fact]
    public async Task Deleting_an_entry_shows_as_a_gap()
    {
        var owner = await OrgWithHistoryAsync();

        await SuperuserAsync("DELETE FROM audit_log WHERE org_id = $1 AND seq = 2", owner.User.OrgId);

        var result = await VerifyAsync(owner);
        Assert.Equal((2L, VerifyReasons.SeqGap), (result.FirstBrokenSeq, result.Reason));
    }

    [Fact]
    public async Task An_anchor_catches_entries_cut_off_the_end()
    {
        var owner = await OrgWithHistoryAsync();
        var before = await VerifyAsync(owner);
        var anchor = new AnchorRequest(before.Entries, before.Head!);   // saved somewhere else
        Assert.True((await VerifyAsync(owner, anchor)).Ok);

        await SuperuserAsync("DELETE FROM audit_log WHERE org_id = $1 AND seq = $2",
            owner.User.OrgId, before.Entries);

        Assert.True((await VerifyAsync(owner)).Ok);   // the chain alone can't see a shorter chain
        Assert.Equal(VerifyReasons.AnchorMismatch, (await VerifyAsync(owner, anchor)).Reason);
    }

    [Fact]
    public async Task A_bad_anchor_is_rejected()
    {
        var owner = await Api.RegisterOrgAsync();

        var response = await owner.Client.PostAsJsonAsync("/api/admin/audit/verify", new VerifyRequest(new AnchorRequest(1, "nothex")), Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Each_org_sees_and_verifies_only_its_own_chain_and_only_security_admins_may()
    {
        var owner = await OrgWithHistoryAsync();
        var other = await Api.RegisterOrgAsync("Other");
        var admin = await Api.CreateUserAsync(owner, "Admin", "admin");

        var theirs = await ChainAsync(other);
        Assert.All(theirs, e => Assert.NotEqual(AuditActions.NotesExported, e.Action));
        Assert.Equal(2L, (await VerifyAsync(other)).Entries);   // their org created + their login
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.Client.GetAsync("/api/admin/audit", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.Client.PostAsJsonAsync("/api/admin/audit/verify", new VerifyRequest(null), Ct)).StatusCode);
    }

    [Fact]
    public async Task Paging_returns_entries_after_a_seq()
    {
        var owner = await OrgWithHistoryAsync();

        var page = await owner.Client.GetFromJsonAsync<List<AuditEntryView>>("/api/admin/audit?afterSeq=2&limit=2", Ct);

        Assert.Equal([3L, 4L], page!.Select(e => e.Seq));
    }

    [Fact]
    public async Task A_tor_response_is_audited_as_a_decision_and_an_execution()
    {
        var owner = await Api.RegisterOrgAsync();
        await PolicyTests.ChangeAsync(owner, p => p with { Response = new ResponsePolicy(ResponseActions.RevokeAndLock) });
        var victim = await Api.CreateUserAsync(owner, "Victim");
        using (var tor = Api.CreateSimulatedClient(TestGeoIpLookup.TorExitIp))
        {
            (await tor.PostAsJsonAsync("/api/auth/login", new LoginRequest(victim.User.Email, victim.Password), Ct)).EnsureSuccessStatusCode();
        }

        var executed = await Eventually.GetAsync(async () =>
            (await ChainAsync(owner)).SingleOrDefault(e => e.Action == AuditActions.ResponseExecuted), what: "response audited");
        var decided = (await ChainAsync(owner)).Single(e => e.Action == AuditActions.AnomalyDecided);

        Assert.Equal(decided.AnomalyId, executed.AnomalyId);
        Assert.Equal(ActorTypes.System, executed.ActorType);
        Assert.Equal("responded", decided.Details.GetProperty("decision").GetString());
        Assert.True(executed.Details.GetProperty("locked").GetBoolean());
        Assert.Equal(2, executed.Details.GetProperty("revokedSessions").GetArrayLength());
        Assert.Equal(DetectorIds.Tor, executed.Details.GetProperty("detector").GetString());

        Assert.Equal(HttpStatusCode.NoContent, (await owner.Client.PostAsync($"/api/admin/users/{victim.User.Id}/unlock", null, Ct)).StatusCode);
        Assert.Contains(await ChainAsync(owner), e => e.Action == AuditActions.UserUnlocked && e.TargetId == victim.User.Id.ToString());
        Assert.True((await VerifyAsync(owner)).Ok);
    }

    [Fact]
    public async Task Timestamps_round_trip_at_microsecond_precision()
    {
        // .NET ticks are 100 ns; PostgreSQL keeps microseconds. If the append hashed the finer
        // value, every verify would fail. A clock with sub-microsecond ticks proves it doesn't.
        var owner = await Api.RegisterOrgAsync();
        await using var db = containers.Db();
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 10, 24, 9, 0, 0, TimeSpan.Zero).AddTicks(1_234_567));
        await new AuditLog(db, clock).AppendAsync(new AuditRecord(owner.User.OrgId, ActorTypes.System, null, "test.precision"), Ct);

        Assert.True((await VerifyAsync(owner)).Ok);
    }
}
