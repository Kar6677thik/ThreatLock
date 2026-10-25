using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using ThreatLock.Core.Audit;

namespace ThreatLock.Simulator;

/// <summary>
/// <c>audit-verify</c> (SPEC §11.4): downloads an org's audit chain through the API and
/// recomputes every hash <em>here</em>, with this copy of <see cref="AuditChain"/>. Someone who
/// controls the server could make its verify endpoint lie; they can't make this program lie, as
/// long as it's built from code you trust.
/// </summary>
public static class AuditVerifier
{
    private sealed record Login(string AccessToken);

    private sealed record Entry(long Seq, DateTimeOffset OccurredAt, string ActorType, Guid? ActorId, string Action, string? TargetType,
        string? TargetId, Guid? AnomalyId, JsonElement Details, string? IdempotencyKey, string PrevHash, string EntryHash);

    private sealed record ServerVerify(bool Ok, long Entries, string? Head, long? FirstBrokenSeq, string? Reason);

    public static async Task<int> RunAsync(Options options, CancellationToken ct)
    {
        using var http = new HttpClient { BaseAddress = new Uri(options.Require("base-url")) };
        var login = await http.PostAsJsonAsync("/api/auth/login", new { email = options.Require("email"), password = options.Require("password") }, ct);
        login.EnsureSuccessStatusCode();
        var token = (await login.Content.ReadFromJsonAsync<Login>(Commands.Json, ct))!.AccessToken;
        http.DefaultRequestHeaders.Authorization = new("Bearer", token);
        var orgId = (await http.GetFromJsonAsync<JsonElement>("/api/me", ct)).GetProperty("orgId").GetGuid();

        AuditAnchor? anchor = options.Get("anchor-seq") is { } seq
            ? new AuditAnchor(long.Parse(seq, System.Globalization.CultureInfo.InvariantCulture), options.Require("anchor-hash"))
            : null;
        var verifier = new AuditChainVerifier(anchor);
        VerifyResult? local = null;
        long after = 0;
        while (local is null)
        {
            var page = (await http.GetFromJsonAsync<List<Entry>>($"/api/admin/audit?afterSeq={after}&limit=500", Commands.Json, ct))!;
            foreach (var e in page)
            {
                var fields = new AuditFields(orgId, e.Seq, e.OccurredAt, e.ActorType, e.ActorId, e.Action, e.TargetType, e.TargetId, e.AnomalyId,
                    JsonNode.Parse(e.Details.GetRawText()) as JsonObject ?? [], e.IdempotencyKey, Convert.FromHexString(e.PrevHash));
                local = verifier.Add(new AuditEntry(fields, Convert.FromHexString(e.EntryHash)));
                if (local is not null) break;
                after = e.Seq;
            }

            if (local is null && page.Count < 500) local = verifier.Complete();
        }

        var server = await (await http.PostAsJsonAsync("/api/admin/audit/verify", new { anchor = anchor is null ? null : new { seq = anchor.Seq, hash = anchor.Hash } }, ct))
            .Content.ReadFromJsonAsync<ServerVerify>(Commands.Json, ct);
        Console.WriteLine($"local : {Describe(local)}");
        Console.WriteLine($"server: {(server is null ? "no answer" : Describe(new VerifyResult(server.Ok, server.Entries, server.Head, server.FirstBrokenSeq, server.Reason)))}");
        if (server is not null && server.Ok != local.Ok) Console.WriteLine("The server's verify disagrees with this one. Trust this one.");
        return local.Ok ? 0 : 3;
    }

    private static string Describe(VerifyResult r) =>
        r.Ok ? $"intact, {r.Entries} entries, head {r.Head}" : $"BROKEN at seq {r.FirstBrokenSeq} ({r.Reason}); {r.Entries} entries before it check out";
}
