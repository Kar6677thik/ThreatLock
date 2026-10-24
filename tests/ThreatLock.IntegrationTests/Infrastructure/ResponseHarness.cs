using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Npgsql;
using StackExchange.Redis;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.Core.Response;
using ThreatLock.Infrastructure.Detection;
using ThreatLock.Infrastructure.Persistence;
using ThreatLock.Infrastructure.Response;
using ThreatLock.Infrastructure.Sessions;

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// The response orchestrator's parts wired by hand against a database of the test's own, with a
/// fake clock and a fault injector. Tests drive it step by step (claim, execute, "crash", let
/// the lease expire, claim again) instead of waiting on a background loop.
/// </summary>
public sealed class ResponseHarness : IAsyncDisposable
{
    private readonly IConnectionMultiplexer redis;

    private ResponseHarness(string connectionString, IConnectionMultiplexer redis)
    {
        this.redis = redis;
        ConnectionString = connectionString;
        Db = NpgsqlDataSource.Create(connectionString);
        Sessions = new SessionStore(Db, redis, Clock, NullLogger<SessionStore>.Instance);
        Jobs = new ResponseJobStore(Db, Options.Create(new ResponseOptions()), Clock);
        Anomalies = new AnomalyStore(Db, Clock);
        Executor = new ResponseExecutor(Db, Sessions, Jobs, Faults, Clock, NullLogger<ResponseExecutor>.Instance);
    }

    public string ConnectionString { get; }
    public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 10, 24, 9, 0, 0, TimeSpan.Zero));
    public CrashInjector Faults { get; } = new();
    public NpgsqlDataSource Db { get; }
    public IDatabase Redis => redis.GetDatabase();
    public SessionStore Sessions { get; }
    public ResponseJobStore Jobs { get; }
    public AnomalyStore Anomalies { get; }
    public ResponseExecutor Executor { get; }

    public static async Task<ResponseHarness> CreateAsync(ContainersFixture containers) =>
        new(await containers.CreateDatabaseAsync(), await ConnectionMultiplexer.ConnectAsync(containers.Redis.GetConnectionString()));

    public ThreatLockDbContext NewDbContext()
    {
        var options = new DbContextOptionsBuilder<ThreatLockDbContext>();
        DbContextConfiguration.Configure(options, ConnectionString);
        return new ThreatLockDbContext(options.Options, new NoTenantContext());
    }

    /// <summary>An org with users holding the given roles (every user is also a member).</summary>
    public async Task<(Guid OrgId, Guid[] UserIds)> SeedOrgAsync(params string[][] rolesPerUser)
    {
        await using var db = NewDbContext();
        var org = new ThreatLock.Infrastructure.Persistence.Org { Name = "Harness", Slug = TestData.UniqueSlug(), CreatedAt = Clock.GetUtcNow() };
        db.Orgs.Add(org);
        var users = rolesPerUser.Select((_, i) => new AppUser
        {
            OrgId = org.Id,
            DisplayName = $"User {i}",
            UserName = TestData.UniqueEmail(),
            Email = $"u{i}-{Guid.NewGuid():N}@example.test",
            SecurityStamp = Guid.NewGuid().ToString(),
            CreatedAt = Clock.GetUtcNow(),
        }).ToArray();
        db.Users.AddRange(users);
        await db.SaveChangesAsync(Ct);

        for (var i = 0; i < users.Length; i++)
        {
            await db.Database.ExecuteSqlAsync(
                $"INSERT INTO user_roles (user_id, role_id) SELECT {users[i].Id}, id FROM roles WHERE name = ANY({rolesPerUser[i].Append("member").ToArray()})", Ct);
        }

        return (org.Id, [.. users.Select(u => u.Id)]);
    }

    /// <summary>
    /// A live session for the user, created now. <paramref name="cachedActive"/> also puts it in
    /// the Redis cache as "active", as if it had just made a request.
    /// </summary>
    public async Task<Guid> AddSessionAsync(Guid orgId, Guid userId, bool cachedActive = false)
    {
        await using var db = NewDbContext();
        var now = Clock.GetUtcNow();
        var session = new Session
        {
            OrgId = orgId,
            UserId = userId,
            CreatedAt = now,
            LastSeenAt = now,
            IdleExpiresAt = now.AddHours(12),
            AbsoluteExpiresAt = now.AddDays(7),
        };
        db.Sessions.Add(session);
        await db.SaveChangesAsync(Ct);
        if (cachedActive) await Redis.StringSetAsync($"tl:sess:{session.Id}", "a", TimeSpan.FromSeconds(60));
        return session.Id;
    }

    /// <summary>A new anomaly with a "responded" decision, and its job, created exactly as the Worker does.</summary>
    public async Task<AnomalyUpsert> RespondedAnomalyAsync(Guid orgId, Guid userId, string action = JobActions.RevokeSessions,
        string detector = DetectorIds.Tor)
    {
        var signal = new DetectionSignal(detector, orgId, userId, null, Severity.High, $"test:{Guid.NewGuid():N}",
            new JsonObject(), Guid.NewGuid(), ["198.51.100.9"]);
        var plan = new ResponsePlan(action, SecurityPolicy.Default.NotifyRoles);
        var outcome = action == JobActions.Notify ? DecisionOutcome.Notified : DecisionOutcome.Responded;
        return await Anomalies.UpsertAsync(signal, new Decision(outcome, "test"), 0, plan, Ct);
    }

    public async Task<T?> ScalarAsync<T>(string sql, params object[] args)
    {
        await using var command = Db.CreateCommand(sql);
        foreach (var arg in args) command.Parameters.AddWithValue(arg);
        var result = await command.ExecuteScalarAsync(Ct);
        if (result is DateTime utc && (typeof(T) == typeof(DateTimeOffset) || typeof(T) == typeof(DateTimeOffset?)))
        {
            return (T)(object)new DateTimeOffset(utc);   // Npgsql returns timestamptz as a UTC DateTime
        }

        return result is null or DBNull ? default : (T)result;
    }

    public async ValueTask DisposeAsync()
    {
        await Db.DisposeAsync();
        await redis.DisposeAsync();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}

/// <summary>"The Worker died here": throws once at the chosen step, then lets everything through.</summary>
public sealed class CrashInjector : IResponseFaultInjector
{
    private ResponseStep? crashAt;

    public void CrashOnceAfter(ResponseStep step) => crashAt = step;

    public ValueTask AfterAsync(ResponseStep completed, ClaimedJob job)
    {
        if (crashAt != completed) return ValueTask.CompletedTask;
        crashAt = null;
        throw new SimulatedCrashException(completed);
    }
}

public sealed class SimulatedCrashException(ResponseStep step) : Exception($"Simulated crash after {step}.");
