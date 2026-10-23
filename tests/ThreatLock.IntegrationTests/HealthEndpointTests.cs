using System.Net;
using System.Text.Json;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// Liveness vs readiness (SPEC §18). Kubernetes restarts a pod whose liveness fails and stops
/// routing traffic to a pod whose readiness fails, so they must mean different things.
/// </summary>
public class HealthEndpointTests(ContainersFixture containers)
{
    // Nothing listens on port 1, so connections are refused immediately.
    private const string UnreachablePostgres = "Host=127.0.0.1;Port=1;Database=x;Username=x;Password=x;Timeout=2";
    private const string UnreachableRedis = "127.0.0.1:1";

    [Fact]
    public async Task Healthz_is_ok_when_process_is_running()
    {
        var factory = containers.Api;
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/healthz", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Readyz_is_ok_when_postgres_and_redis_are_reachable()
    {
        var factory = containers.Api;
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/readyz", TestContext.Current.CancellationToken);
        var checks = await ReadChecksAsync(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", checks["postgres"]);
        Assert.Equal("Healthy", checks["redis"]);
    }

    [Theory]
    [InlineData("postgres")]
    [InlineData("redis")]
    public async Task Readyz_is_503_and_names_the_dependency_that_is_down(string down)
    {
        var postgres = down == "postgres" ? UnreachablePostgres : containers.Postgres.GetConnectionString();
        var redis = down == "redis" ? UnreachableRedis : containers.Redis.GetConnectionString();
        await using var factory = new ThreatLockApiFactory(postgres, redis);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/readyz", TestContext.Current.CancellationToken);
        var checks = await ReadChecksAsync(response);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("Unhealthy", checks[down]);
    }

    [Fact]
    public async Task Healthz_stays_ok_even_when_a_dependency_is_down()
    {
        // A database outage must not make Kubernetes restart healthy API processes in a loop.
        await using var factory = new ThreatLockApiFactory(containers.Postgres.GetConnectionString(), UnreachableRedis);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/healthz", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task<Dictionary<string, string>> ReadChecksAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return json.RootElement.GetProperty("checks").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);
    }
}
