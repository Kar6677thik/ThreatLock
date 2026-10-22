using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// Boots the real API in memory (no network port) and points it at the test containers.
/// Pass different connection strings to simulate a dependency being down.
/// </summary>
public sealed class ThreatLockApiFactory(string postgres, string redis) : WebApplicationFactory<Program>
{
    public ThreatLockApiFactory(ContainersFixture containers)
        : this(containers.Postgres.GetConnectionString(), containers.Redis.GetConnectionString())
    {
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:Postgres", postgres);
        builder.UseSetting("ConnectionStrings:Redis", redis);
    }
}
