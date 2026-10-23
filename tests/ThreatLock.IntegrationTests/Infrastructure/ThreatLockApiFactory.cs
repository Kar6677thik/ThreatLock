using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// Boots the real API in memory (no network port) and points it at the test containers.
/// Pass different connection strings or settings to simulate misconfiguration or outages.
/// </summary>
public sealed class ThreatLockApiFactory(string postgres, string redis, IReadOnlyDictionary<string, string?>? settings = null)
    : WebApplicationFactory<Program>
{
    /// <summary>Test-only signing key (base64 of 32+ bytes). Tests use it to forge tokens on purpose.</summary>
    public static readonly string SigningKey = Convert.ToBase64String("threatlock-integration-test-signing-key!"u8.ToArray());

    public ThreatLockApiFactory(ContainersFixture containers, IReadOnlyDictionary<string, string?>? settings = null)
        : this(containers.Postgres.GetConnectionString(), containers.Redis.GetConnectionString(), settings)
    {
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:Postgres", postgres);
        builder.UseSetting("ConnectionStrings:Redis", redis);
        builder.UseSetting("Auth:SigningKey", SigningKey);
        builder.UseSetting("Demo:AllowSignup", "true");
        builder.UseSetting("Database:MigrateOnStartup", "false");

        foreach (var (key, value) in settings ?? new Dictionary<string, string?>())
        {
            builder.UseSetting(key, value);
        }
    }

    /// <summary>A client that sends the given access token on every request.</summary>
    public HttpClient CreateClient(string accessToken)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", accessToken);
        return client;
    }
}
