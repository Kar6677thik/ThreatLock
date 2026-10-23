using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

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

    /// <summary>Replaces the app's clock, for tests about expiry. Null keeps the real clock.</summary>
    public TimeProvider? Clock { get; init; }

    /// <summary>Lets a test set the connection's remote IP, as a real proxy hop would (ADR-0007 tests).</summary>
    public System.Net.IPAddress? RemoteIp { get; init; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // https so the Secure refresh cookie is stored and sent back by the test client's
        // cookie container, exactly as a browser would. TestServer doesn't care about the scheme.
        ClientOptions.BaseAddress = new Uri("https://localhost");

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

        builder.ConfigureServices(services =>
        {
            if (Clock is not null) services.AddSingleton(Clock);
            if (RemoteIp is not null) services.AddSingleton<IStartupFilter>(new RemoteIpStartupFilter(RemoteIp));
        });
    }

    /// <summary>Runs before the app's own pipeline, so UseForwardedHeaders sees this as the peer address.</summary>
    private sealed class RemoteIpStartupFilter(System.Net.IPAddress ip) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = ip;
                return nextMiddleware(context);
            });
            next(app);
        };
    }

    /// <summary>A client that sends the given access token on every request.</summary>
    public HttpClient CreateClient(string accessToken)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", accessToken);
        return client;
    }
}
