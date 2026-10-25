using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>The Prometheus endpoint (SPEC §18): served without a token, with ThreatLock's own series in it.</summary>
public class MetricsTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Metrics_include_captured_events_and_session_checks()
    {
        var owner = await containers.Api.RegisterOrgAsync();
        (await owner.Client.GetAsync("/api/notes", Ct)).EnsureSuccessStatusCode();   // one session check, one event

        using var anonymous = containers.Api.CreateClient();
        var text = await Eventually.GetAsync(async () =>
        {
            var body = await anonymous.GetStringAsync("/metrics", Ct);
            return body.Contains("tl_session_check_duration", StringComparison.Ordinal) ? body : null;
        }, what: "metrics exported");

        Assert.Contains("tl_events_captured_total", text, StringComparison.Ordinal);
        Assert.Matches("""tl_session_check_duration_seconds_count\{[^}]*source="(redis|postgres)""", text);   // a new session misses the cache first
        Assert.Contains("http_server_request_duration_seconds", text, StringComparison.Ordinal);
        // Nothing user-identifying in labels: no ids, no emails.
        Assert.DoesNotContain(owner.User.Id.ToString(), text, StringComparison.Ordinal);
        Assert.DoesNotContain(owner.User.Email, text, StringComparison.Ordinal);
    }
}
