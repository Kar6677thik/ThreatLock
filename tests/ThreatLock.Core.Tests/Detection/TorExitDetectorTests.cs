using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using static ThreatLock.Core.Tests.Detection.DetectorTestData;

namespace ThreatLock.Core.Tests.Detection;

public class TorExitDetectorTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private readonly TorExitDetector detector = new();

    [Fact]
    public async Task Activity_from_a_tor_exit_raises_a_high_severity_signal()
    {
        var evt = Event(T0, London, ip: TorIp);

        var signal = Assert.Single(await detector.EvaluateAsync(evt, Context(), Ct));

        Assert.Equal((DetectorIds.Tor, Severity.High, evt.Id), (signal.Detector, signal.Severity, signal.EventId));
        Assert.Equal(TorIp, signal.Evidence["ip"]!.GetValue<string>());
    }

    [Fact]
    public async Task Activity_from_a_normal_ip_raises_nothing()
    {
        Assert.Empty(await detector.EvaluateAsync(Event(T0, London), Context(), Ct));
    }

    [Theory]
    [InlineData(EventTypes.LoginFailed)]        // a failed login proves nobody holds a credential
    [InlineData(EventTypes.SessionRevoked)]
    public async Task Events_that_are_not_authenticated_activity_are_ignored(string type)
    {
        Assert.Empty(await detector.EvaluateAsync(Event(T0, London, ip: TorIp, type: type), Context(), Ct));
    }

    [Fact]
    public async Task Every_event_in_one_session_shares_a_dedupe_key()
    {
        var first = Assert.Single(await detector.EvaluateAsync(Event(T0, London, ip: TorIp), Context(), Ct));
        var second = Assert.Single(await detector.EvaluateAsync(Event(T0.AddMinutes(5), London, ip: TorIp, type: EventTypes.ExportRequested), Context(), Ct));

        Assert.Equal(first.DedupeKey, second.DedupeKey);
    }
}
