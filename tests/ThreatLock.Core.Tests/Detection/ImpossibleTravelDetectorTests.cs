using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using ThreatLock.Core.Geo;
using static ThreatLock.Core.Tests.Detection.DetectorTestData;

namespace ThreatLock.Core.Tests.Detection;

/// <summary>
/// Event timestamps drive everything, so "London 11 hours later" is just a different
/// <c>OccurredAt</c>, no waiting involved (ADR-0006).
/// </summary>
public class ImpossibleTravelDetectorTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private readonly ImpossibleTravelDetector detector = new();
    private readonly DetectionContext context = Context();

    private async Task<IReadOnlyList<DetectionSignal>> TravelAsync(GeoInfo from, GeoInfo to, TimeSpan gap, string toIp = "203.0.113.20")
    {
        Assert.Empty(await detector.EvaluateAsync(Event(T0, from, ip: "203.0.113.10"), context, Ct));
        return await detector.EvaluateAsync(Event(T0 + gap, to, ip: toIp), context, Ct);
    }

    [Fact]
    public async Task Bangalore_to_London_in_ten_minutes_is_impossible()
    {
        var signal = Assert.Single(await TravelAsync(Bangalore, London, TimeSpan.FromMinutes(10)));

        Assert.Equal((DetectorIds.ImpossibleTravel, Severity.Medium), (signal.Detector, signal.Severity));
        Assert.Equal("IN", signal.Evidence["from"]!["country"]!.GetValue<string>());
        Assert.Equal("GB", signal.Evidence["to"]!["country"]!.GetValue<string>());
        Assert.True(signal.Evidence["speedKmh"]!.GetValue<double>() > 40_000);
    }

    [Fact]
    public async Task Bangalore_to_London_in_eleven_hours_is_a_plausible_flight()
    {
        Assert.Empty(await TravelAsync(Bangalore, London, TimeSpan.FromHours(11)));
    }

    [Fact]
    public async Task Short_hops_are_ignored_because_geoip_is_imprecise()
    {
        // Bangalore → Chennai in 1 minute is "fast" but under the 500 km floor.
        Assert.Empty(await TravelAsync(Bangalore, Chennai, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public async Task Accuracy_radii_are_subtracted_before_judging_distance()
    {
        // ~640 km apart, but each point may be off by 100 km: 640 - 200 = 440 km < 500 km.
        var a = new GeoInfo("XX", "A", 0, 0, 100);
        var b = new GeoInfo("YY", "B", 0, 5.75, 100);

        Assert.Empty(await TravelAsync(a, b, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public async Task Two_far_apart_events_at_the_same_instant_are_impossible()
    {
        var signal = Assert.Single(await TravelAsync(Bangalore, London, TimeSpan.Zero));

        Assert.Null(signal.Evidence["speedKmh"]);   // infinite speed has no JSON number
    }

    [Fact]
    public async Task Arriving_from_a_tor_exit_raises_severity()
    {
        var signal = Assert.Single(await TravelAsync(Bangalore, London, TimeSpan.FromMinutes(10), toIp: TorIp));

        Assert.Equal(Severity.High, signal.Severity);
    }

    [Fact]
    public async Task Locations_older_than_the_lookback_window_are_not_compared()
    {
        Assert.Empty(await TravelAsync(Bangalore, London, TimeSpan.FromHours(25)));
    }

    [Fact]
    public async Task Events_without_geo_are_skipped_and_do_not_reset_the_last_location()
    {
        await detector.EvaluateAsync(Event(T0, Bangalore), context, Ct);
        Assert.Empty(await detector.EvaluateAsync(Event(T0.AddMinutes(1), geo: null, ip: "10.0.0.5"), context, Ct));

        // Still compared against Bangalore.
        Assert.Single(await detector.EvaluateAsync(Event(T0.AddMinutes(2), London, ip: "203.0.113.20"), context, Ct));
    }

    [Fact]
    public async Task An_out_of_order_older_event_does_not_move_the_last_location_backwards()
    {
        await detector.EvaluateAsync(Event(T0.AddHours(1), Bangalore), context, Ct);
        // A redelivered event from earlier, somewhere else: ignored entirely.
        Assert.Empty(await detector.EvaluateAsync(Event(T0, London), context, Ct));

        var last = await context.State.GetLastLocationAsync(User, Ct);
        Assert.Equal("Bengaluru", last!.Geo.City);
    }

    [Fact]
    public async Task Failed_logins_never_count_as_being_somewhere()
    {
        await detector.EvaluateAsync(Event(T0, Bangalore), context, Ct);

        Assert.Empty(await detector.EvaluateAsync(Event(T0.AddMinutes(5), London, type: EventTypes.LoginFailed), context, Ct));
    }

    [Fact]
    public async Task Repeated_jumps_within_the_same_hour_share_a_dedupe_key()
    {
        var first = Assert.Single(await TravelAsync(Bangalore, London, TimeSpan.FromMinutes(5)));
        await detector.EvaluateAsync(Event(T0.AddMinutes(10), Bangalore), context, Ct);
        var back = Assert.Single(await detector.EvaluateAsync(Event(T0.AddMinutes(15), London, ip: "203.0.113.20"), context, Ct));

        Assert.Equal(first.DedupeKey, back.DedupeKey);
    }
}
