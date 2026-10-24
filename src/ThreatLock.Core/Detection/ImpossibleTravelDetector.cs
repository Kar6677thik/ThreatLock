using System.Globalization;
using System.Text.Json.Nodes;
using ThreatLock.Core.Events;
using ThreatLock.Core.Geo;
using ThreatLock.Core.Policy;

namespace ThreatLock.Core.Detection;

/// <summary>Tunables for D2. Orgs override them through policy thresholds (SPEC §9.1).</summary>
public sealed record ImpossibleTravelSettings(double MaxSpeedKmh = 900, double MinDistanceKm = 500, double LookbackHours = 24)
{
    public const string MaxSpeedKmhKey = "maxSpeedKmh";
    public const string MinDistanceKmKey = "minDistanceKm";

    public static ImpossibleTravelSettings Default { get; } = new();

    /// <summary>This org's thresholds, falling back to the detector's defaults.</summary>
    public ImpossibleTravelSettings For(DetectorPolicy policy) => this with
    {
        MaxSpeedKmh = policy.Threshold(MaxSpeedKmhKey, MaxSpeedKmh),
        MinDistanceKm = policy.Threshold(MinDistanceKmKey, MinDistanceKm),
    };
}

/// <summary>
/// D2 (SPEC §8.2): the same user appears in two places too far apart to travel between in the
/// time between the two events. Compares each authenticated event with the user's last known
/// location.
/// <para>
/// GeoIP is imprecise, so both points' accuracy radii are subtracted from the distance first, and
/// distances under <see cref="ImpossibleTravelSettings.MinDistanceKm"/> are ignored. VPNs and
/// mobile carriers still cause false positives (Break B3, M8).
/// </para>
/// </summary>
public sealed class ImpossibleTravelDetector(ImpossibleTravelSettings? settings = null) : IDetector
{
    private readonly ImpossibleTravelSettings defaults = settings ?? ImpossibleTravelSettings.Default;

    public string Id => DetectorIds.ImpossibleTravel;

    public async ValueTask<IReadOnlyList<DetectionSignal>> EvaluateAsync(ActivityEvent evt, DetectionContext context, CancellationToken ct)
    {
        if (!EventTypes.IsAuthenticatedActivity(evt) || evt.Geo is not { } here || evt.Ip is null) return [];

        var userId = evt.UserId!.Value;
        var settings = defaults.For(context.EffectivePolicy.For(Id));
        var lookback = TimeSpan.FromHours(settings.LookbackHours);
        var previous = await context.State.GetLastLocationAsync(userId, ct);

        // An event older than what we've already seen (a redelivery, or the stream catching up
        // out of order) must not move the user's "last location" backwards in time.
        if (previous is not null && evt.OccurredAt < previous.At) return [];

        await context.State.SetLastLocationAsync(userId, new LastLocation(evt.Ip, here, evt.OccurredAt), lookback, ct);

        if (previous is null || evt.OccurredAt - previous.At > lookback) return [];

        var rawKm = GeoMath.DistanceKm(previous.Geo, here);
        var distanceKm = Math.Max(0, rawKm - previous.Geo.AccuracyKm - here.AccuracyKm);
        if (distanceKm < settings.MinDistanceKm) return [];

        var hours = (evt.OccurredAt - previous.At).TotalHours;
        // Two events at the same instant, far apart: infinitely fast, so certainly impossible.
        var speedKmh = hours > 0 ? distanceKm / hours : double.PositiveInfinity;
        if (speedKmh <= settings.MaxSpeedKmh) return [];

        var severity = await context.TorExits.IsExitAsync(evt.IpAddress!, ct) ? Severity.High : Severity.Medium;
        var hourBucket = evt.OccurredAt.UtcDateTime.ToString("yyyyMMddHH", CultureInfo.InvariantCulture);
        var dedupeKey = $"travel:{userId}:{previous.Geo.CountryCode ?? "??"}:{here.CountryCode ?? "??"}:{hourBucket}";

        var evidence = new JsonObject
        {
            ["from"] = Point(previous.Ip, previous.Geo, previous.At),
            ["to"] = Point(evt.Ip, here, evt.OccurredAt),
            ["rawDistanceKm"] = Math.Round(rawKm),
            ["distanceKm"] = Math.Round(distanceKm),
            ["hours"] = Math.Round(hours, 3),
            ["speedKmh"] = double.IsInfinity(speedKmh) ? null : Math.Round(speedKmh),
            ["simulated"] = evt.Simulated,
        };

        return [new DetectionSignal(Id, evt.OrgId, userId, evt.SessionId, severity, dedupeKey, evidence, evt.Id, [previous.Ip, evt.Ip])];
    }

    private static JsonObject Point(string ip, GeoInfo geo, DateTimeOffset at) => new()
    {
        ["ip"] = ip,
        ["country"] = geo.CountryCode,
        ["city"] = geo.City,
        ["lat"] = geo.Latitude,
        ["lon"] = geo.Longitude,
        ["accuracyKm"] = geo.AccuracyKm,
        ["at"] = at,
    };
}
