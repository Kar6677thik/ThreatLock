using System.Net;

namespace ThreatLock.Core.Geo;

/// <summary>Where an IP address probably is (ADR-0009). "Probably": city-level GeoIP is often off by tens to hundreds of km.</summary>
/// <param name="CountryCode">ISO 3166-1 alpha-2, e.g. "IN".</param>
/// <param name="AccuracyKm">How wrong the point may be. Detectors subtract it from distances.</param>
public sealed record GeoInfo(string? CountryCode, string? City, double Latitude, double Longitude, double AccuracyKm);

/// <summary>IP → location. Implemented over the DB-IP database in Infrastructure; faked in tests.</summary>
public interface IGeoIpLookup
{
    /// <summary>Null for private, reserved or unknown addresses.</summary>
    GeoInfo? Lookup(IPAddress ip);
}

public static class GeoMath
{
    private const double EarthRadiusKm = 6371.0088;   // mean Earth radius (IUGG)

    /// <summary>
    /// Great-circle distance between two points, via the haversine formula. Treats the Earth as a
    /// sphere, which is off by at most ~0.5 %; GeoIP error is far bigger than that.
    /// </summary>
    public static double DistanceKm(double lat1, double lon1, double lat2, double lon2)
    {
        static double Radians(double degrees) => degrees * Math.PI / 180;

        var dLat = Radians(lat2 - lat1);
        var dLon = Radians(lon2 - lon1);
        var a = Math.Pow(Math.Sin(dLat / 2), 2)
              + Math.Cos(Radians(lat1)) * Math.Cos(Radians(lat2)) * Math.Pow(Math.Sin(dLon / 2), 2);
        return 2 * EarthRadiusKm * Math.Asin(Math.Min(1, Math.Sqrt(a)));
    }

    public static double DistanceKm(GeoInfo from, GeoInfo to) =>
        DistanceKm(from.Latitude, from.Longitude, to.Latitude, to.Longitude);
}
