using ThreatLock.Core.Geo;
using static ThreatLock.Core.Tests.Detection.DetectorTestData;

namespace ThreatLock.Core.Tests.Detection;

public class GeoMathTests
{
    [Fact]
    public void Distance_to_self_is_zero()
    {
        Assert.Equal(0, GeoMath.DistanceKm(London, London), precision: 6);
    }

    [Theory]
    // Reference great-circle distances (spherical Earth), to within 1 %.
    [InlineData(51.5074, -0.1278, 48.8566, 2.3522, 344)]      // London → Paris
    [InlineData(12.9716, 77.5946, 51.5074, -0.1278, 8008)]    // Bangalore → London
    [InlineData(40.7128, -74.0060, 34.0522, -118.2437, 3936)] // New York → Los Angeles
    public void Distance_matches_known_city_pairs(double lat1, double lon1, double lat2, double lon2, double expectedKm)
    {
        var km = GeoMath.DistanceKm(lat1, lon1, lat2, lon2);

        Assert.InRange(km, expectedKm * 0.99, expectedKm * 1.01);
    }

    [Fact]
    public void Distance_is_symmetric_and_handles_the_antimeridian()
    {
        // Fiji (178°E) to Samoa (172°W) is short across the date line, not the long way round.
        var km = GeoMath.DistanceKm(-18.1, 178.4, -13.8, -172.0);

        Assert.InRange(km, 1000, 1300);
        Assert.Equal(km, GeoMath.DistanceKm(-13.8, -172.0, -18.1, 178.4), precision: 6);
    }
}
