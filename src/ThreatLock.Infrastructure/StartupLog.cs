using Microsoft.Extensions.Logging;

namespace ThreatLock.Infrastructure;

/// <summary>
/// Source-generated log messages shared by the API and Worker. The generator writes the
/// formatting code at compile time, so nothing is allocated when the level is disabled
/// (analyzer rules CA1848 / CA1873).
/// </summary>
public static partial class StartupLog
{
    [LoggerMessage(Level = LogLevel.Information, Message = "{App} {Component} {Version} starting in {Environment}")]
    public static partial void Starting(ILogger logger, string app, string component, string version, string environment);

    [LoggerMessage(Level = LogLevel.Warning, Message = "GeoIP database not found at {Path}; locations will be unknown. Run scripts/download-geoip.sh")]
    public static partial void GeoIpMissing(ILogger logger, string path);
}
