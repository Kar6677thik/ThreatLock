using System.Reflection;

namespace ThreatLock.Core;

/// <summary>
/// Identity of the running build, shown by <c>GET /api/info</c> and written to startup logs
/// so you can always tell which commit is deployed.
/// </summary>
public static class AppInfo
{
    public const string Name = "ThreatLock";

    /// <summary>
    /// Informational version stamped at build time (e.g. <c>1.0.0+abc1234</c> when CI passes
    /// <c>-p:SourceRevisionId=...</c>). Falls back to the assembly version.
    /// </summary>
    public static string Version { get; } =
        typeof(AppInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(AppInfo).Assembly.GetName().Version?.ToString()
        ?? "unknown";
}
