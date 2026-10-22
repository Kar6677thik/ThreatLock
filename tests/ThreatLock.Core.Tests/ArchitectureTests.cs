using ThreatLock.Core;

namespace ThreatLock.Core.Tests;

/// <summary>
/// Guards the one structural rule that keeps Core fast to test and reusable by the replay
/// harness (SPEC §5.1, ADR-0006): Core does no I/O, so it must not depend on databases,
/// caches, HTTP or our own Infrastructure project.
/// </summary>
public class ArchitectureTests
{
    private static readonly string[] ForbiddenPrefixes =
    [
        "ThreatLock.Infrastructure",
        "ThreatLock.Api",
        "ThreatLock.Worker",
        "Npgsql",
        "StackExchange.Redis",
        "Microsoft.EntityFrameworkCore",
        "Microsoft.AspNetCore",
        "System.Net.Http",
    ];

    [Fact]
    public void Core_does_not_reference_infrastructure_assemblies()
    {
        var references = typeof(AppInfo).Assembly.GetReferencedAssemblies().Select(a => a.Name ?? "");

        var violations = references
            .Where(name => ForbiddenPrefixes.Any(prefix => name.StartsWith(prefix, StringComparison.Ordinal)))
            .ToList();

        Assert.Empty(violations);
    }

    [Fact]
    public void AppInfo_reports_a_name_and_version()
    {
        Assert.Equal("ThreatLock", AppInfo.Name);
        Assert.False(string.IsNullOrWhiteSpace(AppInfo.Version));
    }
}
