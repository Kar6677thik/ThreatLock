namespace ThreatLock.Infrastructure;

/// <summary>
/// Bound from the <c>ConnectionStrings</c> configuration section. In development these come from
/// appsettings.Development.json; in deployment from environment variables such as
/// <c>ConnectionStrings__Postgres</c> (double underscore = section separator).
/// </summary>
public sealed class ConnectionStringsOptions
{
    public const string SectionName = "ConnectionStrings";

    public string Postgres { get; set; } = "";

    public string Redis { get; set; } = "";
}
