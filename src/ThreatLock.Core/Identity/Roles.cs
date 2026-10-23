namespace ThreatLock.Core.Identity;

/// <summary>
/// Role names (SPEC §4). A user may hold several at once; that matters later, when admin
/// notifications must go to each *person* once, not once per role (SPEC §10.4).
/// </summary>
public static class Roles
{
    public const string Member = "member";
    public const string Admin = "admin";
    public const string SecurityAdmin = "security_admin";
    public const string Owner = "owner";

    public static IReadOnlyList<string> All { get; } = [Member, Admin, SecurityAdmin, Owner];

    /// <summary>Roles that may be granted only by an owner (privilege escalation guard).</summary>
    public static IReadOnlyList<string> Privileged { get; } = [Admin, SecurityAdmin, Owner];

    public static bool IsKnown(string role) => All.Contains(role, StringComparer.Ordinal);
}
