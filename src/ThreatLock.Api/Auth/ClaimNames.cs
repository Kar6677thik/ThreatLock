namespace ThreatLock.Api.Auth;

/// <summary>
/// The claim names inside our access tokens (SPEC §6.3). We keep the short JWT-standard names
/// (<c>sub</c>, <c>roles</c>) instead of letting ASP.NET Core rewrite them into long
/// XML-namespace URIs; see <c>MapInboundClaims = false</c> in Program.cs.
/// </summary>
public static class ClaimNames
{
    public const string Subject = "sub";
    public const string Org = "org";
    public const string Roles = "roles";
    public const string Email = "email";
    public const string Name = "name";
}
