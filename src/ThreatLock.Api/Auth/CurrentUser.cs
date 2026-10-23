using System.Security.Claims;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Auth;

/// <summary>
/// The authenticated caller, read from the validated access token. Also tells EF Core which
/// tenant to filter by (<see cref="ITenantContext"/>), so the org always comes from the token
/// and never from anything the client sends (SPEC §4).
/// </summary>
public sealed class CurrentUser(IHttpContextAccessor accessor) : ITenantContext
{
    private ClaimsPrincipal? Principal => accessor.HttpContext?.User;

    public bool IsAuthenticated => Principal?.Identity?.IsAuthenticated == true;

    public Guid? OrgId => ReadGuid(ClaimNames.Org);

    /// <summary>Only call from endpoints that require authorization.</summary>
    public Guid UserId => ReadGuid(ClaimNames.Subject)
        ?? throw new InvalidOperationException("No authenticated user on this request.");

    public Guid RequiredOrgId => OrgId
        ?? throw new InvalidOperationException("No authenticated user on this request.");

    /// <summary>The session behind this request's token (SPEC §6).</summary>
    public Guid SessionId => ReadGuid(ClaimNames.SessionId)
        ?? throw new InvalidOperationException("Token has no session id.");

    public bool IsInRole(string role) => Principal?.IsInRole(role) == true;

    private Guid? ReadGuid(string claim) =>
        IsAuthenticated && Guid.TryParse(Principal!.FindFirstValue(claim), out var id) ? id : null;
}
