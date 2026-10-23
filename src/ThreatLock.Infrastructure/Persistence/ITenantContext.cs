namespace ThreatLock.Infrastructure.Persistence;

/// <summary>
/// Which org the current unit of work acts for. The API fills it from the authenticated user's
/// token (never from the request body or URL, SPEC §4); the Worker will set it explicitly.
/// </summary>
public interface ITenantContext
{
    /// <summary>Null means "no tenant": tenant-filtered queries then return nothing.</summary>
    Guid? OrgId { get; }
}

/// <summary>Used when nothing else is registered (design-time tools, background setup).</summary>
public sealed class NoTenantContext : ITenantContext
{
    public Guid? OrgId => null;
}
