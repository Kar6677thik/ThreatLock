using ThreatLock.Core.Identity;

namespace ThreatLock.Infrastructure.Persistence;

/// <summary>The four roles from SPEC §4, with fixed ids so the seed is stable across migrations.</summary>
internal static class SeededRoles
{
    public static AppRole[] All { get; } =
    [
        Role("0199f2a0-0000-7000-8000-000000000001", Roles.Member),
        Role("0199f2a0-0000-7000-8000-000000000002", Roles.Admin),
        Role("0199f2a0-0000-7000-8000-000000000003", Roles.SecurityAdmin),
        Role("0199f2a0-0000-7000-8000-000000000004", Roles.Owner),
    ];

    private static AppRole Role(string id, string name) => new()
    {
        Id = Guid.Parse(id),
        Name = name,
        NormalizedName = name.ToUpperInvariant(),
        ConcurrencyStamp = id,
    };
}
