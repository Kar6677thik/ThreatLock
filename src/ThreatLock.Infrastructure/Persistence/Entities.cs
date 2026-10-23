using Microsoft.AspNetCore.Identity;

namespace ThreatLock.Infrastructure.Persistence;

// Persistence entities. They live in Infrastructure, not Core, because the user and role types
// must inherit from ASP.NET Core Identity classes, and Core may not depend on Identity
// (ArchitectureTests). Ids are UUIDv7 (Guid.CreateVersion7), which sort by creation time and
// keep B-tree indexes compact, unlike random v4 ids.

/// <summary>An organisation (tenant). Every other row belongs to exactly one.</summary>
public sealed class Org
{
    public Guid Id { get; init; } = Guid.CreateVersion7();
    public required string Name { get; set; }
    public required string Slug { get; set; }
    public DateTimeOffset CreatedAt { get; init; }
}

/// <summary>Identity user plus the org it belongs to (one org per user, SPEC §4).</summary>
public sealed class AppUser : IdentityUser<Guid>
{
    public AppUser() => Id = Guid.CreateVersion7();

    public Guid OrgId { get; set; }
    public Org? Org { get; set; }
    public required string DisplayName { get; set; }
    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class AppRole : IdentityRole<Guid>
{
    public AppRole() => Id = Guid.CreateVersion7();
}

public sealed class Note
{
    public Guid Id { get; init; } = Guid.CreateVersion7();
    public Guid OrgId { get; init; }
    public Guid OwnerId { get; init; }
    public required string Title { get; set; }
    public required string Body { get; set; }

    /// <summary>Shared notes are readable (not writable) by everyone in the org.</summary>
    public bool Shared { get; set; }

    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// A server-side login session: the unit of revocation (SPEC §6, ADR-0002). Access tokens carry
/// its id as the <c>sid</c> claim, and the API checks it on every request.
/// </summary>
public sealed class Session
{
    public Guid Id { get; init; } = Guid.CreateVersion7();
    public Guid UserId { get; init; }
    public Guid OrgId { get; init; }
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>Client IP at login, after trusted-proxy resolution (ADR-0007). Null if unknown.</summary>
    public System.Net.IPAddress? CreatedIp { get; init; }

    /// <summary>The browser's self-chosen device id (X-Device-Id). A signal, never proof.</summary>
    public string? CreatedDeviceId { get; init; }

    public string? CreatedUserAgent { get; init; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset IdleExpiresAt { get; set; }
    public DateTimeOffset AbsoluteExpiresAt { get; init; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
}

/// <summary>
/// One link in a session's refresh-token chain. Only the SHA-256 hash is stored, so a database
/// leak doesn't hand out working refresh tokens. A used token points at its replacement.
/// </summary>
public sealed class RefreshToken
{
    public Guid Id { get; init; } = Guid.CreateVersion7();
    public Guid SessionId { get; init; }
    public required byte[] TokenHash { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? UsedAt { get; set; }
    public Guid? ReplacedById { get; set; }
}
