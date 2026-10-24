using System.Net;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using ThreatLock.Core.Geo;

namespace ThreatLock.Core.Events;

/// <summary>
/// Something a user did (SPEC §7.1). High volume, kept 30 days, read by detectors. Not to be
/// confused with the audit log (concepts.md §2.1).
/// </summary>
/// <param name="Id">UUIDv7. Consumers are idempotent on this id: an event may be delivered twice.</param>
/// <param name="UserId">Null only for <see cref="EventTypes.LoginFailed"/> with an unknown email.</param>
/// <param name="OccurredAt">Server clock when the request arrived. Detectors use this, never "now".</param>
/// <param name="Ip">Client IP after trusted-proxy (or keyed simulation) resolution, as a string.</param>
/// <param name="Geo">Looked up from <paramref name="Ip"/> when the event was captured; null if unknown or private.</param>
public sealed record ActivityEvent(
    Guid Id,
    Guid OrgId,
    Guid? UserId,
    Guid? SessionId,
    string Type,
    DateTimeOffset OccurredAt,
    string? Ip,
    GeoInfo? Geo,
    string? DeviceId,
    string? UserAgent,
    string? RequestId,
    JsonObject? Metadata)
{
    // Computed helpers are not part of the wire format. [JsonIgnore] matters: serialising an
    // IPAddress makes System.Text.Json read its ScopeId, which throws for IPv4 addresses.
    [JsonIgnore]
    public IPAddress? IpAddress => IPAddress.TryParse(Ip, out var ip) ? ip : null;

    /// <summary>True if the request carried a valid simulator key (ADR-0007); reports must say so.</summary>
    [JsonIgnore]
    public bool Simulated => Metadata?["simulated"]?.GetValue<bool>() == true;
}

/// <summary>Event type names (SPEC §7.1).</summary>
public static class EventTypes
{
    public const string LoginSucceeded = "login_succeeded";
    public const string LoginFailed = "login_failed";
    public const string TokenRefreshed = "token_refreshed";
    public const string RefreshTokenReused = "refresh_token_reused";
    public const string Logout = "logout";
    public const string NoteListed = "note_listed";
    public const string NoteRead = "note_read";
    public const string NoteCreated = "note_created";
    public const string NoteUpdated = "note_updated";
    public const string NoteDeleted = "note_deleted";
    public const string ExportRequested = "export_requested";
    public const string SessionRevoked = "session_revoked";

    /// <summary>
    /// Events that prove someone *holds a working credential* for this user: a successful login
    /// or any request made with a valid session. Failed logins and revocations don't.
    /// </summary>
    public static bool IsAuthenticatedActivity(ActivityEvent evt) =>
        evt.UserId is not null
        && evt.Type is not (LoginFailed or SessionRevoked or RefreshTokenReused);
}
