namespace ThreatLock.Api.Auth;

/// <summary>How access tokens are trusted (SPEC §6.1).</summary>
public enum AuthMode
{
    /// <summary>
    /// Default. Every request checks the token's session (<c>sid</c>) is still active, so
    /// revocation takes effect on the next request.
    /// </summary>
    SessionChecked,

    /// <summary>
    /// Break B1 only: the token alone is trusted until it expires. Kept as a switch so the
    /// failure can be reproduced at any time; never use it for real.
    /// </summary>
    StatelessJwt,
}

/// <summary>Bound from the <c>Auth</c> configuration section (SPEC §6).</summary>
public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    public AuthMode Mode { get; set; } = AuthMode.SessionChecked;

    public string Issuer { get; set; } = "threatlock";

    public string Audience { get; set; } = "threatlock-api";

    /// <summary>
    /// HMAC-SHA256 key, base64, at least 32 bytes (256 bits). Anyone holding it can mint valid
    /// tokens for any user, so in deployment it comes from a secret, never from a file.
    /// </summary>
    public string SigningKey { get; set; } = "";

    /// <summary>
    /// 5 minutes. With the session check, revocation doesn't depend on this; it's defence in
    /// depth if the check is ever bypassed. The B1 break run sets it to 60 with StatelessJwt.
    /// </summary>
    public int AccessTokenMinutes { get; set; } = 5;

    /// <summary>A session dies after this long without a refresh.</summary>
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromHours(12);

    /// <summary>A session dies this long after login, however active it is.</summary>
    public TimeSpan SessionAbsoluteTimeout { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// How long after a refresh token's first use a second use counts as a harmless race (two
    /// tabs) rather than theft (SPEC §6.4).
    /// </summary>
    public TimeSpan RefreshReuseGrace { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Marks the refresh cookie <c>Secure</c> (HTTPS only). Browsers treat http://localhost as
    /// secure, so this stays on even in development.
    /// </summary>
    public bool RefreshCookieSecure { get; set; } = true;

    public byte[] SigningKeyBytes() => Convert.FromBase64String(SigningKey);

    internal static bool HasValidSigningKey(AuthOptions o)
    {
        try
        {
            return o.SigningKeyBytes().Length >= 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
