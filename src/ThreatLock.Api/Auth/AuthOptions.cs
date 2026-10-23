namespace ThreatLock.Api.Auth;

/// <summary>Bound from the <c>Auth</c> configuration section (SPEC §6).</summary>
public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    public string Issuer { get; set; } = "threatlock";

    public string Audience { get; set; } = "threatlock-api";

    /// <summary>
    /// HMAC-SHA256 key, base64, at least 32 bytes (256 bits). Anyone holding it can mint valid
    /// tokens for any user, so in deployment it comes from a secret, never from a file.
    /// </summary>
    public string SigningKey { get; set; } = "";

    /// <summary>
    /// M2 uses 60-minute stateless tokens on purpose: this is the naive design that Break B1
    /// demonstrates. M3 introduces server-side sessions and drops this to 5 minutes.
    /// </summary>
    public int AccessTokenMinutes { get; set; } = 60;

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
