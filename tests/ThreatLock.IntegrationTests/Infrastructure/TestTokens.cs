using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// Forges access tokens the way an attacker might, to prove the API rejects them.
/// </summary>
public static class TestTokens
{
    public static string Create(
        string subject,
        string org,
        DateTime? issuedAt = null,
        DateTime? expires = null,
        string issuer = "threatlock",
        string audience = "threatlock-api",
        string? signingKeyBase64 = null,
        string? sessionId = null)
    {
        var iat = issuedAt ?? DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(sessionId is null
                ? [new Claim("sub", subject), new Claim("org", org), new Claim("roles", "owner")]
                : [new Claim("sub", subject), new Claim("org", org), new Claim("roles", "owner"), new Claim("sid", sessionId)]),
            IssuedAt = iat,
            NotBefore = iat,
            Expires = expires ?? iat.AddMinutes(60),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Convert.FromBase64String(signingKeyBase64 ?? ThreatLockApiFactory.SigningKey)),
                SecurityAlgorithms.HmacSha256),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    /// <summary>
    /// The classic attack: an unsigned token with <c>"alg": "none"</c>, claiming to be the owner.
    /// A library that trusts the header's algorithm would accept it.
    /// </summary>
    public static string AlgNone(string subject, string org)
    {
        static string Encode(string json) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var header = Encode("""{"alg":"none","typ":"JWT"}""");
        var payload = Encode($$"""{"iss":"threatlock","aud":"threatlock-api","sub":"{{subject}}","org":"{{org}}","roles":"owner","exp":{{exp}}}""");
        return $"{header}.{payload}.";
    }

    /// <summary>Reads one claim from a token without validating it (tests only).</summary>
    public static string Claim(string token, string name) =>
        new JsonWebToken(token).GetClaim(name).Value;

    /// <summary>Flips one character in the payload, keeping the original signature.</summary>
    public static string Tamper(string token)
    {
        var parts = token.Split('.');
        var payload = parts[1].ToCharArray();
        payload[^2] = payload[^2] == 'A' ? 'B' : 'A';
        return $"{parts[0]}.{new string(payload)}.{parts[2]}";
    }
}
