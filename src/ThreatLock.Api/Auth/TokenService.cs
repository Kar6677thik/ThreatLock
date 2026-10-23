using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Auth;

public sealed record IssuedToken(string AccessToken, DateTimeOffset ExpiresAt);

/// <summary>Creates signed access tokens (JWTs). Validation is configured in Program.cs.</summary>
public sealed class TokenService(IOptions<AuthOptions> options, TimeProvider time)
{
    private readonly JsonWebTokenHandler handler = new();

    public IssuedToken Issue(AppUser user, IEnumerable<string> roles)
    {
        var auth = options.Value;
        var now = time.GetUtcNow();
        var expires = now.AddMinutes(auth.AccessTokenMinutes);

        var claims = new List<Claim>
        {
            new(ClaimNames.Subject, user.Id.ToString()),
            new(ClaimNames.Org, user.OrgId.ToString()),
            new(ClaimNames.Email, user.Email ?? ""),
            new(ClaimNames.Name, user.DisplayName),
            // A unique id per token. Not used yet; a deny-list of jti values is one of the
            // revocation designs compared in ADR-0002.
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimNames.Roles, r)));

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = auth.Issuer,
            Audience = auth.Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(auth.SigningKeyBytes()), SecurityAlgorithms.HmacSha256),
        };

        return new IssuedToken(handler.CreateToken(descriptor), expires);
    }
}
