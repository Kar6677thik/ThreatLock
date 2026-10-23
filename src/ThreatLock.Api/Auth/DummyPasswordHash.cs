using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Auth;

/// <summary>
/// A password hash computed once at startup and verified against when a login names an
/// unknown or locked account. Verifying a real hash takes tens of milliseconds (that's the point
/// of PBKDF2); skipping it for unknown emails would let an attacker tell them apart by timing.
/// </summary>
public sealed class DummyPasswordHash
{
    private static readonly AppUser Nobody = new() { DisplayName = "nobody" };
    private readonly PasswordHasher<AppUser> hasher;
    private readonly string hash;

    // Identity registers IPasswordHasher as *scoped*. A singleton must not hold a scoped
    // service (a "captive dependency"; the container refuses it in Development). So this builds
    // its own hasher from the same options, giving the same algorithm and iteration count.
    public DummyPasswordHash(IOptions<PasswordHasherOptions> options)
    {
        hasher = new PasswordHasher<AppUser>(options);
        hash = hasher.HashPassword(Nobody, Guid.NewGuid().ToString());
    }

    public void Verify(string password) => hasher.VerifyHashedPassword(Nobody, hash, password);
}
