using Microsoft.AspNetCore.Authorization;
using ThreatLock.Core.Identity;

namespace ThreatLock.Api.Auth;

/// <summary>
/// Named authorization policies (SPEC §4, §13). Endpoints say *what* they need ("Admin"), and
/// this file says *which roles* satisfy it, so the mapping lives in one place.
/// </summary>
public static class Policies
{
    public const string Admin = "Admin";
    public const string SecurityAdmin = "SecurityAdmin";
    public const string Owner = "Owner";

    public static void Configure(AuthorizationOptions options)
    {
        // Secure by default: every endpoint requires an authenticated user unless it explicitly
        // opts out with AllowAnonymous (login, register, health checks).
        options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();

        options.AddPolicy(Admin, p => p.RequireRole(Roles.Admin, Roles.SecurityAdmin, Roles.Owner));
        options.AddPolicy(SecurityAdmin, p => p.RequireRole(Roles.SecurityAdmin, Roles.Owner));
        options.AddPolicy(Owner, p => p.RequireRole(Roles.Owner));
    }
}
