using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Auth;

public static class AuthSetup
{
    /// <summary>Identity (users, password hashing, lockout) + JWT bearer validation + policies.</summary>
    public static IServiceCollection AddThreatLockAuth(this IServiceCollection services)
    {
        services.AddOptions<AuthOptions>()
            .BindConfiguration(AuthOptions.SectionName)
            .Validate(AuthOptions.HasValidSigningKey, "Auth:SigningKey must be base64 and at least 32 bytes")
            .Validate(o => o.AccessTokenMinutes is > 0 and <= 24 * 60, "Auth:AccessTokenMinutes must be 1..1440")
            .Validate(o => o.SessionIdleTimeout > TimeSpan.Zero && o.SessionAbsoluteTimeout >= o.SessionIdleTimeout,
                "Auth:SessionIdleTimeout must be positive and no longer than Auth:SessionAbsoluteTimeout")
            .ValidateOnStart();

        // AddIdentityCore = user and role management without Identity's cookie sign-in UI;
        // we issue our own tokens.
        services.AddIdentityCore<AppUser>(options =>
            {
                // NIST SP 800-63B: length beats composition rules ("Password1!" passes those).
                options.Password.RequiredLength = 12;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.User.RequireUniqueEmail = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddRoles<AppRole>()
            .AddEntityFrameworkStores<ThreatLockDbContext>();

        services.AddSingleton<DummyPasswordHash>();
        services.AddSingleton<TokenService>();
        services.AddHttpContextAccessor();
        services.AddScoped<CurrentUser>();
        services.AddScoped<SessionService>();
        services.AddScoped<ITenantContext>(sp => sp.GetRequiredService<CurrentUser>());

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();

        // Configure JWT validation from AuthOptions lazily, so tests can override the key.
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<AuthOptions>>((jwt, auth) =>
            {
                var o = auth.Value;
                // Keep claim names as they are in the token ("sub", "roles") instead of
                // rewriting them to long WS-Federation URIs.
                jwt.MapInboundClaims = false;
                // After the token itself checks out, check its session is still alive.
                jwt.Events = SessionValidation.Events();
                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    // Decoding is not validating (concepts.md §1.3). All of these are checked:
                    ValidIssuer = o.Issuer,
                    ValidAudience = o.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(o.SigningKeyBytes()),
                    // Only accept the algorithm we sign with. Blocks "alg": "none" and
                    // algorithm-confusion tricks.
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    // Default is 5 minutes; with short-lived tokens that's a big extra window.
                    ClockSkew = TimeSpan.FromSeconds(30),
                    NameClaimType = ClaimNames.Subject,
                    RoleClaimType = ClaimNames.Roles,
                };
            });

        services.AddAuthorization(Policies.Configure);
        return services;
    }
}
