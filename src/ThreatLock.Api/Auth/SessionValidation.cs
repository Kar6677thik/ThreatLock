using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using ThreatLock.Infrastructure.Sessions;

namespace ThreatLock.Api.Auth;

/// <summary>
/// Hooks into JWT bearer authentication. After the token's signature, issuer, audience and
/// lifetime are validated, this checks that its session is still alive (SPEC §6.5). This one
/// lookup is what makes revocation take effect on the very next request.
/// </summary>
public static class SessionValidation
{
    private const string RevokedKey = "tl.session_revoked";
    private const string UnavailableKey = "tl.session_store_unavailable";

    public static JwtBearerEvents Events() => new()
    {
        OnTokenValidated = OnTokenValidated,
        OnChallenge = OnChallenge,
    };

    private static async Task OnTokenValidated(TokenValidatedContext context)
    {
        var services = context.HttpContext.RequestServices;
        if (services.GetRequiredService<IOptions<AuthOptions>>().Value.Mode == AuthMode.StatelessJwt)
        {
            return;   // Break B1 mode: trust the token alone.
        }

        if (!Guid.TryParse(context.Principal?.FindFirstValue(ClaimNames.SessionId), out var sid))
        {
            Reject(context, RevokedKey, "Token has no session id.");
            return;
        }

        var store = services.GetRequiredService<SessionStore>();
        var ct = context.HttpContext.RequestAborted;
        try
        {
            if (!await store.IsActiveAsync(sid, ct))
            {
                Reject(context, RevokedKey, "Session revoked or expired.");
                return;
            }

            await store.TouchAsync(sid, ct);
        }
        catch (SessionStoreUnavailableException)
        {
            // Fail closed: if we can't check, we don't let the request through.
            Reject(context, UnavailableKey, "Session status unavailable.");
        }
    }

    private static void Reject(TokenValidatedContext context, string reasonKey, string message)
    {
        context.HttpContext.Items[reasonKey] = true;
        context.Fail(message);
    }

    private static async Task OnChallenge(JwtBearerChallengeContext context)
    {
        var items = context.HttpContext.Items;

        if (items.ContainsKey(UnavailableKey))
        {
            // Not the client's fault: 503 tells it to retry later instead of signing the user out.
            context.HandleResponse();
            await Results.Problem(
                "Cannot verify the session right now. Try again shortly.",
                statusCode: StatusCodes.Status503ServiceUnavailable).ExecuteAsync(context.HttpContext);
            return;
        }

        if (items.ContainsKey(RevokedKey))
        {
            // Standard bearer-token error (RFC 6750), plus a description the SPA can show:
            // WWW-Authenticate: Bearer error="invalid_token", error_description="session_revoked"
            context.Error = "invalid_token";
            context.ErrorDescription = "session_revoked";
        }
    }
}
