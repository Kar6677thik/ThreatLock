namespace ThreatLock.Api.Auth;

/// <summary>
/// The refresh token travels only in this cookie (SPEC §6.3):
/// <list type="bullet">
/// <item><c>HttpOnly</c>: page JavaScript can't read it, so an XSS bug can't steal it directly.</item>
/// <item><c>Secure</c>: only sent over HTTPS.</item>
/// <item><c>SameSite=Strict</c>: never sent on requests started by another site (CSRF).</item>
/// <item><c>Path=/api/auth</c>: not attached to every API call, only to the auth endpoints.</item>
/// </list>
/// </summary>
public static class RefreshCookie
{
    public const string Name = "tl_refresh";
    public const string Path = "/api/auth";

    /// <summary>Second CSRF guard for /refresh: a custom header a cross-site form can't send.</summary>
    public const string CsrfHeader = "X-Requested-With";
    public const string CsrfHeaderValue = "threatlock";

    public static void Set(HttpResponse response, string token, DateTimeOffset expires, bool secure) =>
        response.Cookies.Append(Name, token, Options(expires, secure));

    public static void Clear(HttpResponse response, bool secure) =>
        response.Cookies.Delete(Name, Options(null, secure));

    public static string? Read(HttpRequest request) => request.Cookies[Name];

    private static CookieOptions Options(DateTimeOffset? expires, bool secure) => new()
    {
        HttpOnly = true,
        Secure = secure,
        SameSite = SameSiteMode.Strict,
        Path = Path,
        Expires = expires,
        IsEssential = true,
    };
}
