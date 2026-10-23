using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using ThreatLock.Api.Auth;

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>A login seen at the HTTP level, including the raw refresh cookie value.</summary>
public sealed record RawLogin(LoginResponse Body, string RefreshCookie, string SetCookieHeader);

/// <summary>
/// Helpers that bypass the cookie container, so tests can copy, replay and race refresh
/// cookies the way an attacker (or two browser tabs) would.
/// </summary>
public static class RawAuth
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A client that never stores or sends cookies on its own.</summary>
    public static HttpClient CookielessClient(this ThreatLockApiFactory api) =>
        api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri("https://localhost") });

    public static async Task<RawLogin> LoginAsync(ThreatLockApiFactory api, string email, string password, IDictionary<string, string>? headers = null)
    {
        using var client = api.CookielessClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login") { Content = JsonContent.Create(new LoginRequest(email, password)) };
        foreach (var (name, value) in headers ?? new Dictionary<string, string>()) request.Headers.Add(name, value);

        var response = await client.SendAsync(request, Ct);
        response.EnsureSuccessStatusCode();
        var setCookie = response.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("tl_refresh=", StringComparison.Ordinal));
        return new RawLogin((await response.Content.ReadFromJsonAsync<LoginResponse>(Ct))!, CookieValue(setCookie), setCookie);
    }

    /// <summary>POST /api/auth/refresh with exactly this cookie (or none) and the CSRF header (or not).</summary>
    public static async Task<HttpResponseMessage> RefreshAsync(ThreatLockApiFactory api, string? refreshCookie, bool csrfHeader = true)
    {
        using var client = api.CookielessClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/refresh");
        if (refreshCookie is not null) request.Headers.Add("Cookie", $"tl_refresh={refreshCookie}");
        if (csrfHeader) request.Headers.Add("X-Requested-With", "threatlock");
        return await client.SendAsync(request, Ct);
    }

    /// <summary>The new refresh cookie value from a response, or null if it set none.</summary>
    public static string? NewRefreshCookie(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Where(c => c.StartsWith("tl_refresh=", StringComparison.Ordinal)).Select(CookieValue).FirstOrDefault(v => v.Length > 0)
            : null;

    private static string CookieValue(string setCookie) => setCookie.Split(';')[0]["tl_refresh=".Length..];
}
