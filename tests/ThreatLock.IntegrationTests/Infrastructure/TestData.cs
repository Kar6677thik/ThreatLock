using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.Api.Notes;

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>A user plus a ready-to-use client authenticated as them.</summary>
public sealed record TestUser(UserView User, string AccessToken, string Password, HttpClient Client);

/// <summary>Creates uniquely named orgs, users and notes so tests never collide.</summary>
public static class TestData
{
    public const string Password = "correct horse battery staple";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static string UniqueSlug() => $"org-{Guid.NewGuid():N}"[..20];

    public static string UniqueEmail(string name = "user") => $"{name}-{Guid.NewGuid():N}@example.test";

    /// <summary>Registers a fresh org; the returned user is its owner.</summary>
    public static async Task<TestUser> RegisterOrgAsync(this ThreatLockApiFactory api, string displayName = "Owner")
    {
        using var anonymous = api.CreateClient();
        var response = await anonymous.PostAsJsonAsync("/api/auth/register-org", new RegisterOrgRequest(
            "Test Org", UniqueSlug(), displayName, UniqueEmail("owner"), Password), Ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var login = (await response.Content.ReadFromJsonAsync<LoginResponse>(Ct))!;
        return new TestUser(login.User, login.AccessToken, Password, api.CreateClient(login.AccessToken));
    }

    /// <summary>Creates a user in the admin's org with the given roles, then logs in as them.</summary>
    public static async Task<TestUser> CreateUserAsync(this ThreatLockApiFactory api, TestUser admin, string displayName, params string[] roles)
    {
        var email = UniqueEmail(displayName.ToLowerInvariant());
        var created = await admin.Client.PostAsJsonAsync("/api/admin/users",
            new CreateUserRequest(email, displayName, Password, roles), Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        return await api.LoginAsync(email, Password);
    }

    public static async Task<TestUser> LoginAsync(this ThreatLockApiFactory api, string email, string password)
    {
        using var anonymous = api.CreateClient();
        var response = await anonymous.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var login = (await response.Content.ReadFromJsonAsync<LoginResponse>(Ct))!;
        return new TestUser(login.User, login.AccessToken, password, api.CreateClient(login.AccessToken));
    }

    public static async Task<NoteView> CreateNoteAsync(this TestUser user, string title, bool shared = false, string body = "body")
    {
        var response = await user.Client.PostAsJsonAsync("/api/notes", new NoteRequest(title, body, shared), Ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<NoteView>(Ct))!;
    }
}
