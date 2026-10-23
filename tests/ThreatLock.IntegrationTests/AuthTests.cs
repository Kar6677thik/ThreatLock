using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ThreatLock.Api.Auth;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>Registration, login, lockout, and token validation (SPEC §6.2, §6.3).</summary>
public class AuthTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    [Fact]
    public async Task Register_org_creates_owner_and_returns_working_token()
    {
        var owner = await Api.RegisterOrgAsync("Asha");

        Assert.Equal(["member", "owner"], owner.User.Roles.Order());
        var me = await owner.Client.GetFromJsonAsync<UserView>("/api/me", Ct);
        Assert.Equal(owner.User.Id, me!.Id);
        Assert.Equal("Asha", me.DisplayName);
    }

    [Fact]
    public async Task Register_org_with_taken_slug_is_409()
    {
        using var client = Api.CreateClient();
        var slug = TestData.UniqueSlug();
        var first = await client.PostAsJsonAsync("/api/auth/register-org",
            new RegisterOrgRequest("One", slug, "A", TestData.UniqueEmail(), TestData.Password), Ct);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var second = await client.PostAsJsonAsync("/api/auth/register-org",
            new RegisterOrgRequest("Two", slug, "B", TestData.UniqueEmail(), TestData.Password), Ct);

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Register_with_existing_email_is_409_and_creates_no_org()
    {
        using var client = Api.CreateClient();
        var email = TestData.UniqueEmail();
        await client.PostAsJsonAsync("/api/auth/register-org",
            new RegisterOrgRequest("One", TestData.UniqueSlug(), "A", email, TestData.Password), Ct);

        var slug = TestData.UniqueSlug();
        var duplicate = await client.PostAsJsonAsync("/api/auth/register-org",
            new RegisterOrgRequest("Two", slug, "B", email.ToUpperInvariant(), TestData.Password), Ct);
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);

        // The transaction rolled back, so the slug is still free.
        var retry = await client.PostAsJsonAsync("/api/auth/register-org",
            new RegisterOrgRequest("Two", slug, "B", TestData.UniqueEmail(), TestData.Password), Ct);
        Assert.Equal(HttpStatusCode.Created, retry.StatusCode);
    }

    [Theory]
    [InlineData("short pw", "Password")]                  // under 12 characters
    [InlineData("correct horse battery", "Email", "not-an-email")]
    [InlineData("correct horse battery", "OrgSlug", "a@b.test", "Bad Slug!")]
    public async Task Register_with_invalid_input_is_400_naming_the_field(
        string password, string field, string email = "valid@example.test", string? slug = null)
    {
        using var client = Api.CreateClient();
        var request = new RegisterOrgRequest("Valid Org", slug ?? TestData.UniqueSlug(), "Name",
            email == "valid@example.test" ? TestData.UniqueEmail() : email, password);

        var response = await client.PostAsJsonAsync("/api/auth/register-org", request, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errors = await ReadErrorsAsync(response);
        Assert.Contains(field, errors);
    }

    [Fact]
    public async Task Signup_can_be_disabled()
    {
        await using var api = new ThreatLockApiFactory(containers, new Dictionary<string, string?> { ["Demo:AllowSignup"] = "false" });
        using var client = api.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/register-org",
            new RegisterOrgRequest("Org", TestData.UniqueSlug(), "A", TestData.UniqueEmail(), TestData.Password), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Login_returns_a_60_minute_token_in_M2()
    {
        var owner = await Api.RegisterOrgAsync();

        using var client = Api.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(owner.User.Email, owner.Password), Ct);
        var login = await response.Content.ReadFromJsonAsync<LoginResponse>(Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.InRange(login!.ExpiresAt - DateTimeOffset.UtcNow, TimeSpan.FromMinutes(59), TimeSpan.FromMinutes(60));
    }

    [Fact]
    public async Task Wrong_password_and_unknown_email_get_the_same_401()
    {
        var owner = await Api.RegisterOrgAsync();
        using var client = Api.CreateClient();

        var wrongPassword = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(owner.User.Email, "wrong password!!"), Ct);
        var unknownEmail = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(TestData.UniqueEmail(), "wrong password!!"), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownEmail.StatusCode);
        Assert.Equal(await DetailAsync(wrongPassword), await DetailAsync(unknownEmail));
    }

    [Fact]
    public async Task Account_locks_after_five_failures_even_for_the_right_password()
    {
        var owner = await Api.RegisterOrgAsync();
        using var client = Api.CreateClient();

        for (var i = 0; i < 5; i++)
        {
            await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(owner.User.Email, "wrong password!!"), Ct);
        }

        var correct = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(owner.User.Email, owner.Password), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, correct.StatusCode);
    }

    [Fact]
    public async Task Successful_login_resets_the_failure_count()
    {
        var owner = await Api.RegisterOrgAsync();
        using var client = Api.CreateClient();

        for (var i = 0; i < 4; i++)
        {
            await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(owner.User.Email, "wrong password!!"), Ct);
        }
        await Api.LoginAsync(owner.User.Email, owner.Password);
        for (var i = 0; i < 4; i++)
        {
            await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(owner.User.Email, "wrong password!!"), Ct);
        }

        // 8 failures in total, but never 5 in a row: still not locked.
        await Api.LoginAsync(owner.User.Email, owner.Password);
    }

    [Fact]
    public async Task Requests_without_a_token_are_401()
    {
        using var client = Api.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/me", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/notes", Ct)).StatusCode);
    }

    public static TheoryData<string> ForgedTokenKinds => ["tampered", "wrong-key", "alg-none", "expired", "wrong-audience", "wrong-issuer"];

    [Theory]
    [MemberData(nameof(ForgedTokenKinds))]
    public async Task Forged_or_invalid_tokens_are_rejected(string kind)
    {
        var owner = await Api.RegisterOrgAsync();
        var sub = owner.User.Id.ToString();
        var org = owner.User.OrgId.ToString();
        var otherKey = Convert.ToBase64String("an-attacker-chosen-signing-key-0123456789"u8.ToArray());

        var token = kind switch
        {
            "tampered" => TestTokens.Tamper(owner.AccessToken),
            "wrong-key" => TestTokens.Create(sub, org, signingKeyBase64: otherKey),
            "alg-none" => TestTokens.AlgNone(sub, org),
            // Beyond the 30 s clock-skew allowance.
            "expired" => TestTokens.Create(sub, org, issuedAt: DateTime.UtcNow.AddHours(-2), expires: DateTime.UtcNow.AddMinutes(-1)),
            "wrong-audience" => TestTokens.Create(sub, org, audience: "some-other-api"),
            "wrong-issuer" => TestTokens.Create(sub, org, issuer: "evil"),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        using var client = Api.CreateClient(token);

        var response = await client.GetAsync("/api/me", Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_correctly_forged_token_shows_why_the_signing_key_is_a_secret()
    {
        // Anyone who has the signing key can mint a valid token for any user. This is why the
        // key must live in a secret store, never in the repository (SPEC §19).
        var owner = await Api.RegisterOrgAsync();
        using var client = Api.CreateClient(TestTokens.Create(owner.User.Id.ToString(), owner.User.OrgId.ToString()));

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/me", Ct)).StatusCode);
    }

    private static async Task<HashSet<string>> ReadErrorsAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        return [.. json.RootElement.GetProperty("errors").EnumerateObject().Select(p => p.Name)];
    }

    private static async Task<string?> DetailAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        return json.RootElement.GetProperty("detail").GetString();
    }
}
