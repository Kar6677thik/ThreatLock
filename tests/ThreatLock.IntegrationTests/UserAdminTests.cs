using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>Role-based access and the privilege-escalation guards (SPEC §4, §13).</summary>
public class UserAdminTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    [Fact]
    public async Task Members_cannot_use_admin_endpoints()
    {
        var owner = await Api.RegisterOrgAsync();
        var member = await Api.CreateUserAsync(owner, "Member");

        Assert.Equal(HttpStatusCode.Forbidden, (await member.Client.GetAsync("/api/admin/users", Ct)).StatusCode);
        var create = await member.Client.PostAsJsonAsync("/api/admin/users",
            new CreateUserRequest(TestData.UniqueEmail(), "X", TestData.Password, null), Ct);
        Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);
    }

    [Fact]
    public async Task Admin_can_add_members_but_not_grant_privileged_roles()
    {
        var owner = await Api.RegisterOrgAsync();
        var admin = await Api.CreateUserAsync(owner, "Admin", "admin");

        var member = await admin.Client.PostAsJsonAsync("/api/admin/users",
            new CreateUserRequest(TestData.UniqueEmail(), "New member", TestData.Password, null), Ct);
        var escalation = await admin.Client.PostAsJsonAsync("/api/admin/users",
            new CreateUserRequest(TestData.UniqueEmail(), "Sneaky", TestData.Password, ["owner"]), Ct);

        Assert.Equal(HttpStatusCode.Created, member.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, escalation.StatusCode);
    }

    [Fact]
    public async Task A_user_can_hold_several_roles_and_every_user_is_a_member()
    {
        var owner = await Api.RegisterOrgAsync();
        var both = await Api.CreateUserAsync(owner, "Both", "admin", "security_admin");

        Assert.Equal(["admin", "member", "security_admin"], both.User.Roles.Order());
    }

    [Fact]
    public async Task Owner_can_change_roles_and_new_roles_apply_from_the_next_login()
    {
        var owner = await Api.RegisterOrgAsync();
        var user = await Api.CreateUserAsync(owner, "Promoted");

        var response = await owner.Client.PutAsJsonAsync($"/api/admin/users/{user.User.Id}/roles", new SetRolesRequest(["admin"]), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The old token still says "member" (claims are frozen into a token when it is issued).
        Assert.Equal(HttpStatusCode.Forbidden, (await user.Client.GetAsync("/api/admin/users", Ct)).StatusCode);
        var relogged = await Api.LoginAsync(user.User.Email, user.Password);
        Assert.Equal(HttpStatusCode.OK, (await relogged.Client.GetAsync("/api/admin/users", Ct)).StatusCode);
    }

    [Fact]
    public async Task Only_owners_change_roles_and_owners_cannot_demote_themselves()
    {
        var owner = await Api.RegisterOrgAsync();
        var admin = await Api.CreateUserAsync(owner, "Admin", "admin");

        var byAdmin = await admin.Client.PutAsJsonAsync($"/api/admin/users/{admin.User.Id}/roles", new SetRolesRequest(["owner"]), Ct);
        var selfDemote = await owner.Client.PutAsJsonAsync($"/api/admin/users/{owner.User.Id}/roles", new SetRolesRequest(["admin"]), Ct);
        var unknown = await owner.Client.PutAsJsonAsync($"/api/admin/users/{admin.User.Id}/roles", new SetRolesRequest(["superuser"]), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, byAdmin.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, selfDemote.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
    }

    [Fact]
    public async Task Duplicate_email_is_409()
    {
        var owner = await Api.RegisterOrgAsync();

        var response = await owner.Client.PostAsJsonAsync("/api/admin/users",
            new CreateUserRequest(owner.User.Email, "Clone", TestData.Password, null), Ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Revoking_sessions_requires_security_admin_or_owner()
    {
        var owner = await Api.RegisterOrgAsync();
        var admin = await Api.CreateUserAsync(owner, "Admin", "admin");
        var security = await Api.CreateUserAsync(owner, "Sec", "security_admin");
        var victim = await Api.CreateUserAsync(owner, "Victim");

        var byAdmin = await admin.Client.PostAsync($"/api/admin/users/{victim.User.Id}/revoke-sessions", null, Ct);
        var bySecurity = await security.Client.PostAsync($"/api/admin/users/{victim.User.Id}/revoke-sessions", null, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, byAdmin.StatusCode);
        Assert.Equal(HttpStatusCode.OK, bySecurity.StatusCode);
    }

    [Fact]
    public async Task Listing_users_shows_their_roles()
    {
        var owner = await Api.RegisterOrgAsync();
        await Api.CreateUserAsync(owner, "Sec", "security_admin");

        var users = await owner.Client.GetFromJsonAsync<List<AdminUserView>>("/api/admin/users", Ct);

        Assert.Equal(2, users!.Count);
        Assert.Contains(users, u => u.DisplayName == "Sec" && u.Roles.SequenceEqual(["member", "security_admin"]));
        var me = await owner.Client.GetFromJsonAsync<UserView>("/api/me", Ct);
        Assert.Contains(users, u => u.Id == me!.Id);
    }
}
