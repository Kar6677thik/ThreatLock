using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Notes;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// The tenant isolation rule (SPEC §4): nothing in org B is visible or changeable from org A,
/// even when A knows B's ids. Owners of org A have every role, so this also proves roles don't
/// cross org boundaries.
/// </summary>
public class TenantIsolationTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    [Fact]
    public async Task Another_orgs_note_is_not_found_by_id_even_when_shared()
    {
        var alice = await Api.RegisterOrgAsync("Alice");   // org A
        var mallory = await Api.RegisterOrgAsync("Mallory"); // org B, owner of her org
        var note = await alice.CreateNoteAsync("Org A shared plan", shared: true);

        var get = await mallory.Client.GetAsync($"/api/notes/{note.Id}", Ct);
        var put = await mallory.Client.PutAsJsonAsync($"/api/notes/{note.Id}", new NoteRequest("pwned", "", true), Ct);
        var delete = await mallory.Client.DeleteAsync($"/api/notes/{note.Id}", Ct);

        Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, put.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await alice.Client.GetAsync($"/api/notes/{note.Id}", Ct)).StatusCode);
    }

    [Fact]
    public async Task Lists_and_exports_never_include_another_orgs_notes()
    {
        var alice = await Api.RegisterOrgAsync("Alice");
        var mallory = await Api.RegisterOrgAsync("Mallory");
        await alice.CreateNoteAsync("Org A shared plan", shared: true);

        var list = await mallory.Client.GetFromJsonAsync<List<NoteSummary>>("/api/notes", Ct);
        var export = await mallory.Client.GetFromJsonAsync<NotesExport>("/api/notes/export", Ct);

        Assert.Empty(list!);
        Assert.Equal(0, export!.Count);
    }

    [Fact]
    public async Task Org_and_owner_in_the_request_body_are_ignored()
    {
        // Mass-assignment attempt: smuggle another org's id into the create request.
        var alice = await Api.RegisterOrgAsync("Alice");
        var mallory = await Api.RegisterOrgAsync("Mallory");

        var response = await mallory.Client.PostAsJsonAsync("/api/notes",
            new { title = "planted", body = "", shared = true, orgId = alice.User.OrgId, ownerId = alice.User.Id }, Ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var aliceSees = await alice.Client.GetFromJsonAsync<List<NoteSummary>>("/api/notes", Ct);
        Assert.Empty(aliceSees!);
    }

    [Fact]
    public async Task Admins_see_and_manage_only_users_of_their_own_org()
    {
        var alice = await Api.RegisterOrgAsync("Alice");
        var bob = await Api.CreateUserAsync(alice, "Bob");
        var mallory = await Api.RegisterOrgAsync("Mallory");

        var users = await mallory.Client.GetFromJsonAsync<List<AdminUserView>>("/api/admin/users", Ct);
        var roles = await mallory.Client.PutAsJsonAsync($"/api/admin/users/{bob.User.Id}/roles", new SetRolesRequest(["owner"]), Ct);
        var revoke = await mallory.Client.PostAsync($"/api/admin/users/{bob.User.Id}/revoke-sessions", null, Ct);

        Assert.Equal([mallory.User.Id], users!.Select(u => u.Id));
        Assert.Equal(HttpStatusCode.NotFound, roles.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, revoke.StatusCode);
    }
}
