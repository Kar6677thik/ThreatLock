using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Notes;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>Notes CRUD, sharing rules and export within one org (SPEC §13).</summary>
public class NotesTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    [Fact]
    public async Task Owner_can_create_read_update_and_delete_a_note()
    {
        var owner = await Api.RegisterOrgAsync();

        var created = await owner.CreateNoteAsync("Draft", body: "v1");
        Assert.True(created.IsOwner);

        var updated = await owner.Client.PutAsJsonAsync($"/api/notes/{created.Id}", new NoteRequest("Final", "v2", Shared: true), Ct);
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);

        var read = await owner.Client.GetFromJsonAsync<NoteView>($"/api/notes/{created.Id}", Ct);
        Assert.Equal(("Final", "v2", true), (read!.Title, read.Body, read.Shared));
        Assert.True(read.UpdatedAt >= read.CreatedAt);

        Assert.Equal(HttpStatusCode.NoContent, (await owner.Client.DeleteAsync($"/api/notes/{created.Id}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await owner.Client.GetAsync($"/api/notes/{created.Id}", Ct)).StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task Title_is_required(string? title)
    {
        var owner = await Api.RegisterOrgAsync();

        var response = await owner.Client.PostAsJsonAsync("/api/notes", new { title, body = "x", shared = false }, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Colleague_can_read_shared_notes_but_not_private_ones()
    {
        var owner = await Api.RegisterOrgAsync();
        var colleague = await Api.CreateUserAsync(owner, "Ben");
        var shared = await owner.CreateNoteAsync("Team plan", shared: true);
        var secret = await owner.CreateNoteAsync("Diary");

        var list = await colleague.Client.GetFromJsonAsync<List<NoteSummary>>("/api/notes", Ct);

        var visible = Assert.Single(list!);
        Assert.Equal(shared.Id, visible.Id);
        Assert.False(visible.IsOwner);
        Assert.Equal(HttpStatusCode.OK, (await colleague.Client.GetAsync($"/api/notes/{shared.Id}", Ct)).StatusCode);
        // 404, not 403: a private note's existence is itself private.
        Assert.Equal(HttpStatusCode.NotFound, (await colleague.Client.GetAsync($"/api/notes/{secret.Id}", Ct)).StatusCode);
    }

    [Fact]
    public async Task Colleague_cannot_edit_or_delete_a_shared_note()
    {
        var owner = await Api.RegisterOrgAsync();
        var colleague = await Api.CreateUserAsync(owner, "Ben");
        var shared = await owner.CreateNoteAsync("Team plan", shared: true);

        var put = await colleague.Client.PutAsJsonAsync($"/api/notes/{shared.Id}", new NoteRequest("Hijacked", "", false), Ct);
        var delete = await colleague.Client.DeleteAsync($"/api/notes/{shared.Id}", Ct);

        Assert.Equal(HttpStatusCode.Forbidden, put.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
        var unchanged = await owner.Client.GetFromJsonAsync<NoteView>($"/api/notes/{shared.Id}", Ct);
        Assert.Equal("Team plan", unchanged!.Title);
    }

    [Fact]
    public async Task Export_contains_exactly_what_the_caller_can_read_as_a_download()
    {
        var owner = await Api.RegisterOrgAsync();
        var colleague = await Api.CreateUserAsync(owner, "Ben");
        var mine = await colleague.CreateNoteAsync("Mine");
        var shared = await owner.CreateNoteAsync("Shared", shared: true);
        await owner.CreateNoteAsync("Private");

        var response = await colleague.Client.GetAsync("/api/notes/export", Ct);
        var export = await response.Content.ReadFromJsonAsync<NotesExport>(Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("attachment", response.Content.Headers.ContentDisposition?.DispositionType);
        Assert.Equal(2, export!.Count);
        Assert.Equal(new[] { mine.Id, shared.Id }.Order(), export.Notes.Select(n => n.Id).Order());
    }
}
