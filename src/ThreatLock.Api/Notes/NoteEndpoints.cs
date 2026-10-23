using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api.Auth;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Notes;

public sealed record NoteRequest(
    [property: Required, StringLength(200, MinimumLength = 1)] string Title,
    [property: StringLength(20_000)] string? Body,
    bool Shared);

public sealed record NoteSummary(Guid Id, string Title, bool Shared, bool IsOwner, string OwnerName, DateTimeOffset UpdatedAt);

public sealed record NoteView(Guid Id, string Title, string Body, bool Shared, bool IsOwner, string OwnerName, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);

public sealed record NotesExport(DateTimeOffset ExportedAt, int Count, IReadOnlyList<NoteView> Notes);

/// <summary>
/// Notes CRUD and bulk export (SPEC §13). Two independent layers protect every query:
/// <list type="number">
/// <item>The EF Core tenant filter: only rows from the caller's org exist as far as this code can see.</item>
/// <item>Object-level authorization: within the org, a note is readable if you own it or it's
/// shared, and writable only by its owner.</item>
/// </list>
/// A note you cannot read returns 404, not 403, so its existence isn't revealed.
/// </summary>
public static class NoteEndpoints
{
    public static void MapNoteEndpoints(this IEndpointRouteBuilder app)
    {
        var notes = app.MapGroup("/api/notes").WithTags("Notes");
        notes.MapGet("/", List);
        notes.MapPost("/", Create);
        notes.MapGet("/export", Export);
        notes.MapGet("/{id:guid}", Get);
        notes.MapPut("/{id:guid}", Update);
        notes.MapDelete("/{id:guid}", Delete);
    }

    /// <summary>Notes the caller may read: their own, plus everything shared in their org.</summary>
    private static IQueryable<Note> Readable(ThreatLockDbContext db, Guid userId) =>
        db.Notes.Where(n => n.OwnerId == userId || n.Shared);

    private static async Task<Ok<List<NoteSummary>>> List(ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var userId = me.UserId;
        var notes = await Readable(db, userId)
            .OrderByDescending(n => n.UpdatedAt)
            .Join(db.Users, n => n.OwnerId, u => u.Id, (n, u) =>
                new NoteSummary(n.Id, n.Title, n.Shared, n.OwnerId == userId, u.DisplayName, n.UpdatedAt))
            .ToListAsync(ct);
        return TypedResults.Ok(notes);
    }

    private static async Task<Results<Ok<NoteView>, NotFound>> Get(Guid id, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var note = await ProjectViews(db, Readable(db, me.UserId).Where(n => n.Id == id), me.UserId).SingleOrDefaultAsync(ct);
        return note is null ? TypedResults.NotFound() : TypedResults.Ok(note);
    }

    private static async Task<Created<NoteView>> Create(
        NoteRequest request, ThreatLockDbContext db, CurrentUser me, TimeProvider time, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var note = new Note
        {
            // Org and owner come from the token, never from the request (mass-assignment guard).
            OrgId = me.RequiredOrgId,
            OwnerId = me.UserId,
            Title = request.Title.Trim(),
            Body = request.Body ?? "",
            Shared = request.Shared,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.Notes.Add(note);
        await db.SaveChangesAsync(ct);

        var view = await ProjectViews(db, db.Notes.Where(n => n.Id == note.Id), me.UserId).SingleAsync(ct);
        return TypedResults.Created($"/api/notes/{note.Id}", view);
    }

    private static async Task<Results<Ok<NoteView>, NotFound, ForbidHttpResult>> Update(
        Guid id, NoteRequest request, ThreatLockDbContext db, CurrentUser me, TimeProvider time, CancellationToken ct)
    {
        var note = await Readable(db, me.UserId).SingleOrDefaultAsync(n => n.Id == id, ct);
        if (note is null) return TypedResults.NotFound();
        // You can see a colleague's shared note, so 403 reveals nothing new here.
        if (note.OwnerId != me.UserId) return TypedResults.Forbid();

        note.Title = request.Title.Trim();
        note.Body = request.Body ?? "";
        note.Shared = request.Shared;
        note.UpdatedAt = time.GetUtcNow();
        await db.SaveChangesAsync(ct);

        var view = await ProjectViews(db, db.Notes.Where(n => n.Id == id), me.UserId).SingleAsync(ct);
        return TypedResults.Ok(view);
    }

    private static async Task<Results<NoContent, NotFound, ForbidHttpResult>> Delete(
        Guid id, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var note = await Readable(db, me.UserId).SingleOrDefaultAsync(n => n.Id == id, ct);
        if (note is null) return TypedResults.NotFound();
        if (note.OwnerId != me.UserId) return TypedResults.Forbid();

        db.Notes.Remove(note);
        await db.SaveChangesAsync(ct);
        return TypedResults.NoContent();
    }

    /// <summary>
    /// Everything the caller can read, in one download. Legitimate (backups, migrations) and
    /// exactly what an attacker with a stolen session wants, which is why detector D4 watches it.
    /// </summary>
    private static async Task<FileContentHttpResult> Export(
        ThreatLockDbContext db, CurrentUser me, TimeProvider time, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var notes = await ProjectViews(db, Readable(db, me.UserId).OrderBy(n => n.CreatedAt), me.UserId).ToListAsync(ct);
        var json = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            new NotesExport(now, notes.Count, notes), System.Text.Json.JsonSerializerOptions.Web);
        return TypedResults.File(json, "application/json", $"threatlock-notes-{now:yyyyMMdd-HHmmss}.json");
    }

    private static IQueryable<NoteView> ProjectViews(ThreatLockDbContext db, IQueryable<Note> notes, Guid userId) =>
        notes.Join(db.Users, n => n.OwnerId, u => u.Id, (n, u) =>
            new NoteView(n.Id, n.Title, n.Body, n.Shared, n.OwnerId == userId, u.DisplayName, n.CreatedAt, n.UpdatedAt));
}
