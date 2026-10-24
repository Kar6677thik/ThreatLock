using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api.Auth;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Admin;

/// <param name="Count">How many anomalies about this user were grouped into this entry.</param>
public sealed record NotificationView(
    Guid Id, string Title, Guid AnomalyId, Guid LastAnomalyId, Guid SubjectUserId, int Count,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset? ReadAt);

public sealed record Inbox(int Unread, IReadOnlyList<NotificationView> Items);

/// <summary>
/// The admin's in-app inbox (SPEC §10.4). Everyone sees only their *own* notifications: the
/// recipient is the caller, never a parameter, so there's no id to tamper with.
/// </summary>
public static class NotificationEndpoints
{
    public static void MapNotificationEndpoints(this IEndpointRouteBuilder app)
    {
        var inbox = app.MapGroup("/api/admin/notifications").WithTags("Admin: notifications").RequireAuthorization(Policies.Admin);
        inbox.MapGet("/", List);
        inbox.MapPost("/{id:guid}/read", MarkRead);
        inbox.MapPost("/read-all", MarkAllRead);
    }

    private static async Task<Ok<Inbox>> List(ThreatLockDbContext db, CurrentUser me, bool? unreadOnly, CancellationToken ct)
    {
        var mine = db.Notifications.Where(n => n.RecipientUserId == me.UserId && n.OrgId == me.RequiredOrgId);
        var unread = await mine.CountAsync(n => n.ReadAt == null, ct);
        var items = await (unreadOnly == true ? mine.Where(n => n.ReadAt == null) : mine)
            .OrderByDescending(n => n.UpdatedAt)
            .Take(100)
            .Select(n => new NotificationView(n.Id, n.Title, n.AnomalyId, n.LastAnomalyId, n.SubjectUserId, n.Count, n.CreatedAt, n.UpdatedAt, n.ReadAt))
            .ToListAsync(ct);
        return TypedResults.Ok(new Inbox(unread, items));
    }

    private static async Task<Results<NoContent, NotFound>> MarkRead(Guid id, ThreatLockDbContext db, CurrentUser me, TimeProvider time, CancellationToken ct)
    {
        var mine = db.Notifications.Where(n => n.Id == id && n.RecipientUserId == me.UserId);
        if (!await mine.AnyAsync(ct)) return TypedResults.NotFound();

        await mine.Where(n => n.ReadAt == null).ExecuteUpdateAsync(set => set.SetProperty(n => n.ReadAt, time.GetUtcNow()), ct);
        return TypedResults.NoContent();
    }

    private static async Task<NoContent> MarkAllRead(ThreatLockDbContext db, CurrentUser me, TimeProvider time, CancellationToken ct)
    {
        await db.Notifications
            .Where(n => n.RecipientUserId == me.UserId && n.ReadAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(n => n.ReadAt, time.GetUtcNow()), ct);
        return TypedResults.NoContent();
    }
}
