using System.Globalization;
using System.Text.Json.Nodes;
using ThreatLock.Core.Events;
using ThreatLock.Core.Policy;

namespace ThreatLock.Core.Detection;

/// <summary>Tunables for D4 (SPEC §8.2).</summary>
public sealed record NewDeviceExportSettings(double WindowMinutes = 30, double BulkReadThreshold = 50)
{
    public const string WindowMinutesKey = "windowMinutes";
    public const string BulkReadThresholdKey = "bulkReadThreshold";

    public static NewDeviceExportSettings Default { get; } = new();

    public TimeSpan Window => TimeSpan.FromMinutes(WindowMinutes);

    public NewDeviceExportSettings For(DetectorPolicy policy) => this with
    {
        WindowMinutes = policy.Threshold(WindowMinutesKey, WindowMinutes),
        BulkReadThreshold = policy.Threshold(BulkReadThresholdKey, BulkReadThreshold),
    };
}

/// <summary>
/// D4 (SPEC §8.2): a login from a device this user has never used, followed soon by taking
/// everything: an export, or reading more than <see cref="NewDeviceExportSettings.BulkReadThreshold"/>
/// distinct notes. That's the shape of "stole the password, grab the data, leave".
/// <para>
/// "New" is decided by the API at login, where PostgreSQL's <c>user_devices</c> is the source of
/// truth, and arrives as <c>metadata.newDevice</c>. A user's very first device is never "new":
/// nothing distinguishes it from a brand-new account's normal start.
/// </para>
/// Known weakness: device ids are chosen by the client and forgeable. D5 and D2 cover part of that.
/// </summary>
public sealed class NewDeviceExportDetector(NewDeviceExportSettings? settings = null) : IDetector
{
    public const string NewDeviceMetadata = "newDevice";

    private readonly NewDeviceExportSettings defaults = settings ?? NewDeviceExportSettings.Default;

    public string Id => DetectorIds.NewDeviceExport;

    public async ValueTask<IReadOnlyList<DetectionSignal>> EvaluateAsync(ActivityEvent evt, DetectionContext context, CancellationToken ct)
    {
        if (evt.UserId is not { } userId || string.IsNullOrEmpty(evt.DeviceId)) return [];

        var settings = defaults.For(context.EffectivePolicy.For(Id));
        var markKey = $"newdev:{userId}:{evt.DeviceId}";

        if (evt.Type == EventTypes.LoginSucceeded)
        {
            if (evt.Metadata?[NewDeviceMetadata]?.GetValue<bool>() == true)
            {
                // Remember when this device first appeared; the window is measured from here.
                await context.State.SetValueAsync(markKey, evt.OccurredAt.ToString("O", CultureInfo.InvariantCulture), settings.Window,
                    onlyIfAbsent: true, ct);
            }

            return [];
        }

        if (evt.Type is not (EventTypes.ExportRequested or EventTypes.NoteRead)) return [];

        var mark = await context.State.GetValueAsync(markKey, ct);
        if (mark is null || !DateTimeOffset.TryParse(mark, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var firstSeen)) return [];
        var sinceFirstLogin = evt.OccurredAt - firstSeen;
        if (sinceFirstLogin < TimeSpan.Zero || sinceFirstLogin > settings.Window) return [];

        var evidence = new JsonObject
        {
            ["deviceId"] = evt.DeviceId,
            ["firstSeenAt"] = firstSeen.ToString("O", CultureInfo.InvariantCulture),
            ["minutesSinceFirstLogin"] = Math.Round(sinceFirstLogin.TotalMinutes, 1),
            ["trigger"] = evt.Type,
            ["ip"] = evt.Ip,
            ["userAgent"] = evt.UserAgent,
        };

        if (evt.Type == EventTypes.NoteRead)
        {
            var noteId = evt.Metadata?["noteId"]?.GetValue<string>();
            if (noteId is null) return [];
            var distinct = await context.State.CountInWindowAsync($"newdev-reads:{userId}:{evt.DeviceId}", noteId, evt.OccurredAt, settings.Window, ct);
            if (distinct <= settings.BulkReadThreshold) return [];
            evidence["distinctNotesRead"] = distinct;
        }
        else
        {
            evidence["noteCount"] = evt.Metadata?["noteCount"]?.DeepClone();
        }

        return
        [
            new DetectionSignal(Id, evt.OrgId, userId, evt.SessionId, Severity.High, $"newdev-export:{userId}:{evt.DeviceId}",
                evidence, evt.Id, evt.Ip is null ? [] : [evt.Ip]),
        ];
    }
}
