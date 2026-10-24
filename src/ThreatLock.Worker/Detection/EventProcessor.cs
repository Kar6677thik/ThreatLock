using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using ThreatLock.Infrastructure.Detection;

namespace ThreatLock.Worker.Detection;

/// <summary>
/// Runs every detector over one event and stores what they find (SPEC §8). Idempotent: the same
/// event processed twice yields the same anomalies, because signals de-duplicate on their key.
/// </summary>
public sealed partial class EventProcessor(
    IEnumerable<IDetector> detectors,
    IDetectorState state,
    ITorExitList torExits,
    AnomalyStore anomalies,
    ILogger<EventProcessor> logger)
{
    private readonly DetectionContext context = new(state, torExits);

    /// <summary>Returns how many *new* anomalies the event produced.</summary>
    public async Task<int> ProcessAsync(ActivityEvent evt, CancellationToken ct)
    {
        var created = 0;
        foreach (var detector in detectors)
        {
            foreach (var signal in await detector.EvaluateAsync(evt, context, ct))
            {
                var result = await anomalies.UpsertAsync(signal, ct);
                if (!result.Created) continue;

                created++;
                LogAnomaly(signal.Detector, signal.Severity, result.Id, signal.OrgId, signal.UserId, evt.Id);
            }
        }

        return created;
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Anomaly {AnomalyId}: {Detector} ({Severity}) for user {UserId} in org {OrgId}, from event {EventId}")]
    private partial void LogAnomaly(string detector, Severity severity, Guid anomalyId, Guid orgId, Guid userId, Guid eventId);
}
