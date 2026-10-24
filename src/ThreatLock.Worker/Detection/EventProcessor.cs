using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using ThreatLock.Core.Policy;
using ThreatLock.Core.Response;
using ThreatLock.Infrastructure.Detection;
using ThreatLock.Infrastructure.Policy;

namespace ThreatLock.Worker.Detection;

/// <summary>
/// Runs the detectors over one event, judges each signal with the org's policy, and stores the
/// anomaly together with its decision (SPEC §8–9). Idempotent: the same event processed twice
/// yields the same anomalies, because signals de-duplicate on their key and an anomaly's decision
/// is written only when it's created (and so is its response job, M6).
/// </summary>
public sealed partial class EventProcessor(
    IEnumerable<IDetector> detectors,
    IDetectorState state,
    ITorExitList torExits,
    AnomalyStore anomalies,
    PolicyStore policies,
    ILogger<EventProcessor> logger)
{
    /// <summary>Returns how many *new* anomalies the event produced.</summary>
    public async Task<int> ProcessAsync(ActivityEvent evt, CancellationToken ct)
    {
        var policy = await policies.GetCachedAsync(evt.OrgId, ct);
        var context = new DetectionContext(state, torExits, policy.Policy);

        var created = 0;
        IReadOnlyList<string>? roles = null;
        foreach (var detector in detectors)
        {
            // An org can switch a detector off entirely (SPEC §9.1): then it doesn't even run.
            if (policy.Policy.For(detector.Id).Mode == DetectorMode.Off) continue;

            foreach (var signal in await detector.EvaluateAsync(evt, context, ct))
            {
                roles ??= await policies.GetUserRolesAsync(signal.UserId, ct);
                var decision = PolicyEvaluator.Decide(signal, policy.Policy, roles);

                // "notified" and "responded" need work done; the job commits together with the anomaly.
                var plan = ResponsePlanner.Plan(decision, signal.Severity, policy.Policy);
                var result = await anomalies.UpsertAsync(signal, decision, policy.Version, plan, ct);
                if (!result.Created) continue;

                created++;
                LogAnomaly(signal.Detector, signal.Severity, decision.Outcome, decision.Reason, policy.Version, result.Id, signal.UserId, evt.Id);
            }
        }

        return created;
    }

    [LoggerMessage(Level = LogLevel.Warning,
        Message = "Anomaly {AnomalyId}: {Detector} ({Severity}) → {Outcome} ({Reason}, policy v{PolicyVersion}) for user {UserId}, from event {EventId}")]
    private partial void LogAnomaly(string detector, Severity severity, DecisionOutcome outcome, string reason, int policyVersion,
        Guid anomalyId, Guid userId, Guid eventId);
}
