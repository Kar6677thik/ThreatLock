using System.Diagnostics.Metrics;

namespace ThreatLock.Infrastructure.Observability;

/// <summary>
/// ThreatLock's own metrics (SPEC §18), on .NET's built-in <see cref="System.Diagnostics.Metrics"/>.
/// OpenTelemetry (configured in the API and the Worker) exports them in Prometheus format; this
/// class doesn't know or care how they're exported.
/// <para>
/// Labels are low-cardinality on purpose: detector, decision, outcome, source. Never a user id or
/// an IP: every distinct label value is a separate time series, and IPs are personal data.
/// </para>
/// </summary>
public sealed class ThreatLockMetrics
{
    public const string MeterName = "ThreatLock";

    private readonly Counter<long> eventsCaptured;
    private readonly Counter<long> publishFailures;
    private readonly Counter<long> eventsDead;
    private readonly Counter<long> signals;
    private readonly Counter<long> anomalies;
    private readonly Histogram<double> jobDuration;
    private readonly Counter<long> jobAttempts;
    private readonly Histogram<double> timeToRevoke;
    private readonly Histogram<double> sessionCheck;
    private long streamLag;

    public ThreatLockMetrics(IMeterFactory meters)
    {
        var meter = meters.Create(MeterName);
        eventsCaptured = meter.CreateCounter<long>("tl_events_captured", description: "Activity events recorded by the API");
        publishFailures = meter.CreateCounter<long>("tl_events_publish_failures", description: "Events saved but not put on the stream (the sweeper retries them)");
        eventsDead = meter.CreateCounter<long>("tl_events_dead", description: "Stream messages dead-lettered after too many failed deliveries");
        signals = meter.CreateCounter<long>("tl_detector_signals", description: "Signals raised by detectors, before de-duplication");
        anomalies = meter.CreateCounter<long>("tl_anomalies", description: "New anomalies, by detector and decision");
        jobDuration = meter.CreateHistogram<double>("tl_response_job_duration", unit: "s", description: "Time to run one response job attempt");
        jobAttempts = meter.CreateCounter<long>("tl_response_job_attempts", description: "Response job attempts, by outcome");
        timeToRevoke = meter.CreateHistogram<double>("tl_time_to_revoke", unit: "s",
            description: "Server-side: from the anomaly's first event to its sessions being revoked");
        sessionCheck = meter.CreateHistogram<double>("tl_session_check_duration", unit: "s", description: "The per-request session check, by where the answer came from");
        meter.CreateObservableGauge("tl_stream_lag", () => Interlocked.Read(ref streamLag), description: "Events on the stream not yet read by the detectors' consumer group");
    }

    public void EventCaptured() => eventsCaptured.Add(1);

    public void PublishFailed() => publishFailures.Add(1);

    public void EventDeadLettered() => eventsDead.Add(1);

    public void SignalRaised(string detector) => signals.Add(1, new KeyValuePair<string, object?>("detector", detector));

    public void AnomalyCreated(string detector, string decision) =>
        anomalies.Add(1, new KeyValuePair<string, object?>("detector", detector), new KeyValuePair<string, object?>("decision", decision));

    /// <param name="outcome">succeeded, failed, dead or released.</param>
    public void JobAttempt(string outcome, TimeSpan duration)
    {
        jobAttempts.Add(1, new KeyValuePair<string, object?>("outcome", outcome));
        jobDuration.Record(duration.TotalSeconds, new KeyValuePair<string, object?>("outcome", outcome));
    }

    public void Revoked(string detector, TimeSpan sinceFirstEvent) =>
        timeToRevoke.Record(sinceFirstEvent.TotalSeconds, new KeyValuePair<string, object?>("detector", detector));

    /// <param name="source">redis, postgres or unavailable.</param>
    public void SessionChecked(string source, TimeSpan duration) =>
        sessionCheck.Record(duration.TotalSeconds, new KeyValuePair<string, object?>("source", source));

    public void SetStreamLag(long lag) => Interlocked.Exchange(ref streamLag, lag);
}
