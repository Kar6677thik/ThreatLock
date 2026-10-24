namespace ThreatLock.Infrastructure.Events;

/// <summary>Bound from the <c>Events</c> configuration section (SPEC §7, ADR-0003).</summary>
public sealed class EventStreamOptions
{
    public const string SectionName = "Events";

    /// <summary>Redis stream the API appends to and the Worker reads from.</summary>
    public string StreamName { get; set; } = "tl:events";

    /// <summary>Where poison messages go after <see cref="MaxDeliveries"/> failed attempts.</summary>
    public string DeadLetterStreamName => $"{StreamName}:dead";

    /// <summary>Consumer group: each message goes to one consumer in the group.</summary>
    public string ConsumerGroup { get; set; } = "detectors";

    /// <summary>This process's name within the group. Defaults to the machine (pod) name.</summary>
    public string? ConsumerName { get; set; }

    /// <summary>Approximate cap on stream length (<c>XADD ... MAXLEN ~</c>), so Redis memory stays bounded.</summary>
    public int MaxLength { get; set; } = 100_000;

    /// <summary>A message delivered this many times without being acknowledged is dead-lettered.</summary>
    public int MaxDeliveries { get; set; } = 5;

    /// <summary>A pending message idle this long is assumed abandoned by a crashed consumer and reclaimed.</summary>
    public TimeSpan ClaimIdle { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>How often to look for abandoned messages.</summary>
    public TimeSpan ClaimInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How often the sweeper looks for events that never reached the stream.</summary>
    public TimeSpan SweepInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Only sweep events at least this old, so we don't race the API's own publish.</summary>
    public TimeSpan SweepMinAge { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Activity events are personal data (IPs); delete them after this long (SPEC §7.4).</summary>
    public int RetentionDays { get; set; } = 30;

    public string ResolvedConsumerName => string.IsNullOrWhiteSpace(ConsumerName) ? Environment.MachineName : ConsumerName;
}
