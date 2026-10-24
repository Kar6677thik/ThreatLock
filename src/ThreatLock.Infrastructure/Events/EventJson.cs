using System.Text.Json;
using ThreatLock.Core.Events;

namespace ThreatLock.Infrastructure.Events;

/// <summary>One JSON format for events everywhere: stream payloads, database columns, replay datasets.</summary>
public static class EventJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    public static string Serialize(ActivityEvent evt) => JsonSerializer.Serialize(evt, Options);

    /// <summary>Throws <see cref="JsonException"/> on malformed input; the consumer dead-letters those.</summary>
    public static ActivityEvent Deserialize(string json) =>
        JsonSerializer.Deserialize<ActivityEvent>(json, Options) ?? throw new JsonException("Event payload was null.");
}
