using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ThreatLock.Core.Audit;

/// <summary>Who did it (SPEC §11.2).</summary>
public static class ActorTypes
{
    /// <summary>A user acting on their own account (login, logout, export).</summary>
    public const string User = "user";

    /// <summary>A user acting on someone else, or on the org (create user, unlock, policy edit).</summary>
    public const string Admin = "admin";

    /// <summary>ThreatLock itself: the Worker deciding and responding.</summary>
    public const string System = "system";
}

/// <summary>The audited actions (SPEC §11.1). Dotted names group them in the UI.</summary>
public static class AuditActions
{
    public const string OrgCreated = "org.created";
    public const string LoginSucceeded = "auth.login_succeeded";
    public const string LockedOut = "auth.locked_out";
    public const string Logout = "auth.logout";
    public const string SessionRevoked = "session.revoked";
    public const string SessionsRevokedByAdmin = "session.revoked_all";
    public const string UserCreated = "user.created";
    public const string RolesChanged = "user.roles_changed";
    public const string UserUnlocked = "user.unlocked";
    public const string PolicyUpdated = "policy.updated";
    public const string AnomalyDecided = "security.anomaly_decided";
    public const string ResponseExecuted = "security.response_executed";
    public const string NotesExported = "notes.exported";
}

/// <summary>
/// The fields of one audit entry that are hashed: everything except <c>entry_hash</c> itself.
/// <see cref="Details"/> must hold only strings, integers, booleans, arrays and objects: it is
/// stored as jsonb, and jsonb may rewrite other number formats (<c>1e2</c> becomes <c>100</c>),
/// which would change the hash.
/// </summary>
public sealed record AuditFields(
    Guid OrgId,
    long Seq,
    DateTimeOffset OccurredAt,
    string ActorType,
    Guid? ActorId,
    string Action,
    string? TargetType,
    string? TargetId,
    Guid? AnomalyId,
    JsonObject Details,
    string? IdempotencyKey,
    byte[] PrevHash);

/// <summary>A stored entry: its fields plus the hash computed over them.</summary>
public sealed record AuditEntry(AuditFields Fields, byte[] EntryHash);

/// <summary>Outcome of walking a chain. On failure, <see cref="FirstBrokenSeq"/> names the first entry that doesn't check out.</summary>
public sealed record VerifyResult(bool Ok, long Entries, string? Head, long? FirstBrokenSeq = null, string? Reason = null);

public static class VerifyReasons
{
    /// <summary>The entry's stored hash isn't the hash of its contents: the entry was edited.</summary>
    public const string HashMismatch = "hash_mismatch";

    /// <summary>The entry is self-consistent but doesn't point at the previous entry's hash: something before it was edited and re-hashed, or removed.</summary>
    public const string ChainBreak = "chain_break";

    /// <summary>A sequence number is missing (or repeated): an entry was deleted.</summary>
    public const string SeqGap = "seq_gap";

    /// <summary>The entry at an anchor's seq no longer has the anchored hash: the chain was rewritten from there on, or cut short.</summary>
    public const string AnchorMismatch = "anchor_mismatch";
}

/// <summary>A head hash saved somewhere outside the database at some point in time (SPEC §11.3).</summary>
public sealed record AuditAnchor(long Seq, string Hash);

/// <summary>
/// The hash chain (SPEC §11.2, ADR-0005). Each entry's hash covers the previous entry's hash and
/// its own canonical bytes, so changing any entry breaks every link after it.
/// <para>
/// <b>Never change <see cref="Canonical"/> for existing entries.</b> If the format ever has to
/// change, add a <c>hash_version</c> column and keep the old function for old rows.
/// </para>
/// </summary>
public static class AuditChain
{
    public const int HashLength = 32;

    /// <summary>The <c>prev_hash</c> of seq 1.</summary>
    public static byte[] Genesis => new byte[HashLength];

    private static readonly JsonSerializerOptions CompactJson = new() { WriteIndented = false };

    /// <summary>
    /// PostgreSQL stores microseconds; .NET has 100 ns ticks. Hash what the database will give
    /// back, or every verify would disagree with the append.
    /// </summary>
    public static DateTimeOffset ToStoredPrecision(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(utc.Ticks - utc.Ticks % 10, TimeSpan.Zero);
    }

    /// <summary>
    /// Fields in a fixed order, each written as <c>name=len:value\n</c> (len in UTF-8 bytes), null
    /// as <c>name=~\n</c>. The length prefix makes the encoding unambiguous: without it,
    /// <c>action="ab", target="c"</c> and <c>action="a", target="bc"</c> could produce the same
    /// bytes, and so the same hash.
    /// </summary>
    public static byte[] Canonical(AuditFields f)
    {
        var text = new StringBuilder();
        Field(text, "org_id", f.OrgId.ToString("D"));
        Field(text, "seq", f.Seq.ToString(CultureInfo.InvariantCulture));
        Field(text, "occurred_at", ToStoredPrecision(f.OccurredAt).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture));
        Field(text, "actor_type", f.ActorType);
        Field(text, "actor_id", f.ActorId?.ToString("D"));
        Field(text, "action", f.Action);
        Field(text, "target_type", f.TargetType);
        Field(text, "target_id", f.TargetId);
        Field(text, "anomaly_id", f.AnomalyId?.ToString("D"));
        Field(text, "details", CanonicalJson(f.Details));
        Field(text, "idempotency_key", f.IdempotencyKey);
        Field(text, "prev_hash", Convert.ToHexStringLower(f.PrevHash));
        return Encoding.UTF8.GetBytes(text.ToString());
    }

    private static void Field(StringBuilder text, string name, string? value)
    {
        text.Append(name).Append('=');
        if (value is null) text.Append('~');
        else text.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)).Append(':').Append(value);
        text.Append('\n');
    }

    /// <summary>JSON with object keys sorted (ordinal) at every level and no whitespace: one text per meaning.</summary>
    public static string CanonicalJson(JsonNode? node) => Sorted(node)?.ToJsonString(CompactJson) ?? "null";

    private static JsonNode? Sorted(JsonNode? node) => node switch
    {
        JsonObject obj => new JsonObject(obj.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => KeyValuePair.Create(p.Key, Sorted(p.Value)))),
        JsonArray array => new JsonArray([.. array.Select(Sorted)]),
        null => null,
        _ => JsonNode.Parse(node.ToJsonString()),   // a detached copy of the value
    };

    /// <summary><c>SHA-256(prev_hash || canonical(entry))</c>.</summary>
    public static byte[] Hash(AuditFields fields)
    {
        var canonical = Canonical(fields);
        var input = new byte[fields.PrevHash.Length + canonical.Length];
        fields.PrevHash.CopyTo(input, 0);
        canonical.CopyTo(input, fields.PrevHash.Length);
        return SHA256.HashData(input);
    }

    /// <summary>
    /// Walks entries in seq order and stops at the first one that doesn't check out. With
    /// <paramref name="anchor"/>, also checks that the entry at the anchor's seq still has the
    /// anchored hash, which catches what a chain alone can't: a rewrite of everything from some
    /// point on, or entries cut off the end.
    /// </summary>
    public static VerifyResult Verify(IEnumerable<AuditEntry> entries, AuditAnchor? anchor = null)
    {
        var verifier = new AuditChainVerifier(anchor);
        foreach (var entry in entries)
        {
            if (verifier.Add(entry) is { } failure) return failure;
        }

        return verifier.Complete();
    }
}

/// <summary>
/// <see cref="AuditChain.Verify"/> one entry at a time, so a long chain can be checked while it
/// streams from the database instead of being loaded into memory.
/// </summary>
public sealed class AuditChainVerifier(AuditAnchor? anchor = null)
{
    private long count;
    private long expectedSeq = 1;
    private byte[] prev = AuditChain.Genesis;
    private bool anchorSeen;

    /// <summary>Checks the next entry. Returns the failure, or null if it's fine so far.</summary>
    public VerifyResult? Add(AuditEntry entry)
    {
        var f = entry.Fields;
        if (f.Seq != expectedSeq) return Fail(expectedSeq, VerifyReasons.SeqGap);
        if (!CryptographicOperations.FixedTimeEquals(AuditChain.Hash(f), entry.EntryHash)) return Fail(f.Seq, VerifyReasons.HashMismatch);
        if (!CryptographicOperations.FixedTimeEquals(f.PrevHash, prev)) return Fail(f.Seq, VerifyReasons.ChainBreak);

        if (anchor is not null && f.Seq == anchor.Seq)
        {
            anchorSeen = true;
            if (!string.Equals(Convert.ToHexStringLower(entry.EntryHash), anchor.Hash, StringComparison.OrdinalIgnoreCase))
            {
                return Fail(f.Seq, VerifyReasons.AnchorMismatch);
            }
        }

        prev = entry.EntryHash;
        count++;
        expectedSeq++;
        return null;
    }

    /// <summary>Call after the last entry.</summary>
    public VerifyResult Complete()
    {
        // The anchored entry no longer exists: the chain was cut short.
        if (anchor is not null && !anchorSeen) return Fail(anchor.Seq, VerifyReasons.AnchorMismatch);
        return new(true, count, count == 0 ? null : Convert.ToHexStringLower(prev));
    }

    private VerifyResult Fail(long seq, string reason) => new(false, count, null, seq, reason);
}
