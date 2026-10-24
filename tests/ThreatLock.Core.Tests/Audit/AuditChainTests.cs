using System.Text;
using System.Text.Json.Nodes;
using ThreatLock.Core.Audit;

namespace ThreatLock.Core.Tests.Audit;

public class AuditChainTests
{
    private static readonly Guid Org = Guid.Parse("0199f2a0-0000-7000-8000-00000000aaaa");
    private static readonly DateTimeOffset T0 = new(2026, 10, 24, 9, 0, 0, TimeSpan.Zero);

    private static AuditFields Fields(long seq, byte[] prev, string action = "auth.login_succeeded", JsonObject? details = null) =>
        new(Org, seq, T0.AddSeconds(seq), ActorTypes.User, Guid.Empty, action, "user", "u1", null, details ?? new JsonObject(), null, prev);

    /// <summary>Builds a valid chain of <paramref name="n"/> entries.</summary>
    private static List<AuditEntry> Chain(int n)
    {
        var entries = new List<AuditEntry>();
        var prev = AuditChain.Genesis;
        for (var seq = 1; seq <= n; seq++)
        {
            var fields = Fields(seq, prev, details: new JsonObject { ["n"] = seq });
            var hash = AuditChain.Hash(fields);
            entries.Add(new AuditEntry(fields, hash));
            prev = hash;
        }

        return entries;
    }

    [Fact]
    public void Canonical_form_is_length_prefixed_in_a_fixed_order()
    {
        var text = Encoding.UTF8.GetString(AuditChain.Canonical(Fields(1, AuditChain.Genesis)));

        Assert.StartsWith($"org_id=36:{Org}\nseq=1:1\noccurred_at=27:2026-10-24T09:00:01.000000Z\nactor_type=4:user\n", text);
        Assert.Contains("anomaly_id=~\n", text);           // null is not the same as ""
        Assert.EndsWith($"prev_hash=64:{new string('0', 64)}\n", text);
    }

    [Fact]
    public void Length_prefixes_stop_fields_bleeding_into_each_other()
    {
        var a = Fields(1, AuditChain.Genesis) with { Action = "ab", TargetType = "c" };
        var b = Fields(1, AuditChain.Genesis) with { Action = "a", TargetType = "bc" };

        Assert.NotEqual(AuditChain.Hash(a), AuditChain.Hash(b));
    }

    [Fact]
    public void Null_and_empty_strings_hash_differently()
    {
        var a = Fields(1, AuditChain.Genesis) with { TargetId = null };
        var b = Fields(1, AuditChain.Genesis) with { TargetId = "" };

        Assert.NotEqual(AuditChain.Hash(a), AuditChain.Hash(b));
    }

    [Fact]
    public void Details_hash_the_same_whatever_the_key_order()
    {
        // jsonb hands keys back in its own order, so the hash must not depend on it.
        var a = new JsonObject { ["b"] = 1, ["a"] = new JsonObject { ["y"] = "é", ["x"] = new JsonArray(2, 1) } };
        var b = new JsonObject { ["a"] = new JsonObject { ["x"] = new JsonArray(2, 1), ["y"] = "é" }, ["b"] = 1 };

        Assert.Equal(AuditChain.CanonicalJson(a), AuditChain.CanonicalJson(b));
        Assert.Equal("""{"a":{"x":[2,1],"y":"\u00E9"},"b":1}""", AuditChain.CanonicalJson(a));
    }

    [Fact]
    public void Timestamps_are_hashed_at_the_databases_microsecond_precision()
    {
        var precise = Fields(1, AuditChain.Genesis) with { OccurredAt = T0.AddTicks(12_345_678) };   // 1.2345678 s
        var stored = precise with { OccurredAt = T0.AddTicks(12_345_670) };                        // what PostgreSQL keeps

        Assert.Equal(AuditChain.Hash(precise), AuditChain.Hash(stored));
    }

    [Fact]
    public void An_intact_chain_verifies_and_reports_its_head()
    {
        var chain = Chain(5);

        var result = AuditChain.Verify(chain);

        Assert.Equal((true, 5L, Convert.ToHexStringLower(chain[^1].EntryHash)), (result.Ok, result.Entries, result.Head));
    }

    [Fact]
    public void An_empty_chain_is_valid() => Assert.Equal(new VerifyResult(true, 0, null), AuditChain.Verify([]));

    [Fact]
    public void Editing_an_entry_is_caught_at_that_entry()
    {
        var chain = Chain(5);
        chain[2] = chain[2] with { Fields = chain[2].Fields with { Details = new JsonObject { ["n"] = 999 } } };

        var result = AuditChain.Verify(chain);

        Assert.Equal((false, 3L, VerifyReasons.HashMismatch), (result.Ok, result.FirstBrokenSeq, result.Reason));
    }

    [Fact]
    public void Editing_and_rehashing_an_entry_breaks_the_next_link()
    {
        var chain = Chain(5);
        var edited = chain[2].Fields with { Action = "nothing.to.see" };
        chain[2] = new AuditEntry(edited, AuditChain.Hash(edited));

        var result = AuditChain.Verify(chain);

        Assert.Equal((4L, VerifyReasons.ChainBreak), (result.FirstBrokenSeq, result.Reason));
    }

    [Fact]
    public void Deleting_an_entry_is_a_seq_gap()
    {
        var chain = Chain(5);
        chain.RemoveAt(1);

        var result = AuditChain.Verify(chain);

        Assert.Equal((2L, VerifyReasons.SeqGap), (result.FirstBrokenSeq, result.Reason));
    }

    [Fact]
    public void A_full_rewrite_from_an_edit_onwards_fools_the_chain_but_not_an_anchor()
    {
        var chain = Chain(5);
        var anchor = new AuditAnchor(4, Convert.ToHexStringLower(chain[3].EntryHash));   // saved elsewhere earlier

        // The attacker edits entry 3 and recomputes every hash after it.
        var prev = chain[1].EntryHash;
        for (var i = 2; i < chain.Count; i++)
        {
            var fields = chain[i].Fields with { PrevHash = prev, Action = i == 2 ? "nothing.to.see" : chain[i].Fields.Action };
            chain[i] = new AuditEntry(fields, AuditChain.Hash(fields));
            prev = chain[i].EntryHash;
        }

        Assert.True(AuditChain.Verify(chain).Ok);   // the honest limitation of a chain on its own (ADR-0005)
        var anchored = AuditChain.Verify(chain, anchor);
        Assert.Equal((false, 4L, VerifyReasons.AnchorMismatch), (anchored.Ok, anchored.FirstBrokenSeq, anchored.Reason));
    }

    [Fact]
    public void An_anchor_also_catches_entries_cut_off_the_end()
    {
        var chain = Chain(5);
        var anchor = new AuditAnchor(5, Convert.ToHexStringLower(chain[4].EntryHash));
        chain.RemoveAt(4);

        Assert.True(AuditChain.Verify(chain).Ok);
        Assert.Equal(VerifyReasons.AnchorMismatch, AuditChain.Verify(chain, anchor).Reason);
    }
}
