using ThreatLock.Core.Identity;

namespace ThreatLock.Core.Tests.Identity;

public class SlugTests
{
    [Theory]
    [InlineData("Acme Corp", "acme-corp")]
    [InlineData("  Acme   Corp!!  ", "acme-corp")]
    [InlineData("ACME_2026", "acme-2026")]
    [InlineData("Café Zoë", "caf-zo")]          // non-ASCII letters are dropped, not transliterated
    [InlineData("---", "")]
    [InlineData("", "")]
    public void From_normalises_names(string input, string expected) =>
        Assert.Equal(expected, Slug.From(input));

    [Fact]
    public void From_never_exceeds_max_length_or_ends_with_a_hyphen()
    {
        var slug = Slug.From(new string('a', 49) + " b" + new string('c', 30));

        Assert.True(slug.Length <= Slug.MaxLength);
        Assert.False(slug.EndsWith('-'));
    }

    [Theory]
    [InlineData("acme-corp", true)]
    [InlineData("Acme-Corp", false)]
    [InlineData("acme--corp", false)]
    [InlineData("-acme", false)]
    [InlineData("", false)]
    public void IsValid_accepts_only_normalised_slugs(string slug, bool expected) =>
        Assert.Equal(expected, Slug.IsValid(slug));
}
