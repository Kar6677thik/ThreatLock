using System.Text;

namespace ThreatLock.Core.Identity;

/// <summary>
/// Turns an organisation name into a URL-safe identifier: "Acme Corp!" → "acme-corp".
/// ASCII letters and digits only; everything else collapses into single hyphens.
/// </summary>
public static class Slug
{
    public const int MaxLength = 50;

    public static string From(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var builder = new StringBuilder(text.Length);
        var pendingHyphen = false;
        foreach (var c in text.Trim().ToLowerInvariant())
        {
            if (c is (>= 'a' and <= 'z') or (>= '0' and <= '9'))
            {
                if (pendingHyphen && builder.Length > 0) builder.Append('-');
                builder.Append(c);
                pendingHyphen = false;
            }
            else
            {
                pendingHyphen = true;
            }

            if (builder.Length >= MaxLength) break;
        }

        // Appending "-x" can overshoot by one character, so cut to length *then* trim a
        // trailing hyphen the cut may have exposed.
        var slug = builder.ToString();
        return (slug.Length > MaxLength ? slug[..MaxLength] : slug).TrimEnd('-');
    }

    public static bool IsValid(string slug) =>
        slug.Length is > 0 and <= MaxLength && From(slug) == slug;
}
