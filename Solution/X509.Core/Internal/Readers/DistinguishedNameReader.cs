using System.Security.Cryptography.X509Certificates;
using X509.Core.Metadata;

namespace X509.Core.Internal.Readers;

internal static class DistinguishedNameReader
{
    public static DistinguishedNameInfo Read(X500DistinguishedName distinguishedName)
    {
        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var part in distinguishedName.Decode(X500DistinguishedNameFlags.None).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var idx = part.IndexOf('=');
            if (idx <= 0 || idx >= part.Length - 1)
            {
                continue;
            }

            var key = part[..idx].Trim();
            var value = part[(idx + 1)..].Trim();
            if (!string.IsNullOrWhiteSpace(key))
            {
                attributes[key] = value;
            }
        }

        return new DistinguishedNameInfo
        {
            Raw = distinguishedName.Name ?? string.Empty,
            Attributes = attributes
        };
    }
}
