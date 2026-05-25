namespace X509.Core.Metadata;

public sealed record DistinguishedNameInfo
{
    public string Raw { get; init; } = string.Empty;
    public IReadOnlyDictionary<string, string> Attributes { get; init; } = new Dictionary<string, string>();
}
