namespace X509.Core.Metadata;

public sealed record PublicKeyInfo
{
    public string? AlgorithmOid { get; init; }
    public string? AlgorithmFriendlyName { get; init; }
    public string? KeyValueBase64 { get; init; }
    public int? KeySize { get; init; }
}
