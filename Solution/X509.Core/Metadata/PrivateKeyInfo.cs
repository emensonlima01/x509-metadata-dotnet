namespace X509.Core.Metadata;

public sealed record PrivateKeyInfo
{
    public bool HasPrivateKey { get; init; }
    public string? KeyAlgorithm { get; init; }
    public int? KeySize { get; init; }
    public bool IsExportable { get; init; }
}
