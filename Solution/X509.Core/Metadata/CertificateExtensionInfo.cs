namespace X509.Core.Metadata;

public sealed record CertificateExtensionInfo
{
    public string Oid { get; init; } = string.Empty;
    public string? FriendlyName { get; init; }
    public bool Critical { get; init; }
    public string FormattedValue { get; init; } = string.Empty;
    public string RawDataBase64 { get; init; } = string.Empty;
}
