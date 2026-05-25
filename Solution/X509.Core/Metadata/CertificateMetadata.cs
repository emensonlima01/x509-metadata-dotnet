namespace X509.Core.Metadata;

public sealed record CertificateMetadata
{
    public string? Subject { get; init; }
    public DistinguishedNameInfo SubjectInfo { get; init; } = new();
    public string? Issuer { get; init; }
    public DistinguishedNameInfo IssuerInfo { get; init; } = new();
    public string? SerialNumber { get; init; }
    public string? Thumbprint { get; init; }
    public string? SignatureAlgorithmOid { get; init; }
    public string? SignatureAlgorithmFriendlyName { get; init; }
    public DateTime NotBefore { get; init; }
    public DateTime NotAfter { get; init; }
    public int Version { get; init; }
    public bool IsCurrentlyValidUtc { get; init; }
    public PublicKeyInfo PublicKey { get; init; } = new();
    public PrivateKeyInfo PrivateKey { get; init; } = new();
    public SubjectAlternativeNameInfo SubjectAlternativeName { get; init; } = new();
    public bool? IsCertificateAuthority { get; init; }
    public bool? HasPathLengthConstraint { get; init; }
    public int? PathLengthConstraint { get; init; }
    public IReadOnlyCollection<string> EnhancedKeyUsages { get; init; } = [];
    public IReadOnlyCollection<string> KeyUsages { get; init; } = [];
    public IReadOnlyCollection<CertificateExtensionInfo> Extensions { get; init; } = [];
}
