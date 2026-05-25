namespace X509.Core.Models;

public sealed record DistinguishedNameInfo
{
    public string Raw { get; init; } = string.Empty;
    public IReadOnlyDictionary<string, string> Attributes { get; init; } = new Dictionary<string, string>();
}

public sealed record PublicKeyInfo
{
    public string? AlgorithmOid { get; init; }
    public string? AlgorithmFriendlyName { get; init; }
    public string? KeyValueBase64 { get; init; }
    public int? KeySize { get; init; }
}

public sealed record PrivateKeyInfo
{
    public bool HasPrivateKey { get; init; }
    public string? KeyAlgorithm { get; init; }
    public int? KeySize { get; init; }
    public bool IsExportable { get; init; }
}

public sealed record SubjectAlternativeNameInfo
{
    public IReadOnlyCollection<string> DnsNames { get; init; } = [];
    public IReadOnlyCollection<string> IpAddresses { get; init; } = [];
    public IReadOnlyCollection<string> Uris { get; init; } = [];
    public IReadOnlyCollection<string> Emails { get; init; } = [];
    public IReadOnlyCollection<string> UserPrincipalNames { get; init; } = [];
    public IReadOnlyCollection<string> RawEntries { get; init; } = [];
}

public sealed record CertificateExtensionInfo
{
    public string Oid { get; init; } = string.Empty;
    public string? FriendlyName { get; init; }
    public bool Critical { get; init; }
    public string FormattedValue { get; init; } = string.Empty;
    public string RawDataBase64 { get; init; } = string.Empty;
}

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
