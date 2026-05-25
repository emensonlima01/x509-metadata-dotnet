using System.Security.Cryptography.X509Certificates;
using X509.Core.Metadata;
using X509.Core.Internal.Readers;

namespace X509.Core.Internal.Composition;

internal sealed class CertificateMetadataComposer
{
    private readonly X509Certificate2 _certificate;

    private string? _subject;
    private DistinguishedNameInfo _subjectInfo = new();
    private string? _issuer;
    private DistinguishedNameInfo _issuerInfo = new();
    private string? _serialNumber;
    private string? _thumbprint;
    private string? _signatureAlgorithmOid;
    private string? _signatureAlgorithmFriendlyName;
    private DateTime _notBefore;
    private DateTime _notAfter;
    private int _version;
    private bool _isCurrentlyValidUtc;
    private PublicKeyInfo _publicKey = new();
    private PrivateKeyInfo _privateKey = new();
    private SubjectAlternativeNameInfo _subjectAlternativeName = new();
    private bool? _isCertificateAuthority;
    private bool? _hasPathLengthConstraint;
    private int? _pathLengthConstraint;
    private IReadOnlyCollection<string> _enhancedKeyUsages = [];
    private IReadOnlyCollection<string> _keyUsages = [];
    private IReadOnlyCollection<CertificateExtensionInfo> _extensions = [];

    private CertificateMetadataComposer(X509Certificate2 certificate)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
    }

    public static CertificateMetadataComposer FromCertificate(X509Certificate2 certificate)
    {
        return new CertificateMetadataComposer(certificate);
    }

    public CertificateMetadataComposer WithAll()
    {
        return WithIdentity()
            .WithSignature()
            .WithValidity()
            .WithPublicKey()
            .WithPrivateKey()
            .WithSubjectAlternativeName()
            .WithCertificateAuthority()
            .WithEnhancedKeyUsages()
            .WithKeyUsages()
            .WithExtensions();
    }

    public CertificateMetadataComposer WithIdentity()
    {
        _subject = _certificate.Subject;
        _subjectInfo = DistinguishedNameReader.Read(_certificate.SubjectName);
        _issuer = _certificate.Issuer;
        _issuerInfo = DistinguishedNameReader.Read(_certificate.IssuerName);
        _serialNumber = _certificate.SerialNumber;
        _thumbprint = _certificate.Thumbprint;
        _version = _certificate.Version;

        return this;
    }

    public CertificateMetadataComposer WithSignature()
    {
        _signatureAlgorithmOid = _certificate.SignatureAlgorithm?.Value;
        _signatureAlgorithmFriendlyName = _certificate.SignatureAlgorithm?.FriendlyName;

        return this;
    }

    public CertificateMetadataComposer WithValidity()
    {
        var nowUtc = DateTime.UtcNow;

        _notBefore = _certificate.NotBefore;
        _notAfter = _certificate.NotAfter;
        _isCurrentlyValidUtc = nowUtc >= _certificate.NotBefore.ToUniversalTime()
            && nowUtc <= _certificate.NotAfter.ToUniversalTime();

        return this;
    }

    public CertificateMetadataComposer WithPublicKey()
    {
        _publicKey = KeyMetadataReader.ReadPublicKey(_certificate);
        return this;
    }

    public CertificateMetadataComposer WithPrivateKey()
    {
        _privateKey = KeyMetadataReader.ReadPrivateKey(_certificate);
        return this;
    }

    public CertificateMetadataComposer WithSubjectAlternativeName()
    {
        _subjectAlternativeName = SubjectAlternativeNameReader.Read(_certificate);
        return this;
    }

    public CertificateMetadataComposer WithCertificateAuthority()
    {
        var certificateAuthority = ExtensionMetadataReader.ReadCertificateAuthority(_certificate);

        _isCertificateAuthority = certificateAuthority.IsCertificateAuthority;
        _hasPathLengthConstraint = certificateAuthority.HasPathLengthConstraint;
        _pathLengthConstraint = certificateAuthority.PathLengthConstraint;

        return this;
    }

    public CertificateMetadataComposer WithEnhancedKeyUsages()
    {
        _enhancedKeyUsages = ExtensionMetadataReader.ReadEnhancedKeyUsages(_certificate);
        return this;
    }

    public CertificateMetadataComposer WithKeyUsages()
    {
        _keyUsages = ExtensionMetadataReader.ReadKeyUsages(_certificate);
        return this;
    }

    public CertificateMetadataComposer WithExtensions()
    {
        _extensions = ExtensionMetadataReader.ReadExtensions(_certificate);
        return this;
    }

    public CertificateMetadata Build()
    {
        return new CertificateMetadata
        {
            Subject = _subject,
            SubjectInfo = _subjectInfo,
            Issuer = _issuer,
            IssuerInfo = _issuerInfo,
            SerialNumber = _serialNumber,
            Thumbprint = _thumbprint,
            SignatureAlgorithmOid = _signatureAlgorithmOid,
            SignatureAlgorithmFriendlyName = _signatureAlgorithmFriendlyName,
            NotBefore = _notBefore,
            NotAfter = _notAfter,
            Version = _version,
            IsCurrentlyValidUtc = _isCurrentlyValidUtc,
            PublicKey = _publicKey,
            PrivateKey = _privateKey,
            SubjectAlternativeName = _subjectAlternativeName,
            IsCertificateAuthority = _isCertificateAuthority,
            HasPathLengthConstraint = _hasPathLengthConstraint,
            PathLengthConstraint = _pathLengthConstraint,
            EnhancedKeyUsages = _enhancedKeyUsages,
            KeyUsages = _keyUsages,
            Extensions = _extensions
        };
    }
}
