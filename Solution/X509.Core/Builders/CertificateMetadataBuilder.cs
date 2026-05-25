using X509.Core.Internal.Composition;
using X509.Core.Internal.Loading;
using X509.Core.Metadata;

namespace X509.Core.Builders;

public sealed class CertificateMetadataBuilder
{
    private readonly byte[] _certificateBytes;
    private readonly string? _password;

    private bool _includeIdentity;
    private bool _includeSignature;
    private bool _includeValidity;
    private bool _includePublicKey;
    private bool _includePrivateKey;
    private bool _includeSubjectAlternativeName;
    private bool _includeCertificateAuthority;
    private bool _includeEnhancedKeyUsages;
    private bool _includeKeyUsages;
    private bool _includeExtensions;

    private CertificateMetadataBuilder(byte[] certificateBytes, string? password)
    {
        ArgumentNullException.ThrowIfNull(certificateBytes);

        _certificateBytes = certificateBytes;
        _password = password;
    }

    public static CertificateMetadataBuilder FromBytes(byte[] certificateBytes, string? password = null)
    {
        return new CertificateMetadataBuilder(certificateBytes, password);
    }

    public CertificateMetadataBuilder WithAll()
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

    public CertificateMetadataBuilder WithIdentity()
    {
        _includeIdentity = true;
        return this;
    }

    public CertificateMetadataBuilder WithSignature()
    {
        _includeSignature = true;
        return this;
    }

    public CertificateMetadataBuilder WithValidity()
    {
        _includeValidity = true;
        return this;
    }

    public CertificateMetadataBuilder WithPublicKey()
    {
        _includePublicKey = true;
        return this;
    }

    public CertificateMetadataBuilder WithPrivateKey()
    {
        _includePrivateKey = true;
        return this;
    }

    public CertificateMetadataBuilder WithSubjectAlternativeName()
    {
        _includeSubjectAlternativeName = true;
        return this;
    }

    public CertificateMetadataBuilder WithCertificateAuthority()
    {
        _includeCertificateAuthority = true;
        return this;
    }

    public CertificateMetadataBuilder WithEnhancedKeyUsages()
    {
        _includeEnhancedKeyUsages = true;
        return this;
    }

    public CertificateMetadataBuilder WithKeyUsages()
    {
        _includeKeyUsages = true;
        return this;
    }

    public CertificateMetadataBuilder WithExtensions()
    {
        _includeExtensions = true;
        return this;
    }

    public CertificateMetadata Build()
    {
        if (!HasSelectedMetadata())
        {
            throw new InvalidOperationException("Select at least one metadata section before calling Build, or use WithAll().");
        }

        using var certificate = CertificateLoader.Load(_certificateBytes, _password);
        var metadata = CertificateMetadataComposer.FromCertificate(certificate);

        if (_includeIdentity) metadata.WithIdentity();
        if (_includeSignature) metadata.WithSignature();
        if (_includeValidity) metadata.WithValidity();
        if (_includePublicKey) metadata.WithPublicKey();
        if (_includePrivateKey) metadata.WithPrivateKey();
        if (_includeSubjectAlternativeName) metadata.WithSubjectAlternativeName();
        if (_includeCertificateAuthority) metadata.WithCertificateAuthority();
        if (_includeEnhancedKeyUsages) metadata.WithEnhancedKeyUsages();
        if (_includeKeyUsages) metadata.WithKeyUsages();
        if (_includeExtensions) metadata.WithExtensions();

        return metadata.Build();
    }

    private bool HasSelectedMetadata()
    {
        return _includeIdentity
            || _includeSignature
            || _includeValidity
            || _includePublicKey
            || _includePrivateKey
            || _includeSubjectAlternativeName
            || _includeCertificateAuthority
            || _includeEnhancedKeyUsages
            || _includeKeyUsages
            || _includeExtensions;
    }
}
