using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using X509.Core.Builders;
using X509.Core.Contracts;
using X509.Core.Models;

namespace X509.Core.Services;

public sealed class CertificateMetadataExtractor : ICertificateMetadataExtractor
{
    public CertificateMetadata Extract(byte[] certificateBytes, string? password = null)
    {
        ArgumentNullException.ThrowIfNull(certificateBytes);

        using X509Certificate2 certificate = LoadCertificate(certificateBytes, password);

        return CertificateMetadataBuilder
            .FromCertificate(certificate)
            .WithAllMetadata()
            .Build();
    }

    private static X509Certificate2 LoadCertificate(byte[] certificateBytes, string? password)
    {
        try
        {
            return X509CertificateLoader.LoadPkcs12(certificateBytes, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (CryptographicException)
        {
            return X509CertificateLoader.LoadCertificate(certificateBytes);
        }
    }
}
