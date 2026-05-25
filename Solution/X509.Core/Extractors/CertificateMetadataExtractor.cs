using X509.Core.Builders;
using X509.Core.Metadata;

namespace X509.Core.Extractors;

public sealed class CertificateMetadataExtractor : ICertificateMetadataExtractor
{
    public CertificateMetadata Extract(byte[] certificateBytes, string? password = null)
    {
        return CertificateMetadataBuilder
            .FromBytes(certificateBytes, password)
            .WithAll()
            .Build();
    }
}
