using X509.Core.Metadata;

namespace X509.Core.Extractors;

public interface ICertificateMetadataExtractor
{
    CertificateMetadata Extract(byte[] certificateBytes, string? password = null);
}
