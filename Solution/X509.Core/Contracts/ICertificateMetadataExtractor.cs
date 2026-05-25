using X509.Core.Models;

namespace X509.Core.Contracts;

public interface ICertificateMetadataExtractor
{
    CertificateMetadata Extract(byte[] certificateBytes, string? password = null);
}
