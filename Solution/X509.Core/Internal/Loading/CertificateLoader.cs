using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace X509.Core.Internal.Loading;

internal static class CertificateLoader
{
    public static X509Certificate2 Load(byte[] certificateBytes, string? password)
    {
        try
        {
            return X509CertificateLoader.LoadPkcs12(
                certificateBytes,
                password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (CryptographicException)
        {
            return X509CertificateLoader.LoadCertificate(certificateBytes);
        }
    }
}
