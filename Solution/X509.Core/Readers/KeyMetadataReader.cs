using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using X509.Core.Models;

namespace X509.Core.Readers;

internal static class KeyMetadataReader
{
    public static PublicKeyInfo ReadPublicKey(X509Certificate2 certificate)
    {
        return new PublicKeyInfo
        {
            AlgorithmOid = certificate.PublicKey.Oid?.Value,
            AlgorithmFriendlyName = certificate.PublicKey.Oid?.FriendlyName,
            KeyValueBase64 = Convert.ToBase64String(certificate.PublicKey.EncodedKeyValue.RawData),
            KeySize = ReadPublicKeySize(certificate)
        };
    }

    public static PrivateKeyInfo ReadPrivateKey(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            return new PrivateKeyInfo { HasPrivateKey = false };
        }

        using RSA? rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return new PrivateKeyInfo { HasPrivateKey = true, KeyAlgorithm = "RSA", KeySize = rsa.KeySize, IsExportable = TryExport(rsa) };
        }

        using ECDsa? ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa is not null)
        {
            return new PrivateKeyInfo { HasPrivateKey = true, KeyAlgorithm = "ECDSA", KeySize = ecdsa.KeySize, IsExportable = TryExport(ecdsa) };
        }

        using DSA? dsa = certificate.GetDSAPrivateKey();
        if (dsa is not null)
        {
            return new PrivateKeyInfo { HasPrivateKey = true, KeyAlgorithm = "DSA", KeySize = dsa.KeySize, IsExportable = TryExport(dsa) };
        }

        return new PrivateKeyInfo { HasPrivateKey = true, KeyAlgorithm = "Unknown", IsExportable = false };
    }

    private static int? ReadPublicKeySize(X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is not null) return rsa.KeySize;

        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is not null) return ecdsa.KeySize;

        using DSA? dsa = certificate.GetDSAPublicKey();
        if (dsa is not null) return dsa.KeySize;

        return null;
    }

    private static bool TryExport(AsymmetricAlgorithm algorithm)
    {
        try
        {
            _ = algorithm switch
            {
                RSA rsa => rsa.ExportPkcs8PrivateKey(),
                ECDsa ecdsa => ecdsa.ExportPkcs8PrivateKey(),
                DSA dsa => dsa.ExportPkcs8PrivateKey(),
                _ => throw new NotSupportedException()
            };
            return true;
        }
        catch
        {
            return false;
        }
    }
}
