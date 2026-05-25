using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using X509.Core.Models;

namespace X509.Core.Readers;

internal static class CertificateExtensionReader
{
    public static CertificateAuthorityInfo ReadCertificateAuthority(X509Certificate2 certificate)
    {
        var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();

        return new CertificateAuthorityInfo(
            basicConstraints?.CertificateAuthority,
            basicConstraints?.HasPathLengthConstraint,
            basicConstraints?.PathLengthConstraint);
    }

    public static IReadOnlyCollection<string> ReadEnhancedKeyUsages(X509Certificate2 certificate)
    {
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku is null)
        {
            return [];
        }

        return eku.EnhancedKeyUsages
            .Cast<Oid>()
            .Select(oid => $"{oid.FriendlyName ?? "Unknown"} ({oid.Value})")
            .ToArray();
    }

    public static IReadOnlyCollection<string> ReadKeyUsages(X509Certificate2 certificate)
    {
        var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsage is null)
        {
            return [];
        }

        return Enum.GetValues<X509KeyUsageFlags>()
            .Where(flag => flag != X509KeyUsageFlags.None && keyUsage.KeyUsages.HasFlag(flag))
            .Select(flag => flag.ToString())
            .ToArray();
    }

    public static IReadOnlyCollection<CertificateExtensionInfo> ReadExtensions(X509Certificate2 certificate)
    {
        return certificate.Extensions.Cast<X509Extension>()
            .Select(extension => new CertificateExtensionInfo
            {
                Oid = extension.Oid?.Value ?? string.Empty,
                FriendlyName = extension.Oid?.FriendlyName,
                Critical = extension.Critical,
                FormattedValue = extension.Format(multiLine: false),
                RawDataBase64 = Convert.ToBase64String(extension.RawData)
            })
            .ToArray();
    }
}

internal sealed record CertificateAuthorityInfo(
    bool? IsCertificateAuthority,
    bool? HasPathLengthConstraint,
    int? PathLengthConstraint);
