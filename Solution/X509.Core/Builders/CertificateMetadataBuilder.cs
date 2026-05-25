using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using X509.Core.Models;

namespace X509.Core.Builders;

public sealed class CertificateMetadataBuilder
{
    private readonly X509Certificate2 _certificate;

    public CertificateMetadataBuilder(X509Certificate2 certificate)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
    }

    public CertificateMetadata Build()
    {
        var nowUtc = DateTime.UtcNow;
        var basicConstraints = _certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();

        return new CertificateMetadata
        {
            Subject = _certificate.Subject,
            SubjectInfo = ReadDistinguishedName(_certificate.SubjectName),
            Issuer = _certificate.Issuer,
            IssuerInfo = ReadDistinguishedName(_certificate.IssuerName),
            SerialNumber = _certificate.SerialNumber,
            Thumbprint = _certificate.Thumbprint,
            SignatureAlgorithmOid = _certificate.SignatureAlgorithm?.Value,
            SignatureAlgorithmFriendlyName = _certificate.SignatureAlgorithm?.FriendlyName,
            NotBefore = _certificate.NotBefore,
            NotAfter = _certificate.NotAfter,
            Version = _certificate.Version,
            IsCurrentlyValidUtc = nowUtc >= _certificate.NotBefore.ToUniversalTime() && nowUtc <= _certificate.NotAfter.ToUniversalTime(),
            PublicKey = ReadPublicKey(),
            PrivateKey = ReadPrivateKey(),
            SubjectAlternativeName = ReadSubjectAlternativeName(),
            IsCertificateAuthority = basicConstraints?.CertificateAuthority,
            HasPathLengthConstraint = basicConstraints?.HasPathLengthConstraint,
            PathLengthConstraint = basicConstraints?.PathLengthConstraint,
            EnhancedKeyUsages = ReadEnhancedKeyUsages(),
            KeyUsages = ReadKeyUsages(),
            Extensions = ReadExtensions()
        };
    }

    private DistinguishedNameInfo ReadDistinguishedName(X500DistinguishedName distinguishedName)
    {
        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var part in distinguishedName.Decode(X500DistinguishedNameFlags.None).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var idx = part.IndexOf('=');
            if (idx <= 0 || idx >= part.Length - 1)
            {
                continue;
            }

            var key = part[..idx].Trim();
            var value = part[(idx + 1)..].Trim();
            if (!string.IsNullOrWhiteSpace(key))
            {
                attributes[key] = value;
            }
        }

        return new DistinguishedNameInfo
        {
            Raw = distinguishedName.Name ?? string.Empty,
            Attributes = attributes
        };
    }

    private PublicKeyInfo ReadPublicKey()
    {
        return new PublicKeyInfo
        {
            AlgorithmOid = _certificate.PublicKey.Oid?.Value,
            AlgorithmFriendlyName = _certificate.PublicKey.Oid?.FriendlyName,
            KeyValueBase64 = Convert.ToBase64String(_certificate.PublicKey.EncodedKeyValue.RawData),
            KeySize = ReadPublicKeySize()
        };
    }

    private PrivateKeyInfo ReadPrivateKey()
    {
        if (!_certificate.HasPrivateKey)
        {
            return new PrivateKeyInfo { HasPrivateKey = false };
        }

        using RSA? rsa = _certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return new PrivateKeyInfo { HasPrivateKey = true, KeyAlgorithm = "RSA", KeySize = rsa.KeySize, IsExportable = TryExport(rsa) };
        }

        using ECDsa? ecdsa = _certificate.GetECDsaPrivateKey();
        if (ecdsa is not null)
        {
            return new PrivateKeyInfo { HasPrivateKey = true, KeyAlgorithm = "ECDSA", KeySize = ecdsa.KeySize, IsExportable = TryExport(ecdsa) };
        }

        using DSA? dsa = _certificate.GetDSAPrivateKey();
        if (dsa is not null)
        {
            return new PrivateKeyInfo { HasPrivateKey = true, KeyAlgorithm = "DSA", KeySize = dsa.KeySize, IsExportable = TryExport(dsa) };
        }

        return new PrivateKeyInfo { HasPrivateKey = true, KeyAlgorithm = "Unknown", IsExportable = false };
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

    private SubjectAlternativeNameInfo ReadSubjectAlternativeName()
    {
        var sanExt = _certificate.Extensions.Cast<X509Extension>().FirstOrDefault(x => x.Oid?.Value == "2.5.29.17");
        if (sanExt is null)
        {
            return new SubjectAlternativeNameInfo();
        }

        var dns = new List<string>();
        var ips = new List<string>();
        var uris = new List<string>();
        var emails = new List<string>();
        var upns = new List<string>();
        var rawEntries = new List<string>();

        var reader = new AsnReader(sanExt.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();

        while (sequence.HasData)
        {
            Asn1Tag tag = sequence.PeekTag();
            if (tag.TagClass != TagClass.ContextSpecific)
            {
                sequence.ReadEncodedValue();
                continue;
            }

            switch (tag.TagValue)
            {
                case 1:
                    var email = sequence.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                    emails.Add(email);
                    rawEntries.Add($"rfc822Name={email}");
                    break;
                case 2:
                    var dnsName = sequence.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                    dns.Add(dnsName);
                    rawEntries.Add($"dNSName={dnsName}");
                    break;
                case 6:
                    var uri = sequence.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                    uris.Add(uri);
                    rawEntries.Add($"uniformResourceIdentifier={uri}");
                    break;
                case 7:
                    byte[] value = sequence.ReadOctetString(tag);
                    var ip = new IPAddress(value).ToString();
                    ips.Add(ip);
                    rawEntries.Add($"iPAddress={ip}");
                    break;
                case 0:
                    var otherNameValue = sequence.ReadEncodedValue().ToArray();
                    var userPrincipalName = TryReadUserPrincipalName(otherNameValue);
                    if (userPrincipalName is not null)
                    {
                        upns.Add(userPrincipalName);
                        rawEntries.Add($"userPrincipalName={userPrincipalName}");
                    }
                    else
                    {
                        rawEntries.Add($"otherName={Convert.ToBase64String(otherNameValue)}");
                    }

                    break;
                default:
                    var rawValue = Convert.ToBase64String(sequence.ReadEncodedValue().ToArray());
                    rawEntries.Add($"tag{tag.TagValue}={rawValue}");
                    break;
            }
        }

        return new SubjectAlternativeNameInfo
        {
            DnsNames = dns,
            IpAddresses = ips,
            Uris = uris,
            Emails = emails,
            UserPrincipalNames = upns,
            RawEntries = rawEntries
        };
    }

    private IReadOnlyCollection<string> ReadEnhancedKeyUsages()
    {
        var eku = _certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku is null)
        {
            return [];
        }

        return eku.EnhancedKeyUsages
            .Cast<Oid>()
            .Select(oid => $"{oid.FriendlyName ?? "Unknown"} ({oid.Value})")
            .ToArray();
    }

    private IReadOnlyCollection<string> ReadKeyUsages()
    {
        var keyUsage = _certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsage is null)
        {
            return [];
        }

        return Enum.GetValues<X509KeyUsageFlags>()
            .Where(flag => flag != X509KeyUsageFlags.None && keyUsage.KeyUsages.HasFlag(flag))
            .Select(flag => flag.ToString())
            .ToArray();
    }

    private IReadOnlyCollection<CertificateExtensionInfo> ReadExtensions()
    {
        return _certificate.Extensions.Cast<X509Extension>()
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
    private int? ReadPublicKeySize()
    {
        using RSA? rsa = _certificate.GetRSAPublicKey();
        if (rsa is not null) return rsa.KeySize;

        using ECDsa? ecdsa = _certificate.GetECDsaPublicKey();
        if (ecdsa is not null) return ecdsa.KeySize;

        using DSA? dsa = _certificate.GetDSAPublicKey();
        if (dsa is not null) return dsa.KeySize;

        return null;
    }

    private static string? TryReadUserPrincipalName(byte[] otherNameValue)
    {
        try
        {
            var otherNameReader = new AsnReader(otherNameValue, AsnEncodingRules.DER);
            var otherName = otherNameReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            var typeId = otherName.ReadObjectIdentifier();
            if (typeId != "1.3.6.1.4.1.311.20.2.3")
            {
                return null;
            }

            var explicitValue = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            return explicitValue.ReadCharacterString(UniversalTagNumber.UTF8String);
        }
        catch
        {
            return null;
        }
    }
}
