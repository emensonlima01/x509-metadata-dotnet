using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using X509.Core.Metadata;

namespace X509.Core.Internal.Readers;

internal static class SubjectAlternativeNameReader
{
    public static SubjectAlternativeNameInfo Read(X509Certificate2 certificate)
    {
        var sanExt = certificate.Extensions.Cast<X509Extension>().FirstOrDefault(x => x.Oid?.Value == "2.5.29.17");
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
