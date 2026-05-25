# x509-metadata-dotnet

A .NET library for extracting typed metadata from X.509 certificates.

The core library accepts certificate bytes and keeps all direct `System.Security.Cryptography.X509Certificates` usage inside `X509.Core`.

## Features

- Extract metadata from public certificates (`.cer`) and private certificate containers (`.pfx` / PKCS#12).
- Detect whether the certificate contains a private key.
- Read subject, issuer, serial number, thumbprint, signature algorithm, validity and version.
- Read public key and private key metadata.
- Read Subject Alternative Name entries such as DNS names, IP addresses, URIs, emails and UPN values.
- Read certificate authority constraints, key usages, enhanced key usages and raw extensions.
- Use either a full extractor or a selective builder.

## Project Structure

```text
Solution/
  X509.Core/
    Builders/      Public fluent builder for selective metadata extraction
    Extractors/    Public extractor API for full metadata extraction
    Metadata/      Public typed metadata models
    Internal/      X509 loading, composition and parsing implementation

  X509.Cli/        Local console app for manual testing
  samples/         Test certificates used by the CLI and validation
```

## Usage

### Extract all metadata

```csharp
using X509.Core.Extractors;

byte[] certificateBytes = File.ReadAllBytes("certificate.pfx");
string? password = "test-password";

var extractor = new CertificateMetadataExtractor();
var metadata = extractor.Extract(certificateBytes, password);
```

### Select specific metadata sections

```csharp
using X509.Core.Builders;

byte[] certificateBytes = File.ReadAllBytes("certificate.cer");

var metadata = CertificateMetadataBuilder
    .FromBytes(certificateBytes)
    .WithIdentity()
    .WithPublicKey()
    .WithSubjectAlternativeName()
    .Build();
```

### Extract everything with the builder

```csharp
using X509.Core.Builders;

byte[] certificateBytes = File.ReadAllBytes("certificate.pfx");

var metadata = CertificateMetadataBuilder
    .FromBytes(certificateBytes, "test-password")
    .WithAll()
    .Build();
```

## Returned Metadata

The main return type is `CertificateMetadata`.

It includes:

- `Subject` and `SubjectInfo`
- `Issuer` and `IssuerInfo`
- `SerialNumber`
- `Thumbprint`
- `SignatureAlgorithmOid`
- `SignatureAlgorithmFriendlyName`
- `NotBefore`
- `NotAfter`
- `IsCurrentlyValidUtc`
- `PublicKey`
- `PrivateKey`
- `SubjectAlternativeName`
- `IsCertificateAuthority`
- `KeyUsages`
- `EnhancedKeyUsages`
- `Extensions`

## Samples

The repository includes sample certificates under:

```text
Solution/samples/certificates/
```

The `.cer` files contain public certificates only.
The `.pfx` files contain private keys and use this password:

```text
test-password
```

Example sample certificates:

- `rsa-root-ca`
- `rsa-intermediate-ca`
- `rsa-server-with-san`
- `rsa-client-auth`
- `rsa-code-signing`
- `rsa-expired-server`
- `ecdsa-client-auth`
- `rsa-minimal`

## CLI

The CLI is a local manual testing app.

Run it from the solution folder:

```bash
dotnet run --project X509.Cli
```

The current CLI uses a hardcoded sample certificate path in `Program.cs`.
Change that value to test another certificate.

## Build

```bash
dotnet build Solution/Solution.slnx
```

Or from inside the `Solution` folder:

```bash
dotnet build Solution.slnx
```

## References

- [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [Microsoft Learn - X509Certificate2](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2)
- [Microsoft Learn - X509CertificateLoader](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificateloader)
- [Microsoft Learn - X509CertificateLoader.LoadPkcs12](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificateloader.loadpkcs12)
- [Microsoft Learn - X509Extension](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509extension)
- [Microsoft Learn - SubjectAlternativeNameBuilder](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.subjectalternativenamebuilder)
- [Microsoft Learn - AsnReader](https://learn.microsoft.com/en-us/dotnet/api/system.formats.asn1.asnreader)
