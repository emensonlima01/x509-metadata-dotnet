using System.Text.Json;
using System.Text;
using System.Text.Encodings.Web;
using X509.Core.Builders;

const string certificatePath = @"D:\Repos\x509-metadata-dotnet\Solution\samples\certificates\rsa-server-with-san.pfx";
const string? password = "test-password";

Console.OutputEncoding = Encoding.UTF8;

if (!File.Exists(certificatePath))
{
    Console.WriteLine($"Certificate file not found: {certificatePath}");
    return;
}

var certificateBytes = File.ReadAllBytes(certificatePath);
var metadata = CertificateMetadataBuilder
    .FromBytes(certificateBytes, password)
    .WithAll()
    .Build();

var json = JsonSerializer.Serialize(metadata, new JsonSerializerOptions
{
    WriteIndented = true,
    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
});

Console.WriteLine(json);
