namespace X509.Core.Metadata;

public sealed record SubjectAlternativeNameInfo
{
    public IReadOnlyCollection<string> DnsNames { get; init; } = [];
    public IReadOnlyCollection<string> IpAddresses { get; init; } = [];
    public IReadOnlyCollection<string> Uris { get; init; } = [];
    public IReadOnlyCollection<string> Emails { get; init; } = [];
    public IReadOnlyCollection<string> UserPrincipalNames { get; init; } = [];
    public IReadOnlyCollection<string> RawEntries { get; init; } = [];
}
