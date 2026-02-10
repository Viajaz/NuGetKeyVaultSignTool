using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NuGetKeyVaultSignTool.Core.Tests;

internal static class TestUtilities
{
    public static bool IsTrueEnvironmentVariable(string envVarName)
    {
        string? value = Environment.GetEnvironmentVariable(envVarName);
        if(string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.Equals("1", StringComparison.OrdinalIgnoreCase)
            || value.Equals("true", StringComparison.OrdinalIgnoreCase)
            || value.Equals("yes", StringComparison.OrdinalIgnoreCase)
            || value.Equals("on", StringComparison.OrdinalIgnoreCase);
    }

    public static string CreateTemporaryDirectory()
    {
        string dir = Path.Combine(TestRunEnvironment.WorkRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static string CreateMinimalNupkg(string directory, string packageId, string version)
    {
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, $"{packageId}.{version}.nupkg");

        using FileStream fs = new(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        using ZipArchive zip = new(fs, ZipArchiveMode.Create);

        // Minimal nuspec required for a NuGet package.
        string nuspec = $"""
<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{packageId}</id>
    <version>{version}</version>
    <authors>UnitTest</authors>
    <description>Test package</description>
  </metadata>
</package>
""";

        ZipArchiveEntry nuspecEntry = zip.CreateEntry($"{packageId}.nuspec");
        {
            using StreamWriter writer = new(nuspecEntry.Open());
            writer.Write(nuspec);
        }

        // Add a placeholder file to look like a real package layout.
        zip.CreateEntry("lib/net10.0/_._");

        return path;
    }

    public static (X509Certificate2 PublicCertificate, RSA Rsa) CreatePublicCertificateAndRsa()
    {
        RSA rsa = RSA.Create(2048);
        CertificateRequest req = new("CN=NuGetKeyVaultSignTool.Tests", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certWithKey = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // `SignCommand` only needs the public cert (RSA is provided separately).
        byte[] publicBytes = certWithKey.Export(X509ContentType.Cert);
        X509Certificate2 publicCert = X509CertificateLoader.LoadCertificate(publicBytes);
        return (publicCert, rsa);
    }

    public static ILogger CreateNoopLogger() => new NoopLogger();

    private sealed class NoopLogger : ILogger
    {
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NoopScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            // no-op
        }

        private sealed class NoopScope : IDisposable
        {
            public static readonly NoopScope Instance = new();
            public void Dispose() { }
        }
    }
}