using Azure.Core;
using Azure.Identity;
using NuGet.Common;
using NuGet.Packaging.Signing;
using System;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace NuGetKeyVaultSignTool.Core.Tests;

public class AzureKeyVaultIntegrationTests
{
    private const string KeyVaultUrlEnv = "NUGETKEYVAULTSIGNTOOL_TEST_KEYVAULT_URL";
    private const string CertificateNameEnv = "NUGETKEYVAULTSIGNTOOL_TEST_CERTIFICATE_NAME";
    private const string TimestampUrlEnv = "NUGETKEYVAULTSIGNTOOL_TEST_TIMESTAMP_URL";

    [SkippableFact]
    [Trait("Category", "Integration")]
    [Trait("Category", "Sign.AzureKeyVault")]
    public async Task SignAsync_RealAzureKeyVault_SignsPackage_AndAddsSignature()
    {
        Settings settings = Settings.FromEnvironmentOrSkip();

        using CancellationTokenSource cts = new(TimeSpan.FromMinutes(3));

        // Use DefaultAzureCredential so local dev and CI can authenticate using best-practice methods
        // (Managed Identity, workload identity, env vars for service principal, Azure CLI, VS, etc.)
        TokenCredential credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = true
        });

        string dir = TestUtilities.CreateTemporaryDirectory();
        string inputPackagePath = TestUtilities.CreateMinimalNupkg(dir, "RealAzureKeyVault", "1.0.0");
        string outputPackagePath = Path.Combine(dir, "RealAzureKeyVault.1.0.0.signed.nupkg");

        var cmd = new NuGetKeyVaultSignTool.SignCommand(TestUtilities.CreateNoopLogger());
        bool result = await cmd.SignAsync(
            packagePath: inputPackagePath,
            outputPath: outputPackagePath,
            timestampUrl: settings.TimestampUrl,
            signatureHashAlgorithm: HashAlgorithmName.SHA256,
            timestampHashAlgorithm: HashAlgorithmName.SHA256,
            signatureType: SignatureType.Author,
            overwrite: true,
            v3ServiceIndexUrl: new Uri("https://api.nuget.org/v3/index.json"),
            packageOwners: [],
            keyVaultCertificateName: settings.CertificateName,
            keyVaultUrl: settings.KeyVaultUri,
            credential: credential,
            cancellationToken: cts.Token);

        Assert.True(result);
        Assert.True(File.Exists(outputPackagePath));

        // A signed package contains a signature file at the root.
        using ZipArchive zip = ZipFile.OpenRead(outputPackagePath);
        bool hasSignature = zip.Entries.Any(e => string.Equals(e.FullName, ".signature.p7s", StringComparison.OrdinalIgnoreCase));
        Assert.True(hasSignature, "Expected the signed package to contain '.signature.p7s'.");
    }

    private sealed record Settings(Uri KeyVaultUri, string CertificateName, string TimestampUrl)
    {
        public static Settings FromEnvironmentOrSkip()
        {
            string? keyVaultUrl = Environment.GetEnvironmentVariable(KeyVaultUrlEnv);
            string? certificateName = Environment.GetEnvironmentVariable(CertificateNameEnv);
            string timestampUrl = Environment.GetEnvironmentVariable(TimestampUrlEnv) ?? "http://timestamp.digicert.com"; // DevSkim: ignore DS137138 RFC 3161 does not require TLS and this endpoint may not support HTTPS.

            Skip.If(string.IsNullOrWhiteSpace(keyVaultUrl) || string.IsNullOrWhiteSpace(certificateName),
                $"Azure Key Vault integration test is not configured. Set `{KeyVaultUrlEnv}` and `{CertificateNameEnv}` to enable it.");

            Skip.If(!Uri.TryCreate(keyVaultUrl, UriKind.Absolute, out Uri? vaultUri),
                $"Could not parse `{KeyVaultUrlEnv}` as an absolute Uri: `{keyVaultUrl}`");

            return new Settings(vaultUri, certificateName, timestampUrl);
        }
    }
}