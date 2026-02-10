using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using Xunit;
using Xunit.Sdk;

namespace NuGetKeyVaultSignTool.Core.Tests;

public class VerifyCommandTests
{
    private const string SkipNuGetOrgEnvVar = "NUGETKEYVAULTSIGNTOOL_TEST_SKIP_NUGETORG";

    [Fact]
    public async Task VerifyAsync_UnsignedPackage_ReturnsFalse()
    {
        string dir = TestUtilities.CreateTemporaryDirectory();
        string unsigned = TestUtilities.CreateMinimalNupkg(dir, "AUnsigned", "1.0.0");

        var cmd = new NuGetKeyVaultSignTool.VerifyCommand(TestUtilities.CreateNoopLogger());
        StringBuilder buffer = new();
        bool result = await cmd.VerifyAsync(unsigned, buffer);

        Assert.False(result);
    }

    [Fact]
    public async Task VerifyAsync_MultiplePackages_WhenFirstInvalidSecondValid_ReturnsFalse()
    {
        string dir = TestUtilities.CreateTemporaryDirectory();

        // Ensure the unsigned file sorts before the signed one, so we would catch any regression
        // where a later "true" might overwrite an earlier failure.
        string unsigned = TestUtilities.CreateMinimalNupkg(dir, "AUnsigned", "1.0.0");
        // NOTE: this package is NOT actually signed. It's just a second package file on disk so we can
        // exercise multi-package aggregation behavior. The fake verifier below is what marks it "valid".
        string laterPackage = TestUtilities.CreateMinimalNupkg(dir, "ZNotActuallySigned", "1.0.0");

        // We don't want these unit tests to rely on a real signed package (or machine trust policy),
        // just on VerifyCommand's aggregation behavior across multiple packages.
        var verifier = new FakeVerifyPackageSignatures(path =>
        {
            if(string.Equals(path, unsigned, System.StringComparison.OrdinalIgnoreCase))
            {
                return new NuGetKeyVaultSignTool.VerificationResult(
                    IsValid: false,
                    Issues:
                    [
                        new NuGetKeyVaultSignTool.VerificationIssue(LogLevel.Error, "Package signature is invalid."),
                        new NuGetKeyVaultSignTool.VerificationIssue(LogLevel.Warning, "Package signer is not trusted.")
                    ]);
            }

            return new NuGetKeyVaultSignTool.VerificationResult(IsValid: true, Issues: []);
        });

        var cmd = new NuGetKeyVaultSignTool.VerifyCommand(
            TestUtilities.CreateNoopLogger(),
            verifier,
            resolvePackages: _ => new[] { unsigned, laterPackage });

        StringBuilder buffer = new();
        bool result = await cmd.VerifyAsync(Path.Combine(dir, "*.nupkg"), buffer);

        Assert.False(result);

        string output = buffer.ToString();
        Assert.Contains("Package signature is invalid.", output);
        Assert.Contains("Package signer is not trusted.", output);
        Assert.Contains("Finished with 1 errors and 1 warnings.", output);
    }

    [SkippableFact]
    [Trait("Category", "Integration")]
    [Trait("Category", "Verify.NuGetOrg")]
    public async Task VerifyAsync_Wildcard_WithUnsignedThenSigned_ReturnsFalse()
    {
        Skip.If(TestUtilities.IsTrueEnvironmentVariable(SkipNuGetOrgEnvVar), $"NuGet.org integration test skipped because `{SkipNuGetOrgEnvVar}` is set.");

        string dir = TestUtilities.CreateTemporaryDirectory();

        // Ensure the unsigned file sorts before the signed one, so we would catch any regression
        // where a later "true" might overwrite an earlier failure.
        _ = TestUtilities.CreateMinimalNupkg(dir, "AUnsigned", "1.0.0");

        string downloaded = await DownloadLatestStableNupkgAsync("Microsoft.Extensions.Logging", dir);

        // Rename so it sorts after the unsigned package.
        string signed = Path.Combine(dir, "ZSigned.nupkg");
        if(File.Exists(signed))
        {
            File.Delete(signed);
        }
        File.Move(downloaded, signed);

        Assert.True(HasSignatureFile(signed), "Downloaded package does not appear to be signed (missing `.signature.p7s`).");

        var cmd = new NuGetKeyVaultSignTool.VerifyCommand(TestUtilities.CreateNoopLogger());

        // Sanity-check the signed package verifies successfully in *this* environment.
        // Use cancellation so we cannot hang the test host (revocation checks, etc).
        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(60));
        bool singleResult = await cmd.VerifyAsync(signed, new StringBuilder(), cts.Token);
        Assert.True(singleResult, "Downloaded package did not verify as valid on this machine/policy.");

        // Now verify both packages via wildcard. Expect failure because one is unsigned.
        using CancellationTokenSource wildcardCts = new(TimeSpan.FromSeconds(60));
        bool result = await cmd.VerifyAsync(Path.Combine(dir, "*.nupkg"), new StringBuilder(), wildcardCts.Token);
        Assert.False(result);
    }

    private static async Task<string> DownloadLatestStableNupkgAsync(string packageId, string directory)
    {
        Directory.CreateDirectory(directory);

        string idLower = packageId.ToLowerInvariant();
        string indexUrl = $"https://api.nuget.org/v3-flatcontainer/{idLower}/index.json";

        using HttpClient http = new();
        http.Timeout = TimeSpan.FromSeconds(60);
        http.DefaultRequestHeaders.UserAgent.ParseAdd("NuGetKeyVaultSignTool.Core.Tests/1.0");

        string indexJson = await http.GetStringAsync(indexUrl);

        using JsonDocument doc = JsonDocument.Parse(indexJson);
        JsonElement versionsElem = doc.RootElement.GetProperty("versions");

        string? latestStable = null;
        foreach(JsonElement v in versionsElem.EnumerateArray())
        {
            string? s = v.GetString();
            if(string.IsNullOrWhiteSpace(s))
                continue;

            // Prefer stable versions (no prerelease tag).
            if(!s.Contains('-', StringComparison.Ordinal))
            {
                latestStable = s;
            }
        }

        // Fall back to whatever the last entry is.
        latestStable ??= versionsElem.GetArrayLength() > 0 ? versionsElem[versionsElem.GetArrayLength() - 1].GetString() : null;
        if(string.IsNullOrWhiteSpace(latestStable))
        {
            throw new InvalidOperationException($"Could not determine a version for {packageId} from {indexUrl}");
        }

        string nupkgUrl = $"https://api.nuget.org/v3-flatcontainer/{idLower}/{latestStable}/{idLower}.{latestStable}.nupkg";
        string destPath = Path.Combine(directory, $"{packageId}.{latestStable}.nupkg");

        await using Stream stream = await http.GetStreamAsync(nupkgUrl);
        await using FileStream fs = new(destPath, FileMode.Create, FileAccess.Write, FileShare.None);
        await stream.CopyToAsync(fs);

        return destPath;
    }

    private static bool HasSignatureFile(string nupkgPath)
    {
        using ZipArchive zip = ZipFile.OpenRead(nupkgPath);
        return zip.Entries.Any(e => string.Equals(e.FullName, ".signature.p7s", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class FakeVerifyPackageSignatures : NuGetKeyVaultSignTool.IVerifyPackageSignatures
    {
        private readonly System.Func<string, NuGetKeyVaultSignTool.VerificationResult> handler;

        public FakeVerifyPackageSignatures(System.Func<string, NuGetKeyVaultSignTool.VerificationResult> handler)
        {
            this.handler = handler;
        }

        public Task<NuGetKeyVaultSignTool.VerificationResult> VerifyAsync(string packageFilePath, System.Threading.CancellationToken cancellationToken)
        {
            return Task.FromResult(handler(packageFilePath));
        }
    }
}
