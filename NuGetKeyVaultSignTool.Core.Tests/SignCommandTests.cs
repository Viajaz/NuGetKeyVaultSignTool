using NuGetHashAlgorithmName = NuGet.Common.HashAlgorithmName;
using NuGet.Packaging.Signing;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace NuGetKeyVaultSignTool.Core.Tests;

public class SignCommandTests
{
    [Fact]
    public async Task SignAsync_InvalidSignatureType_ThrowsArgumentOutOfRangeException()
    {
        string dir = TestUtilities.CreateTemporaryDirectory();
        string packagePath = TestUtilities.CreateMinimalNupkg(dir, "InvalidSigType", "1.0.0");
        using var certAndKey = DisposableCertAndKey.Create();

        var cmd = new NuGetKeyVaultSignTool.SignCommand(TestUtilities.CreateNoopLogger(), new FakeSigningService());

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            cmd.SignAsync(
                packagePath,
                packagePath,
                "http://example.test/timestamp",
                new Uri("https://api.nuget.org/v3/index.json"),
                packageOwners: [],
                signatureType: (SignatureType)999,
                signatureHashAlgorithm: NuGetHashAlgorithmName.SHA256,
                timestampHashAlgorithm: NuGetHashAlgorithmName.SHA256,
                overwrite: true,
                publicCertificate: certAndKey.PublicCertificate,
                rsa: certAndKey.Rsa));
    }

    [Fact]
    public async Task SignAsync_InPlaceSigning_UsesSameOutputPath_DeletesTempCopy()
    {
        string dir = TestUtilities.CreateTemporaryDirectory();
        string packagePath = TestUtilities.CreateMinimalNupkg(dir, "InPlace", "1.0.0");
        using var certAndKey = DisposableCertAndKey.Create();

        var signing = new FakeSigningService();
        var cmd = new NuGetKeyVaultSignTool.SignCommand(TestUtilities.CreateNoopLogger(), signing);

        bool result = await cmd.SignAsync(
            packagePath,
            packagePath,
            "http://example.test/timestamp",
            new Uri("https://api.nuget.org/v3/index.json"),
            packageOwners: [],
            signatureType: SignatureType.Author,
            signatureHashAlgorithm: NuGetHashAlgorithmName.SHA256,
            timestampHashAlgorithm: NuGetHashAlgorithmName.SHA256,
            overwrite: true,
            publicCertificate: certAndKey.PublicCertificate,
            rsa: certAndKey.Rsa);

        Assert.True(result);
        Assert.Single(signing.Calls);

        var call = signing.Calls[0];
        Assert.Equal(packagePath, call.OutputPackageFilePath);
        Assert.False(File.Exists(call.InputPackageFilePath), "Temp copy should be deleted after signing attempt completes.");
    }

    [Fact]
    public async Task SignAsync_WildcardInput_CreatesOutputDirectory_UsesPerPackageOutputPath()
    {
        string dir = TestUtilities.CreateTemporaryDirectory();
        string p1 = TestUtilities.CreateMinimalNupkg(dir, "WildcardA", "1.0.0");
        string p2 = TestUtilities.CreateMinimalNupkg(dir, "WildcardB", "1.0.0");

        // Ensure we have at least 2 packages.
        Assert.True(File.Exists(p1));
        Assert.True(File.Exists(p2));

        string pattern = Path.Combine(dir, "*.nupkg");
        string outputDir = Path.Combine(dir, "signed");
        if(Directory.Exists(outputDir))
        {
            Directory.Delete(outputDir, recursive: true);
        }

        using var certAndKey = DisposableCertAndKey.Create();

        var signing = new FakeSigningService();
        var cmd = new NuGetKeyVaultSignTool.SignCommand(TestUtilities.CreateNoopLogger(), signing);

        bool result = await cmd.SignAsync(
            pattern,
            outputDir,
            "http://example.test/timestamp",
            new Uri("https://api.nuget.org/v3/index.json"),
            packageOwners: [],
            signatureType: SignatureType.Author,
            signatureHashAlgorithm: NuGetHashAlgorithmName.SHA256,
            timestampHashAlgorithm: NuGetHashAlgorithmName.SHA256,
            overwrite: true,
            publicCertificate: certAndKey.PublicCertificate,
            rsa: certAndKey.Rsa);

        Assert.True(result);
        Assert.True(Directory.Exists(outputDir), "Wildcard mode should create output directory if it does not exist.");

        Assert.True(signing.Calls.Count >= 2, "Should attempt signing each resolved package.");

        // Validate the output paths are under the provided directory and match input file names.
        var outputs = signing.Calls.Select(c => c.OutputPackageFilePath).ToList();
        Assert.Contains(Path.Combine(outputDir, Path.GetFileName(p1)), outputs);
        Assert.Contains(Path.Combine(outputDir, Path.GetFileName(p2)), outputs);

        // Validate temp copies are cleaned up.
        foreach(string input in signing.Calls.Select(c => c.InputPackageFilePath))
        {
            Assert.False(File.Exists(input!), $"Temp copy should be deleted: {input}");
        }
    }

    [Fact]
    public async Task SignAsync_WhenSigningThrows_ReturnsFalse_AndDeletesTempCopy()
    {
        string dir = TestUtilities.CreateTemporaryDirectory();
        string packagePath = TestUtilities.CreateMinimalNupkg(dir, "Throwing", "1.0.0");
        using var certAndKey = DisposableCertAndKey.Create();

        var signing = new FakeSigningService((input, output, overwrite, provider, logger, request, ct) => throw new InvalidOperationException("boom"));
        var cmd = new NuGetKeyVaultSignTool.SignCommand(TestUtilities.CreateNoopLogger(), signing);

        bool result = await cmd.SignAsync(
            packagePath,
            packagePath,
            "http://example.test/timestamp",
            new Uri("https://api.nuget.org/v3/index.json"),
            packageOwners: [],
            signatureType: SignatureType.Author,
            signatureHashAlgorithm: NuGetHashAlgorithmName.SHA256,
            timestampHashAlgorithm: NuGetHashAlgorithmName.SHA256,
            overwrite: true,
            publicCertificate: certAndKey.PublicCertificate,
            rsa: certAndKey.Rsa);

        Assert.False(result);
        Assert.Single(signing.Calls);

        Assert.False(File.Exists(signing.Calls[0].InputPackageFilePath), "Temp copy should be deleted even when signing fails.");
    }
}