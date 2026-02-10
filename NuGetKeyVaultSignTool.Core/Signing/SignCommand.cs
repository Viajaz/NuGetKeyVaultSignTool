using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using NuGet.Common;
using NuGet.Packaging.Signing;
using NuGet.Protocol;
using RSAKeyVaultProvider;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace NuGetKeyVaultSignTool;

public class SignCommand
{
    private readonly ILogger logger;
    private readonly INuGetSigningService signingService;

    public SignCommand(ILogger logger)
        : this(logger, new NuGetSigningService())
    {
    }

    internal SignCommand(ILogger logger, INuGetSigningService signingService)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(signingService);

        this.logger = logger;
        this.signingService = signingService;
    }

    public async Task<bool> SignAsync(string packagePath,
                                     string outputPath,
                                     string timestampUrl,
                                     HashAlgorithmName signatureHashAlgorithm,
                                     HashAlgorithmName timestampHashAlgorithm,
                                     SignatureType signatureType,
                                     bool overwrite,
                                     Uri v3ServiceIndexUrl,
                                     IReadOnlyList<string> packageOwners,
                                     string keyVaultCertificateName,
                                     Uri keyVaultUrl,
                                     TokenCredential credential,
                                     CancellationToken cancellationToken = default)
    {
        CertificateClient client = new(keyVaultUrl, credential);
        // We call this here to verify it's a valid cert
        // It also implicitly validates the access token or credentials
        Azure.Response<KeyVaultCertificateWithPolicy> kvcert = await client.GetCertificateAsync(keyVaultCertificateName, cancellationToken)
                                 .ConfigureAwait(false);
        using X509Certificate2 publicCertificate = X509CertificateLoader.LoadCertificate(kvcert.Value.Cer);

        using System.Security.Cryptography.RSA rsa = RSAFactory.Create(credential, kvcert.Value.KeyId, publicCertificate);

        return await SignAsync(packagePath, outputPath, timestampUrl, v3ServiceIndexUrl, packageOwners, signatureType, signatureHashAlgorithm, timestampHashAlgorithm, overwrite, publicCertificate, rsa, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<bool> SignAsync(string packagePath, string outputPath, string timestampUrl, Uri v3ServiceIndex, IReadOnlyList<string> packageOwners,
                                      SignatureType signatureType, HashAlgorithmName signatureHashAlgorithm, HashAlgorithmName timestampHashAlgorithm,
                                      bool overwrite, X509Certificate2 publicCertificate, System.Security.Cryptography.RSA rsa, CancellationToken cancellationToken = default)
    {
        bool usingWildCards = packagePath.Contains('*') || packagePath.Contains('?');
        StringComparison pathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        bool inPlaceSigning = usingWildCards
            ? string.Equals(packagePath, outputPath, pathComparison)
            : string.Equals(Path.GetFullPath(packagePath), Path.GetFullPath(outputPath), pathComparison);

        IEnumerable<string> packagesToSign = LocalFolderUtility.ResolvePackageFromPath(packagePath);

        KeyVaultSignatureProvider signatureProvider = new(rsa, new Rfc3161TimestampProvider(new Uri(timestampUrl)));

        SignPackageRequest request = signatureType switch
        {
            SignatureType.Author => new AuthorSignPackageRequest(publicCertificate, signatureHashAlgorithm, timestampHashAlgorithm),
            SignatureType.Repository => new RepositorySignPackageRequest(publicCertificate, signatureHashAlgorithm, timestampHashAlgorithm, v3ServiceIndex, packageOwners),
            _ => throw new ArgumentOutOfRangeException(nameof(signatureType))
        };

        string? originalPackageCopyPath = null;
        foreach(string package in packagesToSign)
        {
            cancellationToken.ThrowIfCancellationRequested();
            logger.LogInformation("{SignAsync} [{package}]: Begin Signing {fileName}", nameof(SignAsync), package, Path.GetFileName(package));
            try
            {
                originalPackageCopyPath = CopyPackage(package);
                string signedPackagePath = outputPath;
                if(inPlaceSigning)
                {
                    signedPackagePath = package;
                }
                else if(usingWildCards)
                {
                    string packageFile = Path.GetFileName(package);

                    // In wildcard mode, treat outputPath as an output directory (per package).
                    // If the caller accidentally passes a file name (e.g. "signed.nupkg"), use its directory.
                    string outputDir = outputPath;
                    if(string.Equals(Path.GetExtension(outputDir), ".nupkg", StringComparison.OrdinalIgnoreCase))
                    {
                        outputDir = Path.GetDirectoryName(outputDir) ?? outputDir;
                    }

                    if(string.IsNullOrWhiteSpace(outputDir))
                    {
                        outputDir = Directory.GetCurrentDirectory();
                    }

                    Directory.CreateDirectory(outputDir);
                    signedPackagePath = Path.Combine(outputDir, packageFile);
                }
                await this.signingService.SignAsync(
                    inputPackageFilePath: originalPackageCopyPath,
                    outputPackageFilePath: signedPackagePath,
                    overwrite: overwrite,
                    signatureProvider: signatureProvider,
                    logger: new NuGetLogger(logger, package),
                    request: request,
                    cancellationToken: cancellationToken);
            }
            catch(Exception e)
            {
                logger.LogError(e, "{errorMessage}", e.Message);
                return false;
            }
            finally
            {
                try
                {
                    if(originalPackageCopyPath is not null)
                    {
                        FileUtility.Delete(originalPackageCopyPath);
                    }
                }
                catch
                {
                }

                logger.LogInformation("{method} [{package}]: End Signing {fileName}", nameof(SignAsync), package, Path.GetFileName(package));
            }
        }

        return true;
    }

    private static string CopyPackage(string sourceFilePath)
    {
        string destFilePath = Path.GetTempFileName();
        File.Copy(sourceFilePath, destFilePath, overwrite: true);

        return destFilePath;
    }
}
