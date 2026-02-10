using Microsoft.Extensions.Logging;
using NuGet.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace NuGetKeyVaultSignTool;

public sealed class VerifyCommand
{
    private readonly ILogger logger;
    private readonly IVerifyPackageSignatures verifyPackageSignatures;
    private readonly Func<string, IEnumerable<string>> resolvePackages;

    public VerifyCommand(ILogger logger)
        : this(logger, new NuGetVerifyPackageSignatures(), static file => LocalFolderUtility.ResolvePackageFromPath(file))
    {
    }

    internal VerifyCommand(ILogger logger, IVerifyPackageSignatures verifyPackageSignatures, Func<string, IEnumerable<string>> resolvePackages)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(verifyPackageSignatures);
        ArgumentNullException.ThrowIfNull(resolvePackages);

        this.logger = logger;
        this.verifyPackageSignatures = verifyPackageSignatures;
        this.resolvePackages = resolvePackages;
    }

    public async Task<bool> VerifyAsync(string file, StringBuilder buffer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(buffer);

        bool allPackagesVerified = true;

        try
        {
            IEnumerable<string> packagesToVerify = resolvePackages(file);

            foreach(string packageFile in packagesToVerify)
            {
                cancellationToken.ThrowIfCancellationRequested();

                VerificationResult verificationResult = await verifyPackageSignatures
                    .VerifyAsync(packageFile, cancellationToken)
                    .ConfigureAwait(false);

                if(!verificationResult.IsValid)
                {
                    foreach(VerificationIssue issue in verificationResult.Issues)
                    {
                        buffer.AppendLine(issue.Message);
                    }

                    if(verificationResult.Issues.Any(i => i.Level >= NuGet.Common.LogLevel.Warning))
                    {
                        int errors = verificationResult.Issues.Count(i => i.Level == NuGet.Common.LogLevel.Error);
                        int warnings = verificationResult.Issues.Count(i => i.Level == NuGet.Common.LogLevel.Warning);

                        buffer.AppendLine($"Finished with {errors} errors and {warnings} warnings.");
                    }

                    allPackagesVerified = false;
                }
            }
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch(Exception e)
        {
            logger.LogError(e, "{errorMessage}", e.Message);
            return false;
        }

        return allPackagesVerified;
    }
}
