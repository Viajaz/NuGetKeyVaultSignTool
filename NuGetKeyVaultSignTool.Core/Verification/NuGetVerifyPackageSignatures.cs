using NuGet.Packaging;
using NuGet.Packaging.Signing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NuGetKeyVaultSignTool;

internal sealed class NuGetVerifyPackageSignatures : IVerifyPackageSignatures
{
    public async Task<VerificationResult> VerifyAsync(string packageFilePath, CancellationToken cancellationToken)
    {
        ISignatureVerificationProvider[] trustProviders =
        [
            new IntegrityVerificationProvider(),
            new SignatureTrustAndValidityVerificationProvider()
        ];

        PackageSignatureVerifier verifier = new(trustProviders);

        using PackageArchiveReader package = new(packageFilePath);
        VerifySignaturesResult verificationResult = await verifier.VerifySignaturesAsync(
            package,
            SignedPackageVerifierSettings.GetVerifyCommandDefaultPolicy(),
            cancellationToken).ConfigureAwait(false);

        if(verificationResult.IsValid)
        {
            return new VerificationResult(IsValid: true, Issues: Array.Empty<VerificationIssue>());
        }

        List<VerificationIssue> issues = verificationResult.Results
            .SelectMany(r => r.Issues)
            .Select(i => i.AsRestoreLogMessage())
            .Select(m => new VerificationIssue(m.Level, m.Message))
            .ToList();

        return new VerificationResult(IsValid: false, Issues: issues);
    }
}
