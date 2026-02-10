using System.Threading;
using System.Threading.Tasks;

namespace NuGetKeyVaultSignTool;

internal interface IVerifyPackageSignatures
{
    Task<VerificationResult> VerifyAsync(string packageFilePath, CancellationToken cancellationToken);
}
