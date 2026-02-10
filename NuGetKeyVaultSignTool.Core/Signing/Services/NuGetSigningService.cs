using NuGet.Common;
using NuGet.Packaging.Signing;
using System.Threading;
using System.Threading.Tasks;

namespace NuGetKeyVaultSignTool;

internal sealed class NuGetSigningService : INuGetSigningService
{
    public async Task SignAsync(
        string inputPackageFilePath,
        string outputPackageFilePath,
        bool overwrite,
        ISignatureProvider signatureProvider,
        ILogger logger,
        SignPackageRequest request,
        CancellationToken cancellationToken)
    {
        using SigningOptions options = SigningOptions.CreateFromFilePaths(
            inputPackageFilePath,
            outputPackageFilePath,
            overwrite,
            signatureProvider,
            logger);

        await SigningUtility.SignAsync(options, request, cancellationToken).ConfigureAwait(false);
    }
}
