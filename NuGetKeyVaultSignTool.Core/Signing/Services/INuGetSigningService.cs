using NuGet.Common;
using NuGet.Packaging.Signing;
using System.Threading;
using System.Threading.Tasks;

namespace NuGetKeyVaultSignTool;

/// <summary>
/// Wraps NuGet signing so it can be mocked in tests.
/// </summary>
internal interface INuGetSigningService
{
    Task SignAsync(
        string inputPackageFilePath,
        string outputPackageFilePath,
        bool overwrite,
        ISignatureProvider signatureProvider,
        ILogger logger,
        SignPackageRequest request,
        CancellationToken cancellationToken);
}
