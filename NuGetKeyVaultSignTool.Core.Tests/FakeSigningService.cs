using NuGet.Common;
using NuGet.Packaging.Signing;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace NuGetKeyVaultSignTool.Core.Tests;

internal sealed class FakeSigningService : INuGetSigningService
{
    private readonly Func<string, string, bool, ISignatureProvider, ILogger, SignPackageRequest, CancellationToken, Task>? handler;

    public FakeSigningService(Func<string, string, bool, ISignatureProvider, ILogger, SignPackageRequest, CancellationToken, Task>? handler = null)
    {
        this.handler = handler;
    }

    public List<Call> Calls { get; } = [];

    public Task SignAsync(
        string inputPackageFilePath,
        string outputPackageFilePath,
        bool overwrite,
        ISignatureProvider signatureProvider,
        ILogger logger,
        SignPackageRequest request,
        CancellationToken cancellationToken)
    {
        Calls.Add(new Call(
            inputPackageFilePath,
            outputPackageFilePath,
            overwrite,
            signatureProvider,
            logger,
            request));

        return handler?.Invoke(inputPackageFilePath, outputPackageFilePath, overwrite, signatureProvider, logger, request, cancellationToken)
            ?? Task.CompletedTask;
    }

    public sealed record Call(
        string InputPackageFilePath,
        string OutputPackageFilePath,
        bool Overwrite,
        ISignatureProvider SignatureProvider,
        ILogger Logger,
        SignPackageRequest Request);
}