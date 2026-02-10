using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NuGetKeyVaultSignTool.Core.Tests;

internal sealed class DisposableCertAndKey : IDisposable
{
    public required X509Certificate2 PublicCertificate { get; init; }
    public required RSA Rsa { get; init; }

    public static DisposableCertAndKey Create()
    {
        var (cert, rsa) = TestUtilities.CreatePublicCertificateAndRsa();
        return new DisposableCertAndKey { PublicCertificate = cert, Rsa = rsa };
    }

    public void Dispose()
    {
        PublicCertificate.Dispose();
        Rsa.Dispose();
    }
}