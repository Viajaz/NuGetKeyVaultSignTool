namespace NuGetKeyVaultSignTool;

internal readonly record struct VerificationIssue(NuGet.Common.LogLevel Level, string Message);
