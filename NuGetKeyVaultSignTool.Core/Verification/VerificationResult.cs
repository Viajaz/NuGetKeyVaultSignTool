using System.Collections.Generic;

namespace NuGetKeyVaultSignTool;

internal readonly record struct VerificationResult(bool IsValid, IReadOnlyList<VerificationIssue> Issues);
