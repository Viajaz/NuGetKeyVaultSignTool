using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace NuGetKeyVaultSignTool.Core.Tests;

/// <summary>
/// Ensures all test-created files (including temp files) are kept within the repo.
/// </summary>
internal static class TestRunEnvironment
{
    private const string OutputRootEnvVar = "NUGETKEYVAULTSIGNTOOL_TEST_OUTPUT_ROOT";
    private static readonly Lazy<Paths> lazyPaths = new(InitializePaths, isThreadSafe: true);

    public static string Root => lazyPaths.Value.Root;
    public static string TempRoot => lazyPaths.Value.TempRoot;
    public static string WorkRoot => lazyPaths.Value.WorkRoot;

    internal static void EnsureInitialized() => _ = lazyPaths.Value;

    private static Paths InitializePaths()
    {
        // Default to the repo root (discovered by walking up from the test output directory),
        // but allow overriding via env var.
        string baseDir = GetOutputBaseDirectory();
        string runId = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Environment.ProcessId}";

        string root = Path.Combine(baseDir, "artifacts", "test-output", runId);
        string tempRoot = Path.Combine(root, "temp");
        string workRoot = Path.Combine(root, "work");

        Directory.CreateDirectory(tempRoot);
        Directory.CreateDirectory(workRoot);

        // Redirect temp for the test process so product code that uses Path.GetTempPath/GetTempFileName
        // also stays repo-contained during tests.
        Environment.SetEnvironmentVariable("TEMP", tempRoot);
        Environment.SetEnvironmentVariable("TMP", tempRoot);
        Environment.SetEnvironmentVariable("TMPDIR", tempRoot);

        return new Paths(root, tempRoot, workRoot);
    }

    private static string GetOutputBaseDirectory()
    {
        string? fromEnv = Environment.GetEnvironmentVariable(OutputRootEnvVar);
        if(!string.IsNullOrWhiteSpace(fromEnv))
        {
            return Path.IsPathRooted(fromEnv)
                ? fromEnv
                : Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), fromEnv));
        }

        return TryFindRepoRootFrom(AppContext.BaseDirectory) ?? Directory.GetCurrentDirectory();
    }

    private static string? TryFindRepoRootFrom(string startDirectory)
    {
        for(DirectoryInfo? dir = new DirectoryInfo(startDirectory); dir is not null; dir = dir.Parent)
        {
            if(File.Exists(Path.Combine(dir.FullName, "NuGetKeyVaultSignTool.sln")))
            {
                return dir.FullName;
            }
        }

        return null;
    }

    private readonly record struct Paths(string Root, string TempRoot, string WorkRoot);
}

internal static class TestRunEnvironmentModuleInitializer
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        TestRunEnvironment.EnsureInitialized();
    }
}