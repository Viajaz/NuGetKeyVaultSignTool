NuGetKeyVaultSignTool (Fork)
=====================

This tool adds [code signatures to a NuGet package](https://docs.microsoft.com/en-us/nuget/reference/signed-packages-reference) using an X509 certificate stored in [Microsoft Azure Key Vault.](https://azure.microsoft.com/en-us/services/key-vault/)

> [!IMPORTANT]
> This fork is **not maintained**. It is published only for others in the community as it upgrades the tool to .NET 10, adds tests, and fixes security issues.

# Getting started

This project can be a .NET global tool or standalone executable. Build it with the **.NET 10 SDK**.

Example:

```ps1
# Pack the tool
dotnet pack .\NuGetKeyVaultSignTool\NuGetKeyVaultSignTool.csproj -c Release

# Install the tool from the locally packed nupkg
dotnet tool install --global NuGetKeyVaultSignTool --add-source .\NuGetKeyVaultSignTool\bin\Release

# Alternatively, install the tool locally
# dotnet tool install --tool-path . NuGetKeyVaultSignTool --add-source .\NuGetKeyVaultSignTool\bin\Release

# Or publish a standalone executable (self-contained folder)
# dotnet publish .\NuGetKeyVaultSignTool\NuGetKeyVaultSignTool.csproj -c Release -r win-x64 --self-contained true

# Produce a package
& dotnet pack src/MyLibrary/

# Execute code signing
& NuGetKeyVaultSignTool sign MyLibrary.1.0.0.nupkg `
  --file-digest sha256 `
  --timestamp-rfc3161 http://timestamp.digicert.com `
  --timestamp-digest sha256 `
  --azure-key-vault-url https://my-keyvault.vault.azure.net `
  --azure-key-vault-client-id 1234566789 `
  --azure-key-vault-tenant-id <the guid or domain> `
  --azure-key-vault-client-secret abcxyz `
  --azure-key-vault-certificate MyCodeSignCert
```

# Standalone executable (self-contained folder)

If you want a standalone executable that runs on a machine without installing .NET, publish a **self-contained** build for your target OS/architecture (RID). This produces a folder you can zip/copy to other machines.

Example (Windows x64):

```ps1
dotnet publish .\NuGetKeyVaultSignTool\NuGetKeyVaultSignTool.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true
.\NuGetKeyVaultSignTool\bin\Release\net10.0\win-x64\publish\NuGetKeyVaultSignTool.exe --help
```

If you want the output written to `.\artifacts\publish\<RID>\`, the project supports a `PublishStandalone=true` switch:

```ps1
dotnet publish .\NuGetKeyVaultSignTool\NuGetKeyVaultSignTool.csproj -c Release -r win-x64 --self-contained true -p:PublishStandalone=true
.\artifacts\publish\win-x64\NuGetKeyVaultSignTool.exe --help
```

# Usage

The tool has two subcommands, `sign` and `verify`.

## `sign`

Signs a NuGet package using a certificate stored in Azure Key Vault.

Usage: `NuGetKeyVaultSignTool.exe sign [options] <FILE_PATH>`

FILE_PATH = the path to the .nupkg file produced by `dotnet pack` or `nuget.exe pack`.

Wildcard input:

When `FILE_PATH` contains wildcards (`*`/`?`) and expands to multiple packages, `--output` is treated as an **output directory** and each signed package is written there using its original file name.

Example:

```ps1
NuGetKeyVaultSignTool sign ".\artifacts\*.nupkg" `
  --output ".\artifacts\signed" `
  --file-digest sha256 `
  --timestamp-rfc3161 http://timestamp.digicert.com `
  --timestamp-digest sha256 `
  --azure-key-vault-url https://my-vault.vault.azure.net/ `
  --azure-key-vault-managed-identity `
  --azure-key-vault-certificate MyCodeSignCert
```

Options:

* `-o | --output` - The output file (single package) or output directory (wildcard input). If omitted, overwrites input.
* `-f | --force` - Overwrites a signature if it exists.
* `-fd | --file-digest` - The digest algorithm to hash the file with.
* `-tr | --timestamp-rfc3161` - Specifies the RFC 3161 timestamp server's URL. Required.
* `-td | --timestamp-digest` - Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.
* `-st | --signature-type` - The signature type (omit for author, default).
* `-kvu | --azure-key-vault-url` - The URL to an Azure Key Vault.
* `-kvt | --azure-key-vault-tenant-id` - The Tenant Id to authenticate to the Azure Key Vault..
* `-kvi | --azure-key-vault-client-id` - The Client ID to authenticate to the Azure Key Vault.
* `-kvs | --azure-key-vault-client-secret` - The Client Secret to authenticate to the Azure Key Vault.
* `-kvc | --azure-key-vault-certificate` - The name of the certificate in Azure Key Vault.
* `-kva | --azure-key-vault-accesstoken` - The Access Token to authenticate to the Azure Key Vault.
* `-kvm | --azure-key-vault-managed-identity` - Use a Managed Identity to access Azure Key Vault.

**Note** For the authentication options to Azure Key Vault, either one of the following options are required:

`azure-key-vault-client-id` and `azure-key-vault-client-secret` and `azure-key-vault-tenant-id` or `azure-key-vault-accesstoken` or `azure-key-vault-managed-identity`.

## `verify`

Verifies that a NuGet package has been code-signed.

Usage: `NuGetKeyVaultSignTool verify [options] <FILE_PATH>`

FILE_PATH = the path (or wildcard pattern) to the .nupkg file(s) produced by `dotnet pack` or `nuget.exe pack`.

## Testing

### Test suites

#### Unit tests

- **Requirements**: none (offline, no credentials).

```ps1
dotnet test .\NuGetKeyVaultSignTool.sln -c Release --filter "Category!=Integration"
```

#### Integration tests (external resources)

- **What these are**: tests that touch external resources (network / NuGet.org / Azure Key Vault) and may be slower or environment-dependent.
- **How they behave**:
  - Some are **opt-in** and will **skip** when not configured (for example, the Azure Key Vault signing test).
  - Some run by default and will **fail** if prerequisites aren’t met (for example, the NuGet.org verification test below, unless explicitly skipped).

```ps1
dotnet test .\NuGetKeyVaultSignTool.sln -c Release --filter "Category=Integration"
```

#### `verify`: NuGet.org signed package + wildcard regression (`Category=Verify.NuGetOrg`)

- **What it covers**: downloads a known signed package from NuGet.org and verifies it; includes a wildcard regression test that mixes unsigned + signed packages.
- **Requirements**:
  - outbound HTTPS access to NuGet.org
  - machine policy can validate the signature chain (trust store / revocation checks, etc.)
- **Default behavior**: this test **runs by default** when you run `dotnet test` without filters, and it will **fail** if the download or verification fails.
- **Opt-out**: set `NUGETKEYVAULTSIGNTOOL_TEST_SKIP_NUGETORG=1` to skip this test (or run only unit tests via `--filter "Category!=Integration"`).

```ps1
dotnet test .\NuGetKeyVaultSignTool.sln -c Release --filter "Category=Verify.NuGetOrg"
```

#### `sign`: Azure Key Vault certificate signing (`Category=Sign.AzureKeyVault`)

- **What it covers**: signs a temporary `.nupkg` using a certificate stored in a real Azure Key Vault.
- **Requirements**:
  - `NUGETKEYVAULTSIGNTOOL_TEST_KEYVAULT_URL` (example: `https://my-vault.vault.azure.net/`)
  - `NUGETKEYVAULTSIGNTOOL_TEST_CERTIFICATE_NAME` (certificate name in the vault)
  - `NUGETKEYVAULTSIGNTOOL_TEST_TIMESTAMP_URL` (optional; defaults to `http://timestamp.digicert.com`)
  - Azure authentication via `DefaultAzureCredential` (examples: service principal env vars, `az login`, managed/workload identity)

```ps1
dotnet test .\NuGetKeyVaultSignTool.sln -c Release --filter "Category=Sign.AzureKeyVault"
```

### Run everything

```ps1
dotnet test .\NuGetKeyVaultSignTool.sln -c Release
```

