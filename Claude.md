# LettuceEncrypt - Claude AI Context

## Project Overview

LettuceEncrypt is an ASP.NET Core library that provides automatic HTTPS certificate generation and management using Let's Encrypt and the ACME protocol. It integrates with Kestrel to automatically configure SSL/TLS certificates for web applications.

**Project Status**: Maintenance mode - security patches and critical fixes only

**Original Author**: [@natemcmaster](https://github.com/natemcmaster)

**Repository**: https://github.com/natemcmaster/LettuceEncrypt

## Architecture

### Solution Structure

```
LettuceEncrypt/
├── src/
│   ├── LettuceEncrypt/                    # Main library
│   ├── LettuceEncrypt.Azure/              # Azure Key Vault integration
│   └── Kestrel.Certificates/              # Kestrel certificate handling
├── test/
│   ├── LettuceEncrypt.UnitTests/          # Core unit tests
│   └── LettuceEncrypt.Azure.UnitTests/    # Azure integration tests
├── samples/
│   ├── Web/                               # Basic web sample
│   └── KeyVault/                          # Azure Key Vault sample
├── .github/                               # GitHub Actions workflows and templates
└── docs/                                  # Documentation
```

### Key Components

1. **LettuceEncrypt** - Core library providing:
   - ACME protocol client integration
   - Certificate generation and renewal
   - Kestrel integration
   - HTTP-01, TLS-ALPN-01, and DNS-01 challenge support
   - Certificate persistence (file system, custom stores)

2. **LettuceEncrypt.Azure** - Azure integration providing:
   - Azure Key Vault certificate storage
   - Azure Key Vault account key storage

3. **Kestrel.Certificates** - Low-level certificate handling for Kestrel

## Technology Stack

- **.NET Version**: .NET 8 (as of latest update)
- **Language Version**: C# 12.0
- **Features**: Implicit usings enabled
- **Target Framework**: Multi-targeting support

## Code Conventions

### Naming Conventions (enforced via .editorconfig)

- **Private fields**: `_camelCase` (prefixed with underscore) - ERROR severity
- **Private static fields**: `s_camelCase` (prefixed with s_) - SUGGESTION severity
- **Constants**: `PascalCase` - ERROR severity

### Code Style

- **Indentation**: 4 spaces for C# files, 2 spaces for XML/JSON
- **Braces**: Always required (`csharp_prefer_braces = true`)
- **Var usage**: Preferred for built-in types and when type is apparent
- **Using directives**: Outside namespace, system directives first
- **New line before**: catch, else, finally, open brace
- **Namespace declarations**: File-scoped (suggestion)
- **Expression bodies**: Preferred for indexers and accessors

### File Header

All source files must include:
```csharp
// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
```

### Build Configuration

- **TreatWarningsAsErrors**: true
- **Code style enforcement**: Enabled in build
- **Strong name signing**: Enabled (using src/StrongName.snk)
- **Symbol packages**: Generated as .snupkg

## Version Information

- **Current Version**: 1.3.4-beta.5 (from Directory.Build.props)
- **Versioning**: Semantic versioning with optional pre-release suffix
- **Build number**: Appended to version suffix from BUILD_NUMBER environment variable

## Development Workflow

### Building the Project

```bash
# Using the provided build script
./build.ps1

# Or using dotnet CLI
dotnet build LettuceEncrypt.sln
```

### Running Tests

```bash
dotnet test LettuceEncrypt.sln
```

### Creating Packages

```bash
dotnet pack LettuceEncrypt.sln
```

### Build Output

- Build artifacts: `.build/{ProjectName}/bin/`
- Intermediate output: `.build/{ProjectName}/obj/`

## Git Attributes

The repository uses comprehensive `.gitattributes` for:
- Auto-detection of text files with LF normalization
- CRLF line endings for Visual Studio project files (.sln, .csproj, etc.)
- LF line endings for bash scripts
- CRLF line endings for PowerShell scripts
- Binary handling for images, archives, fonts
- C# diff strategy for .cs files
- Markdown diff strategy for .md files

## Key Dependencies & Integrations

### ACME Protocol
- Let's Encrypt integration
- Certificate authority (CA) communication
- Challenge validation (HTTP-01, TLS-ALPN-01, DNS-01)

### Kestrel Integration
- Dynamic HTTPS configuration
- Certificate selector integration
- Startup integration points

### Storage Options
- X.509 certificate store (default)
- File system persistence
- Azure Key Vault
- Custom implementations via ICertificateRepository/ICertificateSource

## Configuration

Primary configuration via appsettings.json:
```json
{
  "LettuceEncrypt": {
    "AcceptTermsOfService": true,
    "DomainNames": ["example.com"],
    "EmailAddress": "admin@example.com",
    "AllowedChallengeTypes": "Http01, TlsAlpn01, Dns01"
  }
}
```

## Extension Points

### Customization Interfaces

1. **ICertificateRepository** - Custom certificate storage
2. **ICertificateSource** - Custom certificate loading
3. **IAccountStore** - Custom ACME account key storage
4. **IDnsChallengeProvider** - DNS-01 challenge handling

## Common Patterns

### Service Registration
```csharp
services.AddLettuceEncrypt()
    .PersistDataToDirectory(new DirectoryInfo("path"), "password");
```

### Kestrel Configuration
```csharp
webBuilder.UseKestrel(k =>
{
    k.ConfigureHttpsDefaults(h => h.UseLettuceEncrypt(k.ApplicationServices));
});
```

## Testing Considerations

- Integration tests available in test/ directory
- Developer docs for local testing: test/Integration/
- Non-production testing recommended before deployment

## CI/CD

### GitHub Actions Workflows

1. **ci.yml** - Continuous integration
   - Build verification
   - Test execution
   - Code coverage reporting (Codecov)

2. **stale.yml** - Stale issue/PR management

## Support Scenarios

### Supported ✅
- Kestrel as edge server
- Kestrel behind TCP load balancer (SSL pass-through)

### Not Supported ❌
- IIS hosting
- Azure App Services (use built-in cert management)
- Reverse proxy scenarios (HTTPS terminated before Kestrel)

## Security Considerations

- Security policy: https://github.com/natemcmaster/LettuceEncrypt/security/policy
- Report security issues through GitHub security advisories
- Private keys stored securely using configured storage mechanism
- ACME account keys persisted for certificate renewal

## License

Apache License 2.0 - See LICENSE.txt

## Contributing

See CONTRIBUTING.md for contribution guidelines.

## Notable Notes

- Project renamed from "McMaster.AspNetCore.LetsEncrypt" for trademark reasons
- Not an official Let's Encrypt® or ISRG™ offering
- Requires Kestrel as the web server (not IIS or HTTP.sys)
- Only works when Kestrel is the edge server or behind SSL pass-through
