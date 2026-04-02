<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/social-preview-dark.svg">
  <img src="docs/social-preview-light.svg" alt="mobile-security-mcp" width="100%">
</picture>

<p align="center">
  <a href="https://www.npmjs.com/package/mobile-security-mcp"><img src="https://img.shields.io/npm/v/mobile-security-mcp?color=0ea5e9&label=npm" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/mobile-security-mcp"><img src="https://img.shields.io/npm/dm/mobile-security-mcp?color=0ea5e9&label=downloads" alt="npm downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-10b981" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/TypeScript-5.3-3178c6" alt="TypeScript">
  <img src="https://img.shields.io/badge/MCP-compatible-6366f1" alt="MCP">
  <a href="https://github.com/Serhatcck/mobile-security-mcp/actions"><img src="https://img.shields.io/github/actions/workflow/status/Serhatcck/mobile-security-mcp/ci.yml?label=CI" alt="CI"></a>
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#tools">Tools</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#contributing">Contributing</a> ·
  <a href="#security">Security</a>
</p>

---

**mobile-security-mcp** is an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that gives Claude — and any MCP-compatible AI client — the ability to analyze Android APK and iOS IPA files for security issues through natural language conversation.

Security researchers, mobile pentesters, and app developers can now audit permissions, extract API endpoints, detect hardcoded secrets, inspect Firebase configuration, and enumerate third-party SDKs by simply asking Claude — no scripting required.

---

## Features

### Android
| Tool | What it does |
|---|---|
| `apk_manifest_analyzer` | Parses `AndroidManifest.xml` — flags `debuggable`, `allowBackup`, exported components, intent filters |
| `apk_permissions_checker` | Categorizes all permissions into **dangerous** vs normal with risk explanations |
| `android_api_extractor` | Decompiles smali bytecode to extract Retrofit HTTP endpoints and OkHttp3 fields |
| `android_google_services` | Extracts Firebase/GCP config from `google-services.json` and `resources.arsc` string values |
| `android_secrets_scanner` | Scans DEX bytecode + `resources.arsc` + assets for hardcoded API keys and credentials |

### iOS
| Tool | What it does |
|---|---|
| `ios_manifest_analyzer` | Parses `Info.plist` — flags ATS misconfigs, URL schemes, background modes |
| `ios_permissions_checker` | Categorizes privacy permission declarations by **HIGH / MEDIUM / LOW** risk |
| `ios_entitlements_checker` | Extracts entitlements via `codesign` — flags `get-task-allow`, sandbox bypass, iCloud containers |
| `ios_binary_strings` | Extracts URLs, emails, IPs, and API key patterns from the Mach-O binary |
| `ios_frameworks_detector` | Lists bundled frameworks, maps ~60 known SDKs (analytics, ads, attribution, crash reporting) |
| `ios_google_services` | Parses `GoogleService-Info.plist` for full Firebase configuration |
| `ios_secrets_scanner` | Scans app binary + resource files for hardcoded secrets and credentials |

### Shared Pattern Registry
All secret and Google service detection patterns live in a single `patterns.ts` — easy to extend, used by both Android and iOS scanners.

---

## Installation

```bash
npm install -g mobile-security-mcp
```

### Configure Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mobile-security-mcp": {
      "command": "npx",
      "args": ["mobile-security-mcp"]
    }
  }
}
```

**Config file locations:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

### Run from source

```bash
git clone https://github.com/Serhatcck/mobile-security-mcp.git
cd mobile-security-mcp
npm install && npm run build
```

```json
{
  "mcpServers": {
    "mobile-security-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/mobile-security-mcp/dist/index.js"]
    }
  }
}
```

---

## Usage

Once configured, restart Claude Desktop and start a conversation:

> *"Analyze the permissions in /path/to/app.apk"*

> *"Check this IPA for hardcoded API keys: /path/to/app.ipa"*

> *"What Firebase services does this APK use?"*

> *"Are there any exported components in this APK that could be an attack surface?"*

> *"Show me all third-party SDKs in this iOS app and flag any privacy risks"*

### Prerequisites

**Android:**
- [`apktool`](https://apktool.org) — required for `android_api_extractor` (`brew install apktool`)
- `aapt` (optional) — speeds up manifest parsing, part of Android SDK build tools

**iOS (macOS only):**
- `codesign`, `plutil`, `strings` — all built into macOS, no install needed

---

## Tools

### `apk_manifest_analyzer`
```
Input:  apk_path (string)
Output: Package info, security flags, components, intent filters, warnings
```

### `apk_permissions_checker`
```
Input:  apk_path (string)
Output: Dangerous permissions (highlighted) + normal permissions + risk summary
```

### `android_api_extractor`
```
Input:  apk_path OR smali_folder (string), output_format (txt|postman)
Output: Retrofit HTTP endpoints or Postman collection JSON
```

### `android_google_services`
```
Input:  apk_path (string), smali_folder (optional)
Output: Firebase project ID, API keys, database URL, storage bucket, OAuth clients
```

### `android_secrets_scanner`
```
Input:  apk_path (string), smali_folder (optional), min_length (default 8)
Output: Hardcoded credentials found in DEX + resources.arsc + assets
```

### `ios_manifest_analyzer`
```
Input:  ipa_path (string)
Output: Bundle info, ATS settings, URL schemes, background modes, warnings
```

### `ios_permissions_checker`
```
Input:  ipa_path (string)
Output: Privacy permissions grouped by HIGH/MEDIUM/LOW risk with usage descriptions
```

### `ios_entitlements_checker`
```
Input:  ipa_path (string)
Output: Entitlements extracted from binary, high-risk flags, simulator detection
```

### `ios_binary_strings`
```
Input:  ipa_path (string), filter (all|url|key|email|ip), min_length (default 6)
Output: Filtered strings from Mach-O binary
```

### `ios_frameworks_detector`
```
Input:  ipa_path (string)
Output: Bundled frameworks grouped by category with privacy risk annotations
```

### `ios_google_services`
```
Input:  ipa_path (string)
Output: Full GoogleService-Info.plist contents + pattern scan of resource files
```

### `ios_secrets_scanner`
```
Input:  ipa_path (string), min_length (default 8)
Output: Secrets found in resource files and binary, split by layer with severity
```

---

## Demo

![demo](docs/demo.gif)

> Regenerate with [VHS](https://github.com/charmbracelet/vhs): `brew install charmbracelet/tap/vhs && vhs docs/demo.tape`

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, how to add new tools, and PR guidelines.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities privately.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) © [Serhatcck](https://github.com/Serhatcck)
