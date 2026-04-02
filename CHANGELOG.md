# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-04-02

### Added

**Android tools**
- `apk_manifest_analyzer` — parses AndroidManifest.xml, flags debuggable/allowBackup/cleartext traffic, exported components, intent filters
- `apk_permissions_checker` — categorizes dangerous vs normal permissions with risk summary
- `android_api_extractor` — decompiles smali bytecode to extract Retrofit HTTP endpoints and OkHttp3 fields; outputs plain text or Postman collection
- `android_google_services` — extracts Firebase/GCP config from `google-services.json` and `resources.arsc` via strings command; supports optional smali_folder for structured output
- `android_secrets_scanner` — scans DEX bytecode + `resources.arsc` + text assets for hardcoded API keys and credentials

**iOS tools**
- `ios_manifest_analyzer` — parses Info.plist, flags ATS misconfigs, URL schemes, background location, queried schemes
- `ios_permissions_checker` — maps all `NS*UsageDescription` keys to HIGH/MEDIUM/LOW risk with explanations
- `ios_entitlements_checker` — extracts entitlements from app binary via codesign/ldid, flags get-task-allow and sandbox bypass, detects simulator builds
- `ios_binary_strings` — extracts URLs, emails, private IPs, and API key patterns from Mach-O binary
- `ios_frameworks_detector` — enumerates bundled .framework and .dylib files, maps ~60 known SDKs across networking, analytics, ads, attribution, crash reporting, fraud detection categories
- `ios_google_services` — parses GoogleService-Info.plist for full Firebase configuration
- `ios_secrets_scanner` — two-layer scan: text resource files (plist/json/strings) + app binary via strings command

**Shared**
- `patterns.ts` — centralized `GOOGLE_PATTERNS` and `SECRET_PATTERNS` registry shared across all scanner tools; `scanText` and `renderResults` utilities
