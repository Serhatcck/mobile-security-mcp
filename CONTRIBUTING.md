# Contributing to mobile-security-mcp

Thank you for your interest in contributing! This guide covers everything you need to get started.

## Development Setup

```bash
git clone https://github.com/Serhatcck/mobile-security-mcp.git
cd mobile-security-mcp
npm install
npm run build
```

Watch mode during development:
```bash
npx tsc --watch
```

## Project Structure

```
src/
  index.ts                    # MCP server entry — tool registration
  tools/
    shared/
      patterns.ts             # Centralized regex pattern registry
    android/
      api-extractor.ts        # android_api_extractor
      manifest-analyzer.ts    # apk_manifest_analyzer
      permissions-checker.ts  # apk_permissions_checker
      google-services.ts      # android_google_services
      secrets-scanner.ts      # android_secrets_scanner
    ios/
      manifest-analyzer.ts    # ios_manifest_analyzer
      permissions-checker.ts  # ios_permissions_checker
      entitlements-checker.ts # ios_entitlements_checker
      binary-strings.ts       # ios_binary_strings
      frameworks-detector.ts  # ios_frameworks_detector
      google-services.ts      # ios_google_services
      secrets-scanner.ts      # ios_secrets_scanner
```

## Adding a New Tool

1. Create `src/tools/<platform>/<tool-name>.ts`
2. Export an object with `description`, `schema` (zod), and `handler`
3. Register it in `src/index.ts` with `server.tool(...)`
4. Add an entry to the tools table in `README.md`

Example skeleton:

```typescript
import { z } from "zod";

export const myNewTool = {
  description: "One clear sentence describing what this tool does.",

  schema: {
    file_path: z.string().describe("Absolute path to the file"),
  },

  handler: async (args: { file_path: string }) => {
    // implementation
    return { content: [{ type: "text" as const, text: "result" }] };
  },
};
```

## Adding Detection Patterns

All secret and Google service patterns live in `src/tools/shared/patterns.ts`. To add a new pattern:

```typescript
// In SECRET_PATTERNS array:
{
  name: "My Service API Key",
  pattern: /my-service-[A-Za-z0-9]{32}/g,
  risk: "HIGH",
  description: "My Service API key",
},
```

Risk levels: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`

The pattern will automatically be picked up by both `android_secrets_scanner` and `ios_secrets_scanner`.

## Adding Known Frameworks

To add a framework to `ios_frameworks_detector`, add an entry to the `KNOWN_FRAMEWORKS` map in `src/tools/ios/frameworks-detector.ts`:

```typescript
MySDK: {
  category: "Analytics",
  description: "My SDK description",
  risk: "Optional: explain what data it collects",
},
```

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Add a short description of what changed and why
- Run `npm run build` before submitting — no TypeScript errors
- Test your changes against a real APK or IPA if possible

## Reporting Issues

Use the GitHub issue templates:
- **Bug report** — tool crashes or produces wrong output
- **Feature request** — new tool idea or pattern addition

For security vulnerabilities, see [SECURITY.md](SECURITY.md).
