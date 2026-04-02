import { z } from "zod";
import AdmZip from "adm-zip";
import plist from "plist";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parsePlistBuffer } from "./manifest-analyzer.js";

export const iosEntitlementsChecker = {
  description:
    "Extracts and analyzes entitlements embedded in the iOS app binary using codesign. Detects dangerous entitlements like get-task-allow (debug builds), iCloud containers, and keychain groups.",

  schema: {
    ipa_path: z
      .string()
      .describe("Absolute path to the IPA file to analyze"),
  },

  handler: async (args: { ipa_path: string }) => {
    if (!fs.existsSync(args.ipa_path)) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error: IPA file not found: ${args.ipa_path}`,
          },
        ],
      };
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-ent-"));
    try {
      const binaryPath = extractBinary(args.ipa_path, tmpDir);
      if (!binaryPath) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Error: Could not find app binary inside IPA.",
            },
          ],
        };
      }

      // Detect simulator build early via `file` command
      let isSimulator = false;
      try {
        const fileOut = execSync(`file "${binaryPath}"`, { stdio: "pipe" }).toString();
        isSimulator = fileOut.includes("simulator") || fileOut.includes("x86_64");
      } catch {
        // ignore
      }

      const entitlements = readEntitlements(binaryPath);
      if (!entitlements) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Error: Could not read entitlements. Is codesign available? (macOS only)",
            },
          ],
        };
      }

      // Treat empty entitlements on a simulator build as expected
      if (entitlements === "simulator" || (isSimulator && typeof entitlements === "object" && Object.keys(entitlements).length === 0)) {
        return {
          content: [
            {
              type: "text" as const,
              text: [
                "=== iOS Entitlements Analysis ===",
                "",
                "⚠ Simulator Build Detected",
                "",
                "This IPA contains a simulator binary (x86_64 / arm64-sim).",
                "Simulator builds are NOT code-signed, so entitlements cannot be",
                "extracted with codesign or ldid.",
                "",
                "To analyze entitlements, use a device (Ad Hoc / App Store) IPA",
                "signed with a real provisioning profile.",
              ].join("\n"),
            },
          ],
        };
      }

      const report = buildReport(entitlements);
      return { content: [{ type: "text" as const, text: report }] };
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  },
};

function extractBinary(ipaPath: string, outDir: string): string | null {
  const zip = new AdmZip(ipaPath);
  const entries = zip.getEntries();

  // Find Info.plist to get CFBundleExecutable
  const plistEntry = entries.find((e) =>
    /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.entryName)
  );

  let executableName: string | null = null;
  if (plistEntry) {
    try {
      const parsed = parsePlistBuffer(plistEntry.getData());
      executableName = parsed["CFBundleExecutable"] as string | null;
    } catch {
      // ignore
    }
  }

  // Find the binary entry
  const binaryEntry = entries.find((e) => {
    if (executableName) {
      return new RegExp(`^Payload/[^/]+\\.app/${executableName}$`).test(e.entryName);
    }
    // Heuristic: binary at root of .app with no extension
    return /^Payload\/[^/]+\.app\/[^/]+$/.test(e.entryName) &&
      !e.entryName.endsWith(".plist") &&
      !e.entryName.endsWith(".nib") &&
      !e.entryName.endsWith(".car") &&
      !e.entryName.endsWith(".strings");
  });

  if (!binaryEntry) return null;

  const outPath = path.join(outDir, "binary");
  fs.writeFileSync(outPath, binaryEntry.getData());
  fs.chmodSync(outPath, 0o755);
  return outPath;
}

function readEntitlements(binaryPath: string): Record<string, unknown> | null | "simulator" {
  // Try codesign
  try {
    const output = execSync(
      `codesign -d --entitlements :- "${binaryPath}" 2>/dev/null`,
      { stdio: "pipe" }
    );
    const text = output.toString().trim();
    if (!text || text.length < 10) return "simulator";
    const parsed = plist.parse(text) as Record<string, unknown>;
    return parsed;
  } catch {
    // codesign may fail on simulator binaries
  }

  // Check if it's a simulator binary (x86_64 or arm64-sim Mach-O)
  try {
    const fileOut = execSync(`file "${binaryPath}"`, { stdio: "pipe" }).toString();
    if (fileOut.includes("simulator") || fileOut.includes("i386") || fileOut.includes("x86_64")) {
      return "simulator";
    }
  } catch {
    // ignore
  }

  // Try ldid (common on jailbreak toolchains)
  try {
    const output = execSync(`ldid -e "${binaryPath}"`, { stdio: "pipe" });
    const text = output.toString().trim();
    if (!text || text.length < 10) return "simulator";
    const parsed = plist.parse(text) as Record<string, unknown>;
    return parsed;
  } catch {
    return "simulator";
  }
}

const HIGH_RISK_ENTITLEMENTS: Record<string, string> = {
  "get-task-allow": "DEBUG BUILD — allows other processes to attach a debugger",
  "com.apple.private.security.no-sandbox": "App sandbox disabled — full filesystem access",
  "com.apple.private.security.no-container": "No container restriction",
  "com.apple.security.cs.disable-library-validation": "Arbitrary code injection possible",
  "com.apple.security.cs.allow-unsigned-executable-memory": "Unsigned executable memory allowed",
};

const MEDIUM_RISK_ENTITLEMENTS: Record<string, string> = {
  "aps-environment": "Push notifications enabled",
  "com.apple.developer.icloud-container-identifiers": "iCloud container access",
  "com.apple.developer.ubiquity-kvstore-identifier": "iCloud Key-Value store",
  "keychain-access-groups": "Shared keychain groups",
  "com.apple.developer.associated-domains": "Universal links / Associated domains",
  "com.apple.developer.healthkit": "HealthKit data access",
  "com.apple.developer.homekit": "HomeKit device control",
};

function buildReport(ents: Record<string, unknown>): string {
  const lines: string[] = [];
  const warnings: string[] = [];

  lines.push(`=== iOS Entitlements Analysis ===\n`);
  lines.push(`Total entitlements: ${Object.keys(ents).length}\n`);

  // High risk
  lines.push(`--- High Risk ---`);
  let highFound = false;
  for (const [key, desc] of Object.entries(HIGH_RISK_ENTITLEMENTS)) {
    if (key in ents) {
      const val = ents[key];
      lines.push(`  ⚠ ${key}`);
      lines.push(`      Value  : ${JSON.stringify(val)}`);
      lines.push(`      Risk   : ${desc}`);
      warnings.push(desc);
      highFound = true;
    }
  }
  if (!highFound) lines.push(`  ✓ None`);

  // Medium risk
  lines.push(`\n--- Medium Risk ---`);
  let medFound = false;
  for (const [key, desc] of Object.entries(MEDIUM_RISK_ENTITLEMENTS)) {
    if (key in ents) {
      const val = ents[key];
      lines.push(`  ⚡ ${key}`);
      lines.push(`      Value  : ${JSON.stringify(val)}`);
      lines.push(`      Note   : ${desc}`);
      medFound = true;
    }
  }
  if (!medFound) lines.push(`  None`);

  // All entitlements (informational)
  const knownKeys = new Set([
    ...Object.keys(HIGH_RISK_ENTITLEMENTS),
    ...Object.keys(MEDIUM_RISK_ENTITLEMENTS),
  ]);
  const other = Object.entries(ents).filter(([k]) => !knownKeys.has(k));

  if (other.length > 0) {
    lines.push(`\n--- Other Entitlements (${other.length}) ---`);
    for (const [k, v] of other) {
      lines.push(`    ${k}: ${JSON.stringify(v)}`);
    }
  }

  // APS environment check
  if (ents["aps-environment"] === "development") {
    warnings.push(`aps-environment=development — this is a development/debug build`);
  }

  if (warnings.length > 0) {
    lines.push(`\n=== Security Summary ===`);
    for (const w of warnings) {
      lines.push(`  ⚠ ${w}`);
    }
  } else {
    lines.push(`\n✓ No critical entitlement issues detected.`);
  }

  return lines.join("\n");
}
