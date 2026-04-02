import { z } from "zod";
import AdmZip from "adm-zip";
import plist from "plist";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export const iosManifestAnalyzer = {
  description:
    "Parses Info.plist from an IPA file. Extracts bundle ID, version, URL schemes, App Transport Security settings, background modes, and highlights insecure configurations.",

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

    let plistData: Record<string, unknown>;
    try {
      plistData = extractInfoPlist(args.ipa_path);
    } catch (e) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error extracting Info.plist: ${e instanceof Error ? e.message : String(e)}`,
          },
        ],
      };
    }

    const report = buildReport(plistData);
    return { content: [{ type: "text" as const, text: report }] };
  },
};

export function extractInfoPlist(ipaPath: string): Record<string, unknown> {
  const zip = new AdmZip(ipaPath);
  const entries = zip.getEntries();

  // Find Info.plist inside Payload/<AppName>.app/Info.plist
  const plistEntry = entries.find((e) =>
    /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.entryName)
  );

  if (!plistEntry) {
    throw new Error("Info.plist not found inside IPA");
  }

  const data = plistEntry.getData();
  return parsePlistBuffer(data);
}

export function parsePlistBuffer(data: Buffer): Record<string, unknown> {
  // Try XML plist first
  try {
    const text = data.toString("utf-8");
    if (text.includes("<?xml") || text.includes("<!DOCTYPE plist")) {
      return plist.parse(text) as Record<string, unknown>;
    }
  } catch {
    // not XML
  }

  // Binary plist — convert via plutil (macOS built-in)
  const tmpFile = path.join(os.tmpdir(), `plist-${Date.now()}.plist`);
  try {
    fs.writeFileSync(tmpFile, data);
    const xml = execSync(`plutil -convert xml1 -o - "${tmpFile}"`, {
      stdio: "pipe",
    }).toString();
    return plist.parse(xml) as Record<string, unknown>;
  } finally {
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  }
}

function buildReport(p: Record<string, unknown>): string {
  const lines: string[] = [];
  const warnings: string[] = [];

  lines.push(`=== iOS Info.plist Analysis ===\n`);

  // Basic info
  lines.push(`Bundle ID   : ${p["CFBundleIdentifier"] ?? "N/A"}`);
  lines.push(`Display Name: ${p["CFBundleDisplayName"] ?? p["CFBundleName"] ?? "N/A"}`);
  lines.push(`Version     : ${p["CFBundleShortVersionString"] ?? "N/A"} (build ${p["CFBundleVersion"] ?? "N/A"})`);
  lines.push(`Executable  : ${p["CFBundleExecutable"] ?? "N/A"}`);
  lines.push(`Min iOS     : ${p["MinimumOSVersion"] ?? "N/A"}`);
  lines.push(`Platform    : ${(p["CFBundleSupportedPlatforms"] as string[] | undefined)?.join(", ") ?? "N/A"}`);

  // URL Schemes (deep links)
  const urlTypes = p["CFBundleURLTypes"] as Array<Record<string, unknown>> | undefined;
  const schemes: string[] = [];
  if (urlTypes) {
    for (const t of urlTypes) {
      const s = t["CFBundleURLSchemes"] as string[] | undefined;
      if (s) schemes.push(...s);
    }
  }
  lines.push(`\n--- URL Schemes (Deep Links) ---`);
  if (schemes.length === 0) {
    lines.push(`  None`);
  } else {
    for (const s of schemes) {
      lines.push(`  ${s}://`);
    }
    if (schemes.some((s) => !s.startsWith("com.") && !s.startsWith("fb") && s.length < 10)) {
      warnings.push(`Short/generic URL scheme detected — may be vulnerable to scheme hijacking`);
    }
  }

  // App Transport Security
  const ats = p["NSAppTransportSecurity"] as Record<string, unknown> | undefined;
  lines.push(`\n--- App Transport Security (ATS) ---`);
  if (!ats) {
    lines.push(`  Default ATS (secure)`);
  } else {
    const allowArbitrary = ats["NSAllowsArbitraryLoads"];
    const allowArbitraryWeb = ats["NSAllowsArbitraryLoadsInWebContent"];
    const allowLocalNet = ats["NSAllowsLocalNetworking"];
    const exceptionDomains = ats["NSExceptionDomains"] as Record<string, unknown> | undefined;

    lines.push(`  NSAllowsArbitraryLoads        : ${allowArbitrary ?? false}`);
    lines.push(`  NSAllowsArbitraryLoadsInWebContent: ${allowArbitraryWeb ?? false}`);
    lines.push(`  NSAllowsLocalNetworking       : ${allowLocalNet ?? false}`);

    if (allowArbitrary === true) {
      warnings.push(`NSAllowsArbitraryLoads=true — all HTTP traffic is allowed, bypassing ATS`);
    }
    if (exceptionDomains) {
      lines.push(`  Exception Domains:`);
      for (const domain of Object.keys(exceptionDomains)) {
        lines.push(`    - ${domain}`);
      }
    }
  }

  // Background modes
  const bgModes = p["UIBackgroundModes"] as string[] | undefined;
  lines.push(`\n--- Background Modes ---`);
  if (!bgModes || bgModes.length === 0) {
    lines.push(`  None`);
  } else {
    for (const m of bgModes) {
      lines.push(`  ${m}`);
    }
    if (bgModes.includes("location")) {
      warnings.push(`Background location mode enabled — app can track location when not in foreground`);
    }
  }

  // Queried schemes (iOS 9+ — what other apps can be opened)
  const queriedSchemes = p["LSApplicationQueriesSchemes"] as string[] | undefined;
  if (queriedSchemes && queriedSchemes.length > 0) {
    lines.push(`\n--- Queried URL Schemes (${queriedSchemes.length}) ---`);
    for (const s of queriedSchemes.slice(0, 20)) {
      lines.push(`  ${s}`);
    }
    if (queriedSchemes.length > 20) {
      lines.push(`  … +${queriedSchemes.length - 20} more`);
    }
  }

  // Warnings summary
  if (warnings.length > 0) {
    lines.push(`\n=== Security Warnings ===`);
    for (const w of warnings) {
      lines.push(`  ⚠ ${w}`);
    }
  } else {
    lines.push(`\n✓ No critical Info.plist security issues detected.`);
  }

  return lines.join("\n");
}
