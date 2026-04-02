import { z } from "zod";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export const apkManifestAnalyzer = {
  description:
    "Parses AndroidManifest.xml from an APK. Extracts package info, activities, services, receivers, intent filters, and highlights security-relevant flags like exported components, debuggable, and allowBackup.",

  schema: {
    apk_path: z
      .string()
      .describe("Absolute path to the APK file to analyze"),
  },

  handler: async (args: { apk_path: string }) => {
    if (!fs.existsSync(args.apk_path)) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error: APK file not found: ${args.apk_path}`,
          },
        ],
      };
    }

    // Try aapt first (faster, no full decompile needed), fallback to apktool
    let manifestXml = extractManifestViaAapt(args.apk_path);
    let source = "aapt";

    if (!manifestXml) {
      const result = extractManifestViaApktool(args.apk_path);
      if (!result) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Error: Could not extract AndroidManifest.xml. Install apktool or aapt.",
            },
          ],
        };
      }
      manifestXml = result;
      source = "apktool";
    }

    const report = analyzeManifest(manifestXml, source);
    return { content: [{ type: "text" as const, text: report }] };
  },
};

function extractManifestViaAapt(apkPath: string): string | null {
  try {
    const output = execSync(`aapt dump xmltree "${apkPath}" AndroidManifest.xml`, {
      stdio: "pipe",
    }).toString();
    return output;
  } catch {
    return null;
  }
}

function extractManifestViaApktool(apkPath: string): string | null {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "apktool-manifest-"));
  try {
    execSync(`apktool d "${apkPath}" -o "${tmpDir}" -f`, { stdio: "pipe" });
    const manifestPath = path.join(tmpDir, "AndroidManifest.xml");
    if (fs.existsSync(manifestPath)) {
      return fs.readFileSync(manifestPath, "utf-8");
    }
    return null;
  } catch {
    return null;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function analyzeManifest(content: string, source: string): string {
  const lines: string[] = [];
  const warnings: string[] = [];

  lines.push(`=== Android Manifest Analysis ===`);
  lines.push(`Source: ${source}\n`);

  // Package & version
  const packageMatch = content.match(/package(?:="| A=")([\w.]+)/);
  const versionCodeMatch = content.match(/versionCode(?:="| A=")(\d+)/);
  const versionNameMatch = content.match(/versionName(?:="| A=")([\w.\-]+)/);

  if (packageMatch) lines.push(`Package Name : ${packageMatch[1]}`);
  if (versionCodeMatch) lines.push(`Version Code : ${versionCodeMatch[1]}`);
  if (versionNameMatch) lines.push(`Version Name : ${versionNameMatch[1]}`);

  // Security flags on <application>
  lines.push(`\n--- Security Flags ---`);

  const debuggable = /android:debuggable(?:="| A=")true/i.test(content) ||
    /debuggable.*True/i.test(content);
  const allowBackup = /android:allowBackup(?:="| A=")true/i.test(content) ||
    /allowBackup.*True/i.test(content);
  const cleartext = /android:usesCleartextTraffic(?:="| A=")true/i.test(content) ||
    /usesCleartextTraffic.*True/i.test(content);
  const networkSecurity = /android:networkSecurityConfig/i.test(content);

  lines.push(`  debuggable          : ${debuggable ? "TRUE  ⚠ DANGER" : "false"}`);
  lines.push(`  allowBackup         : ${allowBackup ? "TRUE  ⚠ WARNING" : "false"}`);
  lines.push(`  usesCleartextTraffic: ${cleartext ? "TRUE  ⚠ DANGER" : "false"}`);
  lines.push(`  networkSecurityConfig: ${networkSecurity ? "present" : "not set"}`);

  if (debuggable) warnings.push("debuggable=true — app can be attached with a debugger in production");
  if (allowBackup) warnings.push("allowBackup=true — app data can be extracted via adb backup without root");
  if (cleartext) warnings.push("usesCleartextTraffic=true — app allows unencrypted HTTP traffic");

  // Components
  const activityPattern = /(?:activity|activity-alias)[^>]*?android:name(?:="| A=")([\w.]+)/g;
  const servicePattern = /service[^>]*?android:name(?:="| A=")([\w.]+)/g;
  const receiverPattern = /receiver[^>]*?android:name(?:="| A=")([\w.]+)/g;
  const providerPattern = /provider[^>]*?android:name(?:="| A=")([\w.]+)/g;

  const activities = [...content.matchAll(activityPattern)].map((m) => m[1]);
  const services = [...content.matchAll(servicePattern)].map((m) => m[1]);
  const receivers = [...content.matchAll(receiverPattern)].map((m) => m[1]);
  const providers = [...content.matchAll(providerPattern)].map((m) => m[1]);

  lines.push(`\n--- Components ---`);
  lines.push(`  Activities (${activities.length}): ${activities.slice(0, 5).join(", ")}${activities.length > 5 ? ` … +${activities.length - 5} more` : ""}`);
  lines.push(`  Services   (${services.length}): ${services.slice(0, 5).join(", ")}${services.length > 5 ? ` … +${services.length - 5} more` : ""}`);
  lines.push(`  Receivers  (${receivers.length}): ${receivers.slice(0, 5).join(", ")}${receivers.length > 5 ? ` … +${receivers.length - 5} more` : ""}`);
  lines.push(`  Providers  (${providers.length}): ${providers.slice(0, 5).join(", ")}${providers.length > 5 ? ` … +${providers.length - 5} more` : ""}`);

  // Exported components
  const exportedPattern = /android:exported(?:="| A=")true[\s\S]{0,200}?android:name(?:="| A=")([\w.]+)/g;
  const exported = [...content.matchAll(exportedPattern)].map((m) => m[1]);

  lines.push(`\n--- Exported Components (android:exported="true") ---`);
  if (exported.length === 0) {
    lines.push(`  None detected`);
  } else {
    lines.push(`  ⚠ ${exported.length} exported component(s):`);
    for (const e of exported) {
      lines.push(`    - ${e}`);
    }
    warnings.push(`${exported.length} component(s) with android:exported="true" — potential attack surface`);
  }

  // Intent filters (implies exported if not explicitly set to false in Android 12+)
  const intentFilterPattern = /<intent-filter[\s\S]*?<action[\s\S]*?android:name(?:="| A=")([\w.]+)/g;
  const intentActions = [...content.matchAll(intentFilterPattern)].map((m) => m[1]);

  if (intentActions.length > 0) {
    lines.push(`\n--- Intent Filters (${intentActions.length} actions) ---`);
    for (const action of [...new Set(intentActions)].slice(0, 15)) {
      lines.push(`    - ${action}`);
    }
  }

  // Summary
  if (warnings.length > 0) {
    lines.push(`\n=== Security Warnings ===`);
    for (const w of warnings) {
      lines.push(`  ⚠ ${w}`);
    }
  } else {
    lines.push(`\n✓ No critical manifest security issues detected.`);
  }

  return lines.join("\n");
}
