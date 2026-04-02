import { z } from "zod";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

const DANGEROUS_PERMISSIONS = new Set([
  "READ_SMS",
  "SEND_SMS",
  "RECEIVE_SMS",
  "READ_MMS",
  "WRITE_SMS",
  "RECEIVE_MMS",
  "READ_CONTACTS",
  "WRITE_CONTACTS",
  "GET_ACCOUNTS",
  "RECORD_AUDIO",
  "PROCESS_OUTGOING_CALLS",
  "READ_CALL_LOG",
  "WRITE_CALL_LOG",
  "CALL_PHONE",
  "ADD_VOICEMAIL",
  "USE_SIP",
  "ACCESS_FINE_LOCATION",
  "ACCESS_COARSE_LOCATION",
  "ACCESS_BACKGROUND_LOCATION",
  "CAMERA",
  "READ_EXTERNAL_STORAGE",
  "WRITE_EXTERNAL_STORAGE",
  "MANAGE_EXTERNAL_STORAGE",
  "READ_PHONE_STATE",
  "READ_PHONE_NUMBERS",
  "USE_BIOMETRIC",
  "USE_FINGERPRINT",
  "BODY_SENSORS",
  "ACTIVITY_RECOGNITION",
  "ACCESS_WIFI_STATE",
  "CHANGE_WIFI_STATE",
  "BLUETOOTH_CONNECT",
  "BLUETOOTH_SCAN",
  "NFC",
  "READ_CALENDAR",
  "WRITE_CALENDAR",
  "PACKAGE_USAGE_STATS",
  "BIND_DEVICE_ADMIN",
  "INSTALL_PACKAGES",
  "DELETE_PACKAGES",
]);

export const apkPermissionsChecker = {
  description:
    "Extracts and categorizes permissions requested by an APK. Dangerous permissions (those that grant access to sensitive user data or device features) are highlighted separately.",

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

    const permissions = extractPermissions(args.apk_path);
    if (permissions === null) {
      return {
        content: [
          {
            type: "text" as const,
            text: "Error: Could not extract permissions. Install aapt or apktool.",
          },
        ],
      };
    }

    const report = buildReport(permissions);
    return { content: [{ type: "text" as const, text: report }] };
  },
};

function extractPermissions(apkPath: string): string[] | null {
  // Try aapt
  for (const cmd of [`aapt dump permissions "${apkPath}"`, `aapt2 dump permissions "${apkPath}"`]) {
    try {
      const output = execSync(cmd, { stdio: "pipe" }).toString();
      const perms: string[] = [];
      for (const line of output.split("\n")) {
        const m = line.match(/uses-permission:\s*name='([^']+)'/);
        if (m) perms.push(m[1]);
      }
      if (perms.length > 0) return perms;
    } catch {
      // try next
    }
  }

  // Fallback: apktool + parse manifest XML
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "apktool-perms-"));
  try {
    execSync(`apktool d "${apkPath}" -o "${tmpDir}" -f`, { stdio: "pipe" });
    const manifestPath = path.join(tmpDir, "AndroidManifest.xml");
    if (fs.existsSync(manifestPath)) {
      const xml = fs.readFileSync(manifestPath, "utf-8");
      const perms: string[] = [];
      for (const m of xml.matchAll(/uses-permission[^>]+android:name="([^"]+)"/g)) {
        perms.push(m[1]);
      }
      return perms;
    }
  } catch {
    // fall through
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return null;
}

function buildReport(permissions: string[]): string {
  const dangerous: string[] = [];
  const normal: string[] = [];

  for (const perm of permissions) {
    const shortName = perm.replace("android.permission.", "");
    if (DANGEROUS_PERMISSIONS.has(shortName)) {
      dangerous.push(perm);
    } else {
      normal.push(perm);
    }
  }

  const lines: string[] = [];
  lines.push(`=== APK Permissions Analysis ===`);
  lines.push(`Total permissions: ${permissions.length}\n`);

  lines.push(`--- Dangerous Permissions (${dangerous.length}) ---`);
  if (dangerous.length === 0) {
    lines.push(`  ✓ None`);
  } else {
    for (const p of dangerous) {
      lines.push(`  ⚠ ${p}`);
    }
  }

  lines.push(`\n--- Normal Permissions (${normal.length}) ---`);
  if (normal.length === 0) {
    lines.push(`  None`);
  } else {
    for (const p of normal) {
      lines.push(`    ${p}`);
    }
  }

  if (dangerous.length > 0) {
    lines.push(`\n=== Risk Summary ===`);
    lines.push(`  ${dangerous.length} dangerous permission(s) detected.`);
    if (dangerous.some((p) => p.includes("READ_SMS") || p.includes("SEND_SMS") || p.includes("RECEIVE_SMS"))) {
      lines.push(`  ⚠ SMS permissions can enable toll fraud and message interception.`);
    }
    if (dangerous.some((p) => p.includes("LOCATION"))) {
      lines.push(`  ⚠ Location permissions enable user tracking.`);
    }
    if (dangerous.some((p) => p.includes("RECORD_AUDIO") || p.includes("CAMERA"))) {
      lines.push(`  ⚠ Microphone/Camera permissions allow covert recording.`);
    }
    if (dangerous.some((p) => p.includes("INSTALL_PACKAGES"))) {
      lines.push(`  ⚠ INSTALL_PACKAGES allows the app to install arbitrary APKs — high risk.`);
    }
  }

  return lines.join("\n");
}
