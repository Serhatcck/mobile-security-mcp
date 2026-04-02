import { z } from "zod";
import AdmZip from "adm-zip";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { GOOGLE_PATTERNS, scanText, renderResults } from "../shared/patterns.js";

export const androidGoogleServices = {
  description:
    "Extracts Google and Firebase configuration from an APK. " +
    "Parses google-services.json if present, then scans resources.arsc for string values using the strings command. " +
    "If a smali_folder (apktool output) is provided, parses res/values/strings.xml directly for structured key=value output.",

  schema: {
    apk_path: z.string().describe("Absolute path to the APK file"),
    smali_folder: z
      .string()
      .optional()
      .describe("Absolute path to apktool decompiled output folder (optional — enables structured strings.xml parsing)"),
  },

  handler: async (args: { apk_path: string; smali_folder?: string }) => {
    if (!fs.existsSync(args.apk_path)) {
      return { content: [{ type: "text" as const, text: `Error: APK not found: ${args.apk_path}` }] };
    }

    let zip: AdmZip;
    try {
      zip = new AdmZip(args.apk_path);
    } catch (e) {
      return { content: [{ type: "text" as const, text: `Error opening APK: ${e instanceof Error ? e.message : String(e)}` }] };
    }

    const lines: string[] = [`=== Android Google Services ===\n`];

    // ── 1. google-services.json ──────────────────────────────────────────────
    const gsEntry =
      zip.getEntry("assets/google-services.json") ??
      zip.getEntries().find((e) => e.entryName.endsWith("google-services.json"));

    if (gsEntry) {
      lines.push(`--- google-services.json ---`);
      try {
        const json = JSON.parse(gsEntry.getData().toString("utf-8")) as Record<string, unknown>;
        const proj = json["project_info"] as Record<string, string> | undefined;
        if (proj) {
          if (proj["project_number"]) lines.push(`  Project Number : ${proj["project_number"]}`);
          if (proj["project_id"])     lines.push(`  Project ID     : ${proj["project_id"]}`);
          if (proj["firebase_url"])   lines.push(`  Firebase URL   : ${proj["firebase_url"]}`);
          if (proj["storage_bucket"]) lines.push(`  Storage Bucket : ${proj["storage_bucket"]}`);
        }
        const clients = json["client"] as Array<Record<string, unknown>> | undefined;
        if (clients?.length) {
          lines.push(`  Clients (${clients.length}):`);
          for (const c of clients) {
            const info = c["client_info"] as Record<string, unknown> | undefined;
            const androidInfo = info?.["android_client_info"] as Record<string, string> | undefined;
            const appId = info?.["mobilesdk_app_id"] as string | undefined;
            const pkg = androidInfo?.["package_name"];
            if (pkg)   lines.push(`    Package : ${pkg}`);
            if (appId) lines.push(`    App ID  : ${appId}`);
            const apiKey = (
              (c["services"] as Record<string, unknown> | undefined)?.["api_key"] as
                Array<Record<string, string>> | undefined
            )?.[0]?.["current_key"];
            if (apiKey) lines.push(`    API Key : ${apiKey}`);
            const oauthClients = c["oauth_client"] as Array<Record<string, string>> | undefined;
            for (const oc of oauthClients ?? []) {
              if (oc["client_id"]) lines.push(`    OAuth   : ${oc["client_id"]} (type ${oc["client_type"]})`);
            }
          }
        }
      } catch {
        lines.push(`  Could not parse google-services.json`);
      }
      lines.push(``);
    } else {
      lines.push(`--- google-services.json ---`);
      lines.push(`  Not found in APK assets\n`);
    }

    // ── 2a. smali_folder provided → parse res/values/strings.xml ─────────────
    if (args.smali_folder) {
      const stringsXml = path.join(args.smali_folder, "res", "values", "strings.xml");
      lines.push(`--- res/values/strings.xml (smali folder) ---`);
      if (fs.existsSync(stringsXml)) {
        const xml = fs.readFileSync(stringsXml, "utf-8");
        const found = extractGoogleStringsXml(xml);
        if (found.length) {
          for (const line of found) lines.push(`  ${line}`);
        } else {
          lines.push(`  No Google-related string resources found`);
        }
      } else {
        lines.push(`  strings.xml not found at: ${stringsXml}`);
      }
      lines.push(``);
      return { content: [{ type: "text" as const, text: lines.join("\n") }] };
    }

    // ── 2b. No smali_folder → strings on resources.arsc ──────────────────────
    const arscEntry = zip.getEntry("resources.arsc");
    lines.push(`--- resources.arsc (strings scan) ---`);

    if (!arscEntry) {
      lines.push(`  resources.arsc not found in APK\n`);
    } else {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "arsc-"));
      try {
        const tmpFile = path.join(tmpDir, "resources.arsc");
        fs.writeFileSync(tmpFile, arscEntry.getData());
        const raw = execSync(`strings -a -n 8 "${tmpFile}"`, {
          stdio: "pipe",
          maxBuffer: 50 * 1024 * 1024,
        }).toString();
        const results = scanText(raw, GOOGLE_PATTERNS);
        if (results.size > 0) {
          for (const line of renderResults(results)) lines.push(`  ${line}`);
        } else {
          lines.push(`  No Google patterns found`);
        }
      } catch (e) {
        lines.push(`  strings command failed: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
      lines.push(``);
    }

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  },
};

const GOOGLE_STRING_KEYS = [
  "google_app_id",
  "google_api_key",
  "google_crash_reporting_api_key",
  "google_storage_bucket",
  "project_id",
  "gcm_defaultSenderId",
  "default_web_client_id",
  "firebase_database_url",
  "google_maps_key",
  "google_maps_api_key",
];

function extractGoogleStringsXml(xml: string): string[] {
  const lines: string[] = [];
  for (const key of GOOGLE_STRING_KEYS) {
    const re = new RegExp(`name=["']${key}["'][^>]*>([^<]+)<`, "gi");
    for (const m of xml.matchAll(re)) {
      lines.push(`${key} = ${m[1].trim()}`);
    }
  }
  return lines;
}
