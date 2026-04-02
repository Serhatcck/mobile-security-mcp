import { z } from "zod";
import AdmZip from "adm-zip";
import * as fs from "fs";
import { GOOGLE_PATTERNS, scanText, renderResults } from "../shared/patterns.js";
import { parsePlistBuffer } from "./manifest-analyzer.js";

export const iosGoogleServices = {
  description:
    "Extracts Google and Firebase configuration from an IPA. " +
    "Parses GoogleService-Info.plist for API key, project ID, database URL, storage bucket, GCM sender ID, and OAuth client IDs. " +
    "Also applies Google pattern scanning across all text plist and JSON files in the IPA.",

  schema: {
    ipa_path: z.string().describe("Absolute path to the IPA file"),
  },

  handler: async (args: { ipa_path: string }) => {
    if (!fs.existsSync(args.ipa_path)) {
      return { content: [{ type: "text" as const, text: `Error: IPA not found: ${args.ipa_path}` }] };
    }

    let zip: AdmZip;
    try {
      zip = new AdmZip(args.ipa_path);
    } catch (e) {
      return { content: [{ type: "text" as const, text: `Error opening IPA: ${e instanceof Error ? e.message : String(e)}` }] };
    }

    const lines: string[] = [`=== iOS Google Services ===\n`];

    // ── 1. GoogleService-Info.plist ───────────────────────────────────────────
    const gsEntry = zip.getEntries().find((e) =>
      e.entryName.endsWith("GoogleService-Info.plist")
    );

    lines.push(`--- GoogleService-Info.plist ---`);
    if (gsEntry) {
      lines.push(`  Found: ${gsEntry.entryName}\n`);
      try {
        const plist = parsePlistBuffer(gsEntry.getData()) as Record<string, unknown>;
        const FIELDS: [string, string][] = [
          ["BUNDLE_ID",          "Bundle ID"],
          ["PROJECT_ID",         "Project ID"],
          ["GOOGLE_APP_ID",      "Google App ID"],
          ["API_KEY",            "API Key"],
          ["GCM_SENDER_ID",      "GCM Sender ID"],
          ["DATABASE_URL",       "Firebase Database URL"],
          ["STORAGE_BUCKET",     "Storage Bucket"],
          ["CLIENT_ID",          "OAuth Client ID (iOS)"],
          ["REVERSED_CLIENT_ID", "Reversed Client ID"],
          ["SERVER_CLIENT_ID",   "OAuth Server Client ID"],
        ];
        for (const [key, label] of FIELDS) {
          const val = plist[key];
          if (val !== undefined && val !== null && val !== "") {
            lines.push(`  ${label.padEnd(24)}: ${val}`);
          }
        }
      } catch (e) {
        lines.push(`  Could not parse plist: ${e instanceof Error ? e.message : String(e)}`);
      }
    } else {
      lines.push(`  Not found in IPA`);
    }
    lines.push(``);

    // ── 2. Pattern scan across text plist and JSON files ─────────────────────
    let scannedText = "";
    let scannedCount = 0;

    for (const entry of zip.getEntries()) {
      if (entry.isDirectory) continue;
      if (entry.entryName.endsWith("GoogleService-Info.plist")) continue;
      const isText = entry.entryName.endsWith(".json") ||
                     entry.entryName.endsWith(".xml") ||
                     entry.entryName.endsWith(".strings");
      const isPlist = entry.entryName.endsWith(".plist");
      if (!isText && !isPlist) continue;

      try {
        const data = entry.getData();
        if (isPlist) {
          const text = data.toString("utf-8");
          if (text.startsWith("bplist")) continue; // skip binary plists
          scannedText += text + "\n";
        } else {
          scannedText += data.toString("utf-8") + "\n";
        }
        scannedCount++;
      } catch { /* skip */ }
    }

    if (scannedCount > 0) {
      const results = scanText(scannedText, GOOGLE_PATTERNS);
      lines.push(`--- Pattern Scan (${scannedCount} resource file(s)) ---`);
      if (results.size > 0) {
        lines.push(``);
        for (const line of renderResults(results)) lines.push(`  ${line}`);
      } else {
        lines.push(`  No additional Google patterns found`);
      }
      lines.push(``);
    }

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  },
};
