import { z } from "zod";
import AdmZip from "adm-zip";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { SECRET_PATTERNS, scanText, renderResults } from "../shared/patterns.js";

const TEXT_ASSET_EXTENSIONS = [".json", ".xml", ".txt", ".properties", ".yaml", ".yml", ".plist"];

export const androidSecretsScanner = {
  description:
    "Scans an APK for hardcoded secrets and API keys. " +
    "Without smali_folder: runs strings on classes*.dex and resources.arsc, plus scans text assets inside the APK. " +
    "With smali_folder (apktool output): scans res/values/strings.xml and assets as plain text files.",

  schema: {
    apk_path: z.string().describe("Absolute path to the APK file"),
    smali_folder: z
      .string()
      .optional()
      .describe("Absolute path to apktool decompiled output folder (optional)"),
    min_length: z
      .number()
      .int()
      .min(4)
      .max(100)
      .default(8)
      .describe("Minimum string length for strings command (default 8)"),
  },

  handler: async (args: { apk_path: string; smali_folder?: string; min_length?: number }) => {
    if (!fs.existsSync(args.apk_path)) {
      return { content: [{ type: "text" as const, text: `Error: APK not found: ${args.apk_path}` }] };
    }

    const minLen = args.min_length ?? 8;
    let zip: AdmZip;
    try {
      zip = new AdmZip(args.apk_path);
    } catch (e) {
      return { content: [{ type: "text" as const, text: `Error opening APK: ${e instanceof Error ? e.message : String(e)}` }] };
    }

    const lines: string[] = [`=== Android Secrets Scanner ===\n`];
    const allResults = new Map<string, { def: (typeof SECRET_PATTERNS)[0]; matches: string[] }>();

    const merge = (results: ReturnType<typeof scanText>) => {
      for (const [name, entry] of results) {
        const existing = allResults.get(name);
        if (existing) {
          for (const m of entry.matches) {
            if (!existing.matches.includes(m)) existing.matches.push(m);
          }
        } else {
          allResults.set(name, { ...entry });
        }
      }
    };

    if (args.smali_folder) {
      // ── smali_folder path: plain text files ──────────────────────────────
      lines.push(`Mode: smali folder (${args.smali_folder})\n`);

      // res/values/strings.xml
      const stringsXml = path.join(args.smali_folder, "res", "values", "strings.xml");
      if (fs.existsSync(stringsXml)) {
        merge(scanText(fs.readFileSync(stringsXml, "utf-8"), SECRET_PATTERNS));
        lines.push(`  Scanned: res/values/strings.xml`);
      }

      // assets/**
      const assetsDir = path.join(args.smali_folder, "assets");
      if (fs.existsSync(assetsDir)) {
        const assetFiles = walkDir(assetsDir).filter((f) =>
          TEXT_ASSET_EXTENSIONS.some((ext) => f.endsWith(ext))
        );
        for (const f of assetFiles) {
          try { merge(scanText(fs.readFileSync(f, "utf-8"), SECRET_PATTERNS)); } catch { /* skip */ }
        }
        lines.push(`  Scanned: assets/ (${assetFiles.length} files)`);
      }
      lines.push(``);
    } else {
      // ── Raw APK path: strings on binaries + text assets ───────────────────
      lines.push(`Mode: raw APK (strings on DEX + resources.arsc + text assets)\n`);

      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "apk-sec-"));
      try {
        // DEX files
        const dexEntries = zip.getEntries().filter(
          (e) => !e.isDirectory && /^classes\d*\.dex$/.test(e.entryName)
        );
        for (const entry of dexEntries) {
          const tmp = path.join(tmpDir, entry.entryName);
          fs.writeFileSync(tmp, entry.getData());
          try {
            const out = execSync(`strings -a -n ${minLen} "${tmp}"`, {
              stdio: "pipe", maxBuffer: 100 * 1024 * 1024,
            }).toString();
            merge(scanText(out, SECRET_PATTERNS));
          } catch { /* strings failed */ }
        }
        lines.push(`  Scanned: ${dexEntries.length} DEX file(s)`);

        // resources.arsc
        const arscEntry = zip.getEntry("resources.arsc");
        if (arscEntry) {
          const tmp = path.join(tmpDir, "resources.arsc");
          fs.writeFileSync(tmp, arscEntry.getData());
          try {
            const out = execSync(`strings -a -n ${minLen} "${tmp}"`, {
              stdio: "pipe", maxBuffer: 50 * 1024 * 1024,
            }).toString();
            merge(scanText(out, SECRET_PATTERNS));
          } catch { /* strings failed */ }
          lines.push(`  Scanned: resources.arsc`);
        }

        // Text assets inside ZIP
        let assetCount = 0;
        for (const entry of zip.getEntries()) {
          if (entry.isDirectory) continue;
          if (!entry.entryName.startsWith("assets/")) continue;
          if (!TEXT_ASSET_EXTENSIONS.some((ext) => entry.entryName.endsWith(ext))) continue;
          try {
            merge(scanText(entry.getData().toString("utf-8"), SECRET_PATTERNS));
            assetCount++;
          } catch { /* skip */ }
        }
        if (assetCount > 0) lines.push(`  Scanned: ${assetCount} text asset(s)`);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
      lines.push(``);
    }

    // ── Results ───────────────────────────────────────────────────────────────
    if (allResults.size === 0) {
      lines.push(`✓ No secrets found.`);
    } else {
      lines.push(`--- Findings (${allResults.size} pattern type(s)) ---\n`);
      for (const line of renderResults(allResults)) lines.push(line);

      const critical = [...allResults.values()].filter((v) => v.def.risk === "CRITICAL");
      if (critical.length > 0) {
        lines.push(`\n⚠ ${critical.length} CRITICAL finding(s) — immediate review required.`);
      }
    }

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  },
};

function walkDir(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...walkDir(full));
    else results.push(full);
  }
  return results;
}
