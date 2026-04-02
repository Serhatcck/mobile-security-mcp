import { z } from "zod";
import AdmZip from "adm-zip";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { SECRET_PATTERNS, scanText, renderResults } from "../shared/patterns.js";
import { parsePlistBuffer } from "./manifest-analyzer.js";

export const iosSecretsScanner = {
  description:
    "Scans an IPA for hardcoded secrets and API keys. " +
    "Layer 1: scans text resource files (JSON, XML, .strings, XML plists) inside the IPA. " +
    "Layer 2: extracts the app binary and runs the strings command to find constants in compiled code.",

  schema: {
    ipa_path: z.string().describe("Absolute path to the IPA file"),
    min_length: z
      .number()
      .int()
      .min(4)
      .max(100)
      .default(8)
      .describe("Minimum string length for binary extraction (default 8)"),
  },

  handler: async (args: { ipa_path: string; min_length?: number }) => {
    if (!fs.existsSync(args.ipa_path)) {
      return { content: [{ type: "text" as const, text: `Error: IPA not found: ${args.ipa_path}` }] };
    }

    const minLen = args.min_length ?? 8;

    let zip: AdmZip;
    try {
      zip = new AdmZip(args.ipa_path);
    } catch (e) {
      return { content: [{ type: "text" as const, text: `Error opening IPA: ${e instanceof Error ? e.message : String(e)}` }] };
    }

    const lines: string[] = [`=== iOS Secrets Scanner ===\n`];
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

    // ── Layer 1: text resource files ─────────────────────────────────────────
    let resourceText = "";
    let resourceCount = 0;

    for (const entry of zip.getEntries()) {
      if (entry.isDirectory) continue;
      try {
        if (entry.entryName.endsWith(".plist")) {
          const data = entry.getData();
          const text = data.toString("utf-8");
          if (text.startsWith("bplist")) {
            // binary plist — flatten values to text
            const parsed = parsePlistBuffer(data);
            resourceText += flattenValues(parsed) + "\n";
          } else {
            resourceText += text + "\n";
          }
          resourceCount++;
          continue;
        }
        const TEXT_EXT = [".json", ".xml", ".strings", ".txt", ".yaml", ".yml", ".properties"];
        if (!TEXT_EXT.some((ext) => entry.entryName.endsWith(ext))) continue;
        resourceText += entry.getData().toString("utf-8") + "\n";
        resourceCount++;
      } catch { /* skip unreadable */ }
    }

    lines.push(`--- Layer 1: Resource Files (${resourceCount} file(s)) ---`);
    merge(scanText(resourceText, SECRET_PATTERNS));

    // ── Layer 2: app binary via strings ──────────────────────────────────────
    const binaryEntry = findBinary(zip);
    lines.push(`--- Layer 2: App Binary ---`);

    const layer1Snapshot = new Map(allResults);

    if (!binaryEntry) {
      lines.push(`  Could not locate app binary inside IPA\n`);
    } else {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-sec-"));
      try {
        const tmpBin = path.join(tmpDir, "binary");
        fs.writeFileSync(tmpBin, binaryEntry);

        let binaryInfo = "";
        try {
          binaryInfo = execSync(`file "${tmpBin}"`, { stdio: "pipe" })
            .toString()
            .split(":")
            .slice(1)
            .join(":")
            .trim();
        } catch { /* ignore */ }

        if (binaryInfo) lines.push(`  ${binaryInfo}`);

        const raw = execSync(`strings -a -n ${minLen} "${tmpBin}"`, {
          stdio: "pipe",
          maxBuffer: 100 * 1024 * 1024,
        }).toString();
        merge(scanText(raw, SECRET_PATTERNS));
      } catch (e) {
        lines.push(`  strings failed: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    }
    lines.push(``);

    // ── Results ───────────────────────────────────────────────────────────────
    if (allResults.size === 0) {
      lines.push(`✓ No secrets found.`);
    } else {
      // split findings by layer for clarity
      const inResources = new Map([...allResults].filter(([k]) => layer1Snapshot.has(k)));
      const inBinary = new Map(
        [...allResults].map(([k, v]) => {
          const l1 = layer1Snapshot.get(k);
          const newMatches = l1
            ? v.matches.filter((m) => !l1.matches.includes(m))
            : v.matches;
          return [k, { def: v.def, matches: newMatches }] as const;
        }).filter(([, v]) => v.matches.length > 0)
      );

      if (inResources.size > 0) {
        lines.push(`--- Found in Resource Files ---\n`);
        for (const line of renderResults(inResources)) lines.push(line);
        lines.push(``);
      }
      if (inBinary.size > 0) {
        lines.push(`--- Found in Binary (not in resources) ---\n`);
        for (const line of renderResults(inBinary)) lines.push(line);
        lines.push(``);
      }

      lines.push(`--- Summary ---`);
      lines.push(`  Resource files : ${inResources.size} pattern type(s)`);
      lines.push(`  Binary only    : ${inBinary.size} pattern type(s)`);

      const critical = [...allResults.values()].filter((v) => v.def.risk === "CRITICAL");
      if (critical.length > 0) {
        lines.push(`\n⚠ ${critical.length} CRITICAL finding(s) — immediate review required.`);
      }
    }

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  },
};

function findBinary(zip: AdmZip): Buffer | null {
  const entries = zip.getEntries();

  const plistEntry = entries.find((e) =>
    /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.entryName)
  );

  let executableName: string | null = null;
  if (plistEntry) {
    try {
      const parsed = parsePlistBuffer(plistEntry.getData());
      executableName = parsed["CFBundleExecutable"] as string | null;
    } catch { /* ignore */ }
  }

  const binaryEntry = entries.find((e) => {
    if (executableName) {
      return new RegExp(`^Payload/[^/]+\\.app/${executableName}$`).test(e.entryName);
    }
    return (
      /^Payload\/[^/]+\.app\/[^/]+$/.test(e.entryName) &&
      !e.entryName.match(/\.(plist|nib|car|strings|png|jpg|json|dylib)$/)
    );
  });

  return binaryEntry ? binaryEntry.getData() : null;
}

function flattenValues(obj: unknown): string {
  if (typeof obj === "string") return obj;
  if (typeof obj === "number" || typeof obj === "boolean") return String(obj);
  if (Array.isArray(obj)) return obj.map(flattenValues).join("\n");
  if (obj && typeof obj === "object") {
    return Object.values(obj as Record<string, unknown>).map(flattenValues).join("\n");
  }
  return "";
}
