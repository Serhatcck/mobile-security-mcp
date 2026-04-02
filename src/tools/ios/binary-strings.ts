import { z } from "zod";
import AdmZip from "adm-zip";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parsePlistBuffer } from "./manifest-analyzer.js";

export const iosBinaryStrings = {
  description:
    "Extracts printable strings from an iOS app binary and filters for security-relevant patterns: HTTP/S URLs, API keys, AWS/Firebase/Google credentials, email addresses, and private IP addresses.",

  schema: {
    ipa_path: z
      .string()
      .describe("Absolute path to the IPA file to analyze"),
    filter: z
      .enum(["all", "url", "key", "email", "ip"])
      .default("all")
      .describe(
        "Filter output: all | url (HTTP endpoints) | key (API key patterns) | email | ip (private IPs)"
      ),
    min_length: z
      .number()
      .int()
      .min(4)
      .max(100)
      .default(6)
      .describe("Minimum string length to include (default 6)"),
  },

  handler: async (args: {
    ipa_path: string;
    filter?: "all" | "url" | "key" | "email" | "ip";
    min_length?: number;
  }) => {
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

    const filter = args.filter ?? "all";
    const minLen = args.min_length ?? 6;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-strings-"));
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

      // Detect binary type for diagnostics
      let binaryInfo = "";
      try {
        binaryInfo = execSync(`file "${binaryPath}"`, { stdio: "pipe" }).toString().trim();
      } catch {
        // ignore
      }

      let rawStrings: string[];
      try {
        // -a: scan entire file (not just text sections), useful for Mach-O fat binaries
        const output = execSync(
          `strings -a -n ${minLen} "${binaryPath}"`,
          { stdio: "pipe", maxBuffer: 100 * 1024 * 1024 }
        ).toString();
        rawStrings = output.split("\n").filter(Boolean);
      } catch (e) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error running strings: ${e instanceof Error ? e.message : String(e)}\nIs the 'strings' utility available? (macOS built-in)`,
            },
          ],
        };
      }

      const report = buildReport(rawStrings, filter, binaryInfo);
      return { content: [{ type: "text" as const, text: report }] };
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  },
};

function extractBinary(ipaPath: string, outDir: string): string | null {
  const zip = new AdmZip(ipaPath);
  const entries = zip.getEntries();

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

  const binaryEntry = entries.find((e) => {
    if (executableName) {
      return new RegExp(`^Payload/[^/]+\\.app/${executableName}$`).test(e.entryName);
    }
    return (
      /^Payload\/[^/]+\.app\/[^/]+$/.test(e.entryName) &&
      !e.entryName.match(/\.(plist|nib|car|strings|png|jpg|lproj|storyboard)$/)
    );
  });

  if (!binaryEntry) return null;

  const outPath = path.join(outDir, "binary");
  fs.writeFileSync(outPath, binaryEntry.getData());
  return outPath;
}

// Patterns for filtering
const PATTERNS = {
  url: /https?:\/\/[^\s"'<>]{6,}/gi,
  email: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  ip: /(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)[\d.]{3,}/g,
  // API key patterns: long alphanumeric strings, AWS, Firebase, Google
  key: [
    /AKIA[0-9A-Z]{16}/g,                          // AWS Access Key
    /AIza[0-9A-Za-z\-_]{35}/g,                    // Google API Key
    /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, // UUID-style tokens
    /(?:secret|token|api.?key|apikey|access.?key)['":\s=]+([A-Za-z0-9\-_.]{20,})/gi,
    /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,         // Stripe
    /[0-9a-zA-Z]{40}/g,                           // Generic 40-char hex (e.g. SHA1 tokens)
  ],
};

function buildReport(strings: string[], filter: "all" | "url" | "key" | "email" | "ip", binaryInfo = ""): string {
  const lines: string[] = [];
  lines.push(`=== iOS Binary Strings Analysis ===`);
  if (binaryInfo) lines.push(`Binary type: ${binaryInfo}`);
  lines.push(`Total strings extracted: ${strings.length}`);
  if (binaryInfo.includes("simulator") || binaryInfo.includes("x86_64")) {
    lines.push(`Note: Simulator binary — fewer strings than a device (Ad Hoc) build.`);
  }
  lines.push(``);

  const urls = new Set<string>();
  const emails = new Set<string>();
  const ips = new Set<string>();
  const keys = new Set<string>();

  for (const s of strings) {
    for (const m of s.matchAll(PATTERNS.url)) urls.add(m[0]);
    for (const m of s.matchAll(PATTERNS.email)) emails.add(m[0]);
    for (const m of s.matchAll(PATTERNS.ip)) ips.add(m[0]);

    for (const p of PATTERNS.key) {
      for (const m of s.matchAll(new RegExp(p.source, p.flags))) {
        keys.add(m[0].slice(0, 80)); // cap length
      }
    }
  }

  const printSection = (title: string, items: Set<string>, maxItems = 100) => {
    const arr = [...items].slice(0, maxItems);
    lines.push(`--- ${title} (${items.size}) ---`);
    if (arr.length === 0) {
      lines.push(`  None`);
    } else {
      for (const item of arr) {
        lines.push(`  ${item}`);
      }
      if (items.size > maxItems) {
        lines.push(`  … +${items.size - maxItems} more (increase min_length to reduce noise)`);
      }
    }
    lines.push(``);
  };

  if (filter === "all" || filter === "url") printSection("HTTP/HTTPS URLs", urls);
  if (filter === "all" || filter === "email") printSection("Email Addresses", emails);
  if (filter === "all" || filter === "ip") printSection("Private IP Addresses", ips);
  if (filter === "all" || filter === "key") printSection("Potential API Keys / Tokens", keys, 50);

  // Highlight AWS keys specifically
  const awsKeys = [...keys].filter((k) => k.startsWith("AKIA"));
  if (awsKeys.length > 0) {
    lines.push(`=== ⚠ HIGH RISK: Hardcoded AWS Access Keys Detected ===`);
    for (const k of awsKeys) {
      lines.push(`  ${k}`);
    }
  }

  const googleKeys = [...keys].filter((k) => k.startsWith("AIza"));
  if (googleKeys.length > 0) {
    lines.push(`=== ⚠ Hardcoded Google API Keys Detected ===`);
    for (const k of googleKeys) {
      lines.push(`  ${k}`);
    }
  }

  return lines.join("\n");
}
