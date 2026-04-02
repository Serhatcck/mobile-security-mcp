import { z } from "zod";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export const androidApiExtractor = {
  description:
    "Decompiles an APK and extracts Retrofit HTTP annotations and OkHttp3 endpoints from smali bytecode. Outputs a list of API endpoints or a Postman collection.",

  schema: {
    apk_path: z
      .string()
      .optional()
      .describe("Absolute path to the APK file to decompile and analyze"),
    smali_folder: z
      .string()
      .optional()
      .describe(
        "Absolute path to an already-decompiled smali folder (skips apktool step)"
      ),
    output_format: z
      .enum(["txt", "postman"])
      .default("txt")
      .describe("Output format: plain text list or Postman collection JSON"),
  },

  handler: async (args: {
    apk_path?: string;
    smali_folder?: string;
    output_format?: "txt" | "postman";
  }) => {
    const outputFormat = args.output_format ?? "txt";
    let smaliFolder = args.smali_folder;
    let tmpDir: string | null = null;

    try {
      // Step 1: decompile APK if no smali folder provided
      if (!smaliFolder) {
        if (!args.apk_path) {
          return {
            content: [
              {
                type: "text" as const,
                text: "Error: provide either apk_path or smali_folder.",
              },
            ],
          };
        }
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

        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "apktool-"));
        try {
          execSync(`apktool d "${args.apk_path}" -o "${tmpDir}" -f`, {
            stdio: "pipe",
          });
        } catch (e) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Error: apktool failed. Is apktool installed?\n${e instanceof Error ? e.message : String(e)}`,
              },
            ],
          };
        }
        smaliFolder = tmpDir;
      }

      if (!fs.existsSync(smaliFolder)) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: smali folder not found: ${smaliFolder}`,
            },
          ],
        };
      }

      // Step 2: walk smali files and extract patterns
      const annotationPattern =
        /\.annotation runtime Lretrofit2\/http\/([A-Z]+);([\s\S]*?)\.end annotation/gs;
      const okhttp3Pattern = /\.field .*? Lokhttp3\//g;

      const httpAnnotations: Array<[string, string]> = [];
      const okhttp3Variables: string[] = [];

      walkSmali(smaliFolder, (filePath) => {
        const content = fs.readFileSync(filePath, "utf-8");

        for (const match of content.matchAll(annotationPattern)) {
          httpAnnotations.push([match[1].trim(), match[2].trim()]);
        }
        for (const match of content.matchAll(okhttp3Pattern)) {
          okhttp3Variables.push(match[0].trim());
        }
      });

      // Step 3: build output
      let output: string;
      if (outputFormat === "postman") {
        output = buildPostmanOutput(httpAnnotations);
      } else {
        output = buildTxtOutput(httpAnnotations, okhttp3Variables);
      }

      return { content: [{ type: "text" as const, text: output }] };
    } finally {
      if (tmpDir && fs.existsSync(tmpDir)) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    }
  },
};

function walkSmali(dir: string, callback: (filePath: string) => void): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkSmali(full, callback);
    } else if (entry.isFile() && entry.name.endsWith(".smali")) {
      callback(full);
    }
  }
}

function buildTxtOutput(
  annotations: Array<[string, string]>,
  okhttp3Vars: string[]
): string {
  if (annotations.length === 0 && okhttp3Vars.length === 0) {
    return "No Retrofit annotations or OkHttp3 fields found in the smali code.";
  }

  const lines: string[] = [];

  if (annotations.length > 0) {
    lines.push(`=== Retrofit HTTP Annotations (${annotations.length} found) ===\n`);
    for (const [method, value] of annotations) {
      // Extract the url value from smali annotation body
      const urlMatch = value.match(/value = "([^"]+)"/);
      const url = urlMatch ? urlMatch[1] : value.replace(/\s+/g, " ");
      lines.push(`  [${method}] ${url}`);
    }
  }

  if (okhttp3Vars.length > 0) {
    lines.push(`\n=== OkHttp3 Fields (${okhttp3Vars.length} found) ===\n`);
    for (const v of okhttp3Vars) {
      lines.push(`  ${v}`);
    }
  }

  return lines.join("\n");
}

function buildPostmanOutput(annotations: Array<[string, string]>): string {
  const items = annotations.map(([method, value]) => {
    const urlMatch = value.match(/value = "([^"]+)"/);
    const endpoint = urlMatch ? urlMatch[1] : value.replace(/\s+/g, " ");
    return {
      name: `${method} ${endpoint}`,
      request: {
        method,
        header: [],
        url: {
          raw: "{{base_url}}" + endpoint,
          host: ["{{base_url}}"],
          path: endpoint
            .split("/")
            .filter(Boolean)
            .map((p: string) => (p.startsWith("{") ? p : p)),
        },
      },
    };
  });

  const collection = {
    info: {
      name: "Retrofit Analysis — mobile-mcp-security",
      schema:
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    item: items,
  };

  return JSON.stringify(collection, null, 2);
}
