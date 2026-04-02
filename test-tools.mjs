#!/usr/bin/env node
/**
 * MCP tool tester — her tool'u sırayla çağırır ve sonucu yazdırır.
 * MCP Inspector'ın yaptığının aynısını programmatik olarak yapar.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(__dirname, "dist/index.js");
const APK = path.join(__dirname, "example.apk");
const IPA = path.join(__dirname, "example.ipa");

const SEP = "═".repeat(70);
const SEP2 = "─".repeat(70);

function header(title) {
  console.log(`\n${SEP}`);
  console.log(`  ${title}`);
  console.log(SEP);
}

function result(text) {
  // Print first 80 lines max to keep output readable
  const lines = text.split("\n");
  const preview = lines.slice(0, 80).join("\n");
  console.log(preview);
  if (lines.length > 80) {
    console.log(`\n  … [${lines.length - 80} more lines truncated]`);
  }
}

async function main() {
  console.log("Connecting to mobile-mcp-security server…");

  const transport = new StdioClientTransport({
    command: "node",
    args: [SERVER],
  });

  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(transport);

  // List all tools
  const { tools } = await client.listTools();
  console.log(`\nServer started. ${tools.length} tools registered:\n`);
  for (const t of tools) {
    console.log(`  • ${t.name}`);
  }

  const call = async (name, args) => {
    try {
      const res = await client.callTool({ name, arguments: args });
      return res.content?.[0]?.text ?? JSON.stringify(res);
    } catch (e) {
      return `ERROR: ${e.message}`;
    }
  };

  // ─── Android Tools ───────────────────────────────────────────────

  header("1/8  android_api_extractor  (format: txt)");
  result(await call("android_api_extractor", { apk_path: APK, output_format: "txt" }));

  header("2/8  android_api_extractor  (format: postman)");
  result(await call("android_api_extractor", { apk_path: APK, output_format: "postman" }));

  header("3/8  apk_manifest_analyzer");
  result(await call("apk_manifest_analyzer", { apk_path: APK }));

  header("4/8  apk_permissions_checker");
  result(await call("apk_permissions_checker", { apk_path: APK }));

  // ─── iOS Tools ───────────────────────────────────────────────────

  header("5/8  ios_manifest_analyzer");
  result(await call("ios_manifest_analyzer", { ipa_path: IPA }));

  header("6/8  ios_permissions_checker");
  result(await call("ios_permissions_checker", { ipa_path: IPA }));

  header("7/8  ios_entitlements_checker");
  result(await call("ios_entitlements_checker", { ipa_path: IPA }));

  header("8/8  ios_frameworks_detector");
  result(await call("ios_frameworks_detector", { ipa_path: IPA }));

  // binary_strings ayrı — büyük binary, filter: url
  header("BONUS  ios_binary_strings  (filter: url)");
  result(await call("ios_binary_strings", { ipa_path: IPA, filter: "url", min_length: 8 }));

  header("BONUS  ios_binary_strings  (filter: key)");
  result(await call("ios_binary_strings", { ipa_path: IPA, filter: "key", min_length: 10 }));

  console.log(`\n${SEP}`);
  console.log("  Tüm tool'lar test edildi.");
  console.log(SEP);

  await client.close();
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
