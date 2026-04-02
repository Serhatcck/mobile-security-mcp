#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { androidApiExtractor } from "./tools/android/api-extractor.js";
import { apkManifestAnalyzer } from "./tools/android/manifest-analyzer.js";
import { apkPermissionsChecker } from "./tools/android/permissions-checker.js";
import { androidGoogleServices } from "./tools/android/google-services.js";
import { androidSecretsScanner } from "./tools/android/secrets-scanner.js";
import { iosManifestAnalyzer } from "./tools/ios/manifest-analyzer.js";
import { iosPermissionsChecker } from "./tools/ios/permissions-checker.js";
import { iosEntitlementsChecker } from "./tools/ios/entitlements-checker.js";
import { iosBinaryStrings } from "./tools/ios/binary-strings.js";
import { iosFrameworksDetector } from "./tools/ios/frameworks-detector.js";
import { iosGoogleServices } from "./tools/ios/google-services.js";
import { iosSecretsScanner } from "./tools/ios/secrets-scanner.js";

const server = new McpServer({
  name: "mobile-mcp-security",
  version: "1.0.0",
});

// Android tools
server.tool(
  "android_api_extractor",
  androidApiExtractor.description,
  androidApiExtractor.schema,
  androidApiExtractor.handler
);

server.tool(
  "apk_manifest_analyzer",
  apkManifestAnalyzer.description,
  apkManifestAnalyzer.schema,
  apkManifestAnalyzer.handler
);

server.tool(
  "apk_permissions_checker",
  apkPermissionsChecker.description,
  apkPermissionsChecker.schema,
  apkPermissionsChecker.handler
);

server.tool(
  "android_google_services",
  androidGoogleServices.description,
  androidGoogleServices.schema,
  androidGoogleServices.handler
);

server.tool(
  "android_secrets_scanner",
  androidSecretsScanner.description,
  androidSecretsScanner.schema,
  androidSecretsScanner.handler
);

// iOS tools
server.tool(
  "ios_manifest_analyzer",
  iosManifestAnalyzer.description,
  iosManifestAnalyzer.schema,
  iosManifestAnalyzer.handler
);

server.tool(
  "ios_permissions_checker",
  iosPermissionsChecker.description,
  iosPermissionsChecker.schema,
  iosPermissionsChecker.handler
);

server.tool(
  "ios_entitlements_checker",
  iosEntitlementsChecker.description,
  iosEntitlementsChecker.schema,
  iosEntitlementsChecker.handler
);

server.tool(
  "ios_binary_strings",
  iosBinaryStrings.description,
  iosBinaryStrings.schema,
  iosBinaryStrings.handler
);

server.tool(
  "ios_frameworks_detector",
  iosFrameworksDetector.description,
  iosFrameworksDetector.schema,
  iosFrameworksDetector.handler
);

server.tool(
  "ios_google_services",
  iosGoogleServices.description,
  iosGoogleServices.schema,
  iosGoogleServices.handler
);

server.tool(
  "ios_secrets_scanner",
  iosSecretsScanner.description,
  iosSecretsScanner.schema,
  iosSecretsScanner.handler
);

const transport = new StdioServerTransport();
await server.connect(transport);
