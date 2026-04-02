import { z } from "zod";
import * as fs from "fs";
import { extractInfoPlist } from "./manifest-analyzer.js";

interface PermissionDef {
  key: string;
  label: string;
  risk: "HIGH" | "MEDIUM" | "LOW";
  reason: string;
}

const PERMISSION_KEYS: PermissionDef[] = [
  { key: "NSCameraUsageDescription", label: "Camera", risk: "HIGH", reason: "Can capture photos/video" },
  { key: "NSMicrophoneUsageDescription", label: "Microphone", risk: "HIGH", reason: "Can record audio" },
  { key: "NSLocationAlwaysAndWhenInUseUsageDescription", label: "Location (Always)", risk: "HIGH", reason: "Tracks location at all times" },
  { key: "NSLocationAlwaysUsageDescription", label: "Location (Always — legacy)", risk: "HIGH", reason: "Tracks location at all times" },
  { key: "NSLocationWhenInUseUsageDescription", label: "Location (When In Use)", risk: "MEDIUM", reason: "Tracks location while app is open" },
  { key: "NSContactsUsageDescription", label: "Contacts", risk: "HIGH", reason: "Access to personal contact list" },
  { key: "NSPhotoLibraryUsageDescription", label: "Photo Library (Read)", risk: "HIGH", reason: "Can read all photos and videos" },
  { key: "NSPhotoLibraryAddUsageDescription", label: "Photo Library (Write)", risk: "MEDIUM", reason: "Can save to photo library" },
  { key: "NSFaceIDUsageDescription", label: "Face ID", risk: "HIGH", reason: "Biometric authentication" },
  { key: "NSHealthShareUsageDescription", label: "Health Data (Read)", risk: "HIGH", reason: "Access to sensitive health data" },
  { key: "NSHealthUpdateUsageDescription", label: "Health Data (Write)", risk: "HIGH", reason: "Can modify health records" },
  { key: "NSMotionUsageDescription", label: "Motion & Fitness", risk: "MEDIUM", reason: "Accelerometer and activity data" },
  { key: "NSBluetoothAlwaysUsageDescription", label: "Bluetooth (Always)", risk: "MEDIUM", reason: "Can communicate with BT devices" },
  { key: "NSBluetoothPeripheralUsageDescription", label: "Bluetooth (Peripheral)", risk: "MEDIUM", reason: "Legacy BT permission" },
  { key: "NSCalendarsUsageDescription", label: "Calendars", risk: "MEDIUM", reason: "Access to calendar events" },
  { key: "NSRemindersUsageDescription", label: "Reminders", risk: "LOW", reason: "Access to reminders" },
  { key: "NSSpeechRecognitionUsageDescription", label: "Speech Recognition", risk: "HIGH", reason: "Voice data sent to Apple servers" },
  { key: "NSUserTrackingUsageDescription", label: "App Tracking (ATT)", risk: "MEDIUM", reason: "Cross-app advertising tracking" },
  { key: "NSLocalNetworkUsageDescription", label: "Local Network", risk: "MEDIUM", reason: "Can discover local network devices" },
  { key: "NFCReaderUsageDescription", label: "NFC", risk: "MEDIUM", reason: "Near-field communication access" },
  { key: "NSHomeKitUsageDescription", label: "HomeKit", risk: "MEDIUM", reason: "Smart home device access" },
  { key: "NSAppleMusicUsageDescription", label: "Media Library", risk: "LOW", reason: "Access to music library" },
  { key: "NSLocationTemporaryUsageDescriptionDictionary", label: "Temporary Location", risk: "LOW", reason: "One-time location access" },
];

export const iosPermissionsChecker = {
  description:
    "Extracts privacy permission usage descriptions from an IPA's Info.plist. Each permission is categorized by risk level (HIGH / MEDIUM / LOW) with an explanation.",

  schema: {
    ipa_path: z
      .string()
      .describe("Absolute path to the IPA file to analyze"),
  },

  handler: async (args: { ipa_path: string }) => {
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

    let plistData: Record<string, unknown>;
    try {
      plistData = extractInfoPlist(args.ipa_path);
    } catch (e) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error extracting Info.plist: ${e instanceof Error ? e.message : String(e)}`,
          },
        ],
      };
    }

    const report = buildReport(plistData);
    return { content: [{ type: "text" as const, text: report }] };
  },
};

function buildReport(p: Record<string, unknown>): string {
  const found: Array<{ def: PermissionDef; description: string }> = [];

  for (const def of PERMISSION_KEYS) {
    const val = p[def.key];
    if (val !== undefined && val !== null) {
      found.push({ def, description: String(val) });
    }
  }

  // Unknown NS*UsageDescription keys
  const knownKeys = new Set(PERMISSION_KEYS.map((k) => k.key));
  const unknownPerms: Array<{ key: string; value: string }> = [];
  for (const [key, value] of Object.entries(p)) {
    if (key.endsWith("UsageDescription") && !knownKeys.has(key)) {
      unknownPerms.push({ key, value: String(value) });
    }
  }

  const lines: string[] = [];
  lines.push(`=== iOS Permissions Analysis ===`);
  lines.push(`Found ${found.length + unknownPerms.length} permission declaration(s)\n`);

  const high = found.filter((f) => f.def.risk === "HIGH");
  const medium = found.filter((f) => f.def.risk === "MEDIUM");
  const low = found.filter((f) => f.def.risk === "LOW");

  const printGroup = (
    label: string,
    items: Array<{ def: PermissionDef; description: string }>
  ) => {
    lines.push(`--- ${label} Risk (${items.length}) ---`);
    if (items.length === 0) {
      lines.push(`  None\n`);
      return;
    }
    for (const { def, description } of items) {
      lines.push(`  [${def.risk}] ${def.label}`);
      lines.push(`        Key    : ${def.key}`);
      lines.push(`        Why    : ${def.reason}`);
      lines.push(`        Msg    : "${description}"`);
    }
    lines.push(``);
  };

  printGroup("HIGH", high);
  printGroup("MEDIUM", medium);
  printGroup("LOW", low);

  if (unknownPerms.length > 0) {
    lines.push(`--- Unknown/Custom Permissions (${unknownPerms.length}) ---`);
    for (const { key, value } of unknownPerms) {
      lines.push(`  ${key}: "${value}"`);
    }
    lines.push(``);
  }

  if (found.length === 0 && unknownPerms.length === 0) {
    lines.push(`✓ No privacy usage descriptions found in Info.plist.`);
  }

  return lines.join("\n");
}
