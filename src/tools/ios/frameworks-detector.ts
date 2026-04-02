import { z } from "zod";
import AdmZip from "adm-zip";
import * as fs from "fs";

interface FrameworkInfo {
  category: string;
  description: string;
  risk?: string;
}

const KNOWN_FRAMEWORKS: Record<string, FrameworkInfo> = {
  // Networking
  Alamofire: { category: "Networking", description: "Swift HTTP networking library" },
  AFNetworking: { category: "Networking", description: "Objective-C HTTP networking library" },
  Moya: { category: "Networking", description: "Network abstraction layer over Alamofire" },

  // Analytics & Tracking
  Firebase: { category: "Analytics/Backend", description: "Google Firebase SDK" },
  FirebaseAnalytics: { category: "Analytics", description: "Firebase Analytics" },
  FirebaseAuth: { category: "Authentication", description: "Firebase Authentication" },
  FirebaseFirestore: { category: "Database", description: "Firebase Firestore" },
  FirebaseMessaging: { category: "Push Notifications", description: "Firebase Cloud Messaging" },
  GoogleAnalytics: { category: "Analytics", description: "Google Analytics SDK", risk: "Sends usage data to Google" },
  Amplitude: { category: "Analytics", description: "Amplitude analytics SDK", risk: "User behavior tracking" },
  Mixpanel: { category: "Analytics", description: "Mixpanel analytics", risk: "User behavior tracking" },
  Segment: { category: "Analytics", description: "Segment data pipeline" },
  Intercom: { category: "Customer Support", description: "Intercom in-app messaging" },

  // Crash Reporting
  Crashlytics: { category: "Crash Reporting", description: "Firebase Crashlytics", risk: "Sends crash data (device info, stack traces)" },
  Sentry: { category: "Crash Reporting", description: "Sentry error monitoring" },
  Bugsnag: { category: "Crash Reporting", description: "Bugsnag crash reporting" },
  HockeySDK: { category: "Crash Reporting", description: "HockeyApp SDK (deprecated)" },

  // Attribution & Ads
  Adjust: { category: "Attribution", description: "Mobile attribution SDK", risk: "Cross-app tracking and attribution" },
  AppsFlyer: { category: "Attribution", description: "AppsFlyer attribution SDK", risk: "Cross-app tracking and attribution" },
  Branch: { category: "Deep Linking/Attribution", description: "Branch deep linking", risk: "Tracking" },
  AppLovin: { category: "Ads", description: "AppLovin ad network", risk: "Ad tracking and targeting" },
  GoogleMobileAds: { category: "Ads", description: "Google AdMob", risk: "Ad tracking" },
  FBAudienceNetwork: { category: "Ads", description: "Facebook Audience Network", risk: "Ad tracking with Facebook data" },
  IronSource: { category: "Ads", description: "IronSource mediation" },
  MoPub: { category: "Ads", description: "Twitter MoPub (deprecated)" },
  UnityAds: { category: "Ads", description: "Unity Ads SDK" },

  // Social / Auth
  FacebookSDK: { category: "Social/Auth", description: "Facebook Login & SDK", risk: "Facebook user data sharing" },
  TwitterKit: { category: "Social/Auth", description: "Twitter Kit (deprecated)" },
  GoogleSignIn: { category: "Auth", description: "Google Sign-In" },
  AuthenticationServices: { category: "Auth", description: "Apple Sign In (system framework)" },

  // UI
  SDWebImage: { category: "UI/Image", description: "Async image loading and caching" },
  Kingfisher: { category: "UI/Image", description: "Swift async image loading" },
  Lottie: { category: "UI/Animation", description: "Airbnb Lottie animation" },
  SnapKit: { category: "UI/Layout", description: "Swift Auto Layout DSL" },

  // Data & Storage
  Realm: { category: "Database", description: "Realm mobile database" },
  GRDB: { category: "Database", description: "SQLite library for Swift" },
  KeychainAccess: { category: "Security", description: "Keychain wrapper" },
  CryptoSwift: { category: "Security/Crypto", description: "Swift cryptography library" },

  // Payments
  Stripe: { category: "Payments", description: "Stripe payment SDK" },
  Braintree: { category: "Payments", description: "Braintree/PayPal payments" },

  // Push & Messaging
  OneSignal: { category: "Push Notifications", description: "OneSignal push SDK" },
  Pusher: { category: "Real-time", description: "Pusher WebSocket client" },

  // Security/Obfuscation
  iXGuard: { category: "Obfuscation", description: "iXGuard code obfuscation", risk: "May indicate hardened binary against reverse engineering" },
  DexGuard: { category: "Obfuscation", description: "DexGuard obfuscation" },

  // Google / Firebase (extended)
  GoogleAppMeasurement: { category: "Analytics", description: "Google App Measurement (Firebase Analytics core)", risk: "Sends usage data to Google" },
  GoogleAppMeasurementIdentitySupport: { category: "Analytics", description: "Firebase Analytics identity support" },
  GoogleAdsOnDeviceConversion: { category: "Ads/Attribution", description: "Google Ads on-device conversion tracking", risk: "Ad conversion attribution" },
  GoogleUtilities: { category: "Utilities", description: "Google utilities for Firebase SDKs" },
  GoogleDataTransport: { category: "Analytics", description: "Google data transport layer for Firebase" },
  GoogleMLKit: { category: "Machine Learning", description: "Google ML Kit on-device ML" },

  // Security / Fraud Detection
  AkamaiBMP: { category: "Fraud Detection", description: "Akamai Bot Manager Premier — behavioral biometrics SDK", risk: "Collects device fingerprint, touch patterns, and behavioral data" },
  NuDetectSDK: { category: "Fraud Detection", description: "NuData (Mastercard) behavioral analytics SDK", risk: "Passive biometrics: typing patterns, swipe behavior, device sensors" },
  TrustKit: { category: "Security", description: "TrustKit SSL pinning library" },
  OpenSSL: { category: "Security/Crypto", description: "OpenSSL cryptography" },
  Sift: { category: "Fraud Detection", description: "Sift fraud prevention SDK", risk: "Device fingerprinting and behavior tracking" },
  DataDome: { category: "Fraud Detection", description: "DataDome bot protection SDK" },

  // Networking (extended)
  GRPC: { category: "Networking", description: "gRPC remote procedure call" },
  SocketRocket: { category: "Networking", description: "WebSocket client library" },
  CocoaAsyncSocket: { category: "Networking", description: "Asynchronous socket networking" },

  // Maps & Location
  GoogleMaps: { category: "Maps/Location", description: "Google Maps SDK", risk: "Location data sent to Google" },
  Mapbox: { category: "Maps/Location", description: "Mapbox navigation SDK", risk: "Location data processing" },

  // AR / Media
  ARKit: { category: "AR", description: "Apple ARKit (system framework)" },
  AVFoundation: { category: "Media", description: "Apple AV Foundation (system)" },

  // Testing / Debug (should not appear in prod)
  XCTest: { category: "Testing", description: "Apple XCTest framework", risk: "Testing framework present in release build — debug artifact" },
  OHHTTPStubs: { category: "Testing", description: "HTTP stubbing for tests", risk: "Test-only library found in release build" },
};

export const iosFrameworksDetector = {
  description:
    "Lists all third-party frameworks bundled inside an IPA (from the Frameworks/ directory). Maps known frameworks to categories: networking, analytics, ads, attribution, crash reporting, etc. Highlights privacy-relevant SDKs.",

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

    const report = buildReport(args.ipa_path);
    return { content: [{ type: "text" as const, text: report }] };
  },
};

function buildReport(ipaPath: string): string {
  const zip = new AdmZip(ipaPath);
  const entries = zip.getEntries();

  // Collect unique framework/dylib names from Frameworks/ dir
  const frameworkNames = new Set<string>();
  const dylibNames = new Set<string>();

  for (const entry of entries) {
    const name = entry.entryName;

    // .framework bundles: Payload/<App>.app/Frameworks/<Name>.framework/
    const fwMatch = name.match(/Frameworks\/([^/]+)\.framework\//);
    if (fwMatch) {
      frameworkNames.add(fwMatch[1]);
      continue;
    }

    // Embedded .dylib
    const dylibMatch = name.match(/Frameworks\/([^/]+\.dylib)/);
    if (dylibMatch) {
      dylibNames.add(dylibMatch[1]);
    }
  }

  const lines: string[] = [];
  const privacyRisks: string[] = [];

  lines.push(`=== iOS Frameworks Analysis ===`);
  lines.push(`Frameworks: ${frameworkNames.size}  |  Dylibs: ${dylibNames.size}\n`);

  // Group by category
  const categorized = new Map<string, Array<{ name: string; info: FrameworkInfo }>>();
  const unknown: string[] = [];

  for (const name of frameworkNames) {
    const info = findFrameworkInfo(name);
    if (info) {
      const cat = info.category;
      if (!categorized.has(cat)) categorized.set(cat, []);
      categorized.get(cat)!.push({ name, info });
      if (info.risk) privacyRisks.push(`${name}: ${info.risk}`);
    } else {
      unknown.push(name);
    }
  }

  // Print by category
  for (const [category, items] of [...categorized.entries()].sort()) {
    lines.push(`--- ${category} ---`);
    for (const { name, info } of items) {
      const riskTag = info.risk ? " ⚠" : "";
      lines.push(`  ${name}${riskTag}`);
      lines.push(`    ${info.description}`);
      if (info.risk) lines.push(`    Risk: ${info.risk}`);
    }
    lines.push(``);
  }

  if (unknown.length > 0) {
    lines.push(`--- Unknown / Custom Frameworks (${unknown.length}) ---`);
    for (const name of unknown.sort()) {
      lines.push(`  ${name}`);
    }
    lines.push(``);
  }

  if (dylibNames.size > 0) {
    lines.push(`--- Embedded Dylibs (${dylibNames.size}) ---`);
    for (const name of dylibNames) {
      lines.push(`  ${name}`);
    }
    lines.push(``);
  }

  if (privacyRisks.length > 0) {
    lines.push(`=== Privacy Risk SDKs ===`);
    for (const r of privacyRisks) {
      lines.push(`  ⚠ ${r}`);
    }
  }

  if (frameworkNames.size === 0 && dylibNames.size === 0) {
    lines.push(`No embedded frameworks found. App may use system frameworks only or be statically linked.`);
  }

  return lines.join("\n");
}

function findFrameworkInfo(name: string): FrameworkInfo | null {
  // Exact match
  if (KNOWN_FRAMEWORKS[name]) return KNOWN_FRAMEWORKS[name];

  // Prefix match (e.g. "FirebaseCore" → Firebase)
  for (const [key, info] of Object.entries(KNOWN_FRAMEWORKS)) {
    if (name.startsWith(key) || name.toLowerCase().includes(key.toLowerCase())) {
      return info;
    }
  }

  return null;
}
