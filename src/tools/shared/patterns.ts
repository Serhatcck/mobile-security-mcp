export interface PatternDef {
  name: string;
  pattern: RegExp;
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
}

export const GOOGLE_PATTERNS: PatternDef[] = [
  {
    name: "Google API Key",
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    risk: "HIGH",
    description: "Google API key (Maps, Firebase, etc.)",
  },
  {
    name: "Firebase Realtime DB URL",
    pattern: /https:\/\/[a-z0-9][a-z0-9\-]{1,61}(?:-default-rtdb)?\.firebaseio\.com/g,
    risk: "HIGH",
    description: "Firebase Realtime Database endpoint",
  },
  {
    name: "Firebase Storage Bucket",
    pattern: /[a-z0-9][a-z0-9\-]{3,62}\.appspot\.com/g,
    risk: "MEDIUM",
    description: "Firebase / GCP Storage bucket",
  },
  {
    name: "GCP Storage URL",
    pattern: /https:\/\/storage\.googleapis\.com\/[a-z0-9\-._/]{3,}/g,
    risk: "MEDIUM",
    description: "Google Cloud Storage URL",
  },
  {
    name: "Google OAuth Client ID",
    pattern: /[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com/g,
    risk: "MEDIUM",
    description: "Google OAuth 2.0 client ID",
  },
];

export const SECRET_PATTERNS: PatternDef[] = [
  {
    name: "Google API Key",
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    risk: "HIGH",
    description: "Google API key",
  },
  {
    name: "AWS Access Key ID",
    pattern: /AKIA[0-9A-Z]{16}/g,
    risk: "CRITICAL",
    description: "AWS Access Key ID",
  },
  {
    name: "AWS Secret Access Key",
    pattern: /(?:aws.?secret|secret.?access.?key)['":\s=]+['"]?([A-Za-z0-9\/+]{40})['"]?/gi,
    risk: "CRITICAL",
    description: "AWS Secret Access Key",
  },
  {
    name: "Stripe Secret Key",
    pattern: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
    risk: "CRITICAL",
    description: "Stripe secret key — server-side key in client",
  },
  {
    name: "Stripe Publishable Key",
    pattern: /pk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
    risk: "MEDIUM",
    description: "Stripe publishable key",
  },
  {
    name: "GitHub Token",
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    risk: "CRITICAL",
    description: "GitHub personal access / OAuth / app token",
  },
  {
    name: "JWT Token",
    pattern: /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g,
    risk: "HIGH",
    description: "Hardcoded JWT",
  },
  {
    name: "PEM Private Key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    risk: "CRITICAL",
    description: "PEM private key block",
  },
  {
    name: "SendGrid API Key",
    pattern: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g,
    risk: "HIGH",
    description: "SendGrid API key",
  },
  {
    name: "Twilio Account SID",
    pattern: /AC[0-9a-fA-F]{32}/g,
    risk: "HIGH",
    description: "Twilio Account SID",
  },
  {
    name: "Twilio Key SID",
    pattern: /SK[0-9a-fA-F]{32}/g,
    risk: "HIGH",
    description: "Twilio API Key SID",
  },
  {
    name: "Mapbox Token",
    pattern: /pk\.eyJ1[A-Za-z0-9_\-]{60,}/g,
    risk: "MEDIUM",
    description: "Mapbox public token",
  },
  {
    name: "Slack Token",
    pattern: /xox[baprs]-[0-9A-Za-z\-]{10,}/g,
    risk: "HIGH",
    description: "Slack bot / user / app token",
  },
  {
    name: "Basic Auth Header",
    pattern: /Basic [A-Za-z0-9+\/]{20,}={0,2}/g,
    risk: "HIGH",
    description: "Hardcoded HTTP Basic Auth header",
  },
  {
    name: "Generic Hardcoded Credential",
    pattern: /(?:password|passwd|secret|api_?key|apikey|access_?token)['":\s=]+['"]([A-Za-z0-9\-_.!@#$%^&*]{8,})['"]/gi,
    risk: "MEDIUM",
    description: "Generic hardcoded credential",
  },
];

export function scanText(
  text: string,
  patterns: PatternDef[]
): Map<string, { def: PatternDef; matches: string[] }> {
  const results = new Map<string, { def: PatternDef; matches: string[] }>();
  for (const def of patterns) {
    const re = new RegExp(def.pattern.source, def.pattern.flags);
    const seen = new Set<string>();
    for (const m of text.matchAll(re)) {
      const val = (m[1] ?? m[0]).trim();
      if (!seen.has(val)) {
        seen.add(val);
        const entry = results.get(def.name) ?? { def, matches: [] };
        entry.matches.push(val);
        results.set(def.name, entry);
      }
    }
  }
  return results;
}

export function renderResults(
  results: Map<string, { def: PatternDef; matches: string[] }>
): string[] {
  if (results.size === 0) return [];
  const order: PatternDef["risk"][] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const sorted = [...results.values()].sort(
    (a, b) => order.indexOf(a.def.risk) - order.indexOf(b.def.risk)
  );
  const lines: string[] = [];
  for (const { def, matches } of sorted) {
    lines.push(`[${def.risk}] ${def.name} — ${def.description}`);
    for (const m of matches.slice(0, 5)) lines.push(`  → ${m}`);
    if (matches.length > 5) lines.push(`  … +${matches.length - 5} more`);
  }
  return lines;
}
