/**
 * Shared helpers: severity ordering, slugging, formatting.
 */

export const SEVERITY_ORDER = ["low", "medium", "high", "critical"] as const;
export type Severity = "Low" | "Medium" | "High" | "Critical";

export function severityRank(sev: string | null | undefined): number {
  return SEVERITY_ORDER.indexOf(
    (sev ?? "").toLowerCase() as (typeof SEVERITY_ORDER)[number],
  );
}

export function isValidSeverity(sev: string): boolean {
  return severityRank(sev) >= 0;
}

/** true when `sev` is at least `threshold` on the Low<Medium<High<Critical scale. */
export function severityAtLeast(sev: string, threshold: string): boolean {
  const t = severityRank(threshold);
  if (t < 0) return false;
  return severityRank(sev) >= t;
}

/** 'high' -> 'High'; unknown -> 'Medium'. */
export function normalizeSeverity(sev: string): Severity {
  const s = (sev || "medium").toLowerCase();
  const rank = severityRank(s);
  const word = rank >= 0 ? SEVERITY_ORDER[rank] : "medium";
  return (word[0]!.toUpperCase() + word.slice(1)) as Severity;
}

export function slugify(name: string): string {
  const slug = name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "project";
}

export function truncate(value: string | null | undefined, max: number): string {
  const s = value ?? "";
  return s.length > max ? s.slice(0, Math.max(0, max - 1)) + "…" : s;
}

export function formatUptime(seconds: number | null | undefined): string {
  const s = Math.max(0, Math.floor(seconds ?? 0));
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export function formatBytes(bytes: number | null | undefined): string {
  const b = bytes ?? 0;
  if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(1)}G`;
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(1)}M`;
  if (b >= 1 << 10) return `${(b / (1 << 10)).toFixed(1)}K`;
  return `${b}B`;
}

export function formatTime(ts: string | number | Date | null | undefined): string {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toISOString().replace("T", " ").slice(0, 19);
}

/** Normalize list endpoints that may return an array or `{<key>: [...]}` / `{items}` / `{results}`. */
export function asList<T = Record<string, unknown>>(
  data: unknown,
  keys: string[] = [],
): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    for (const key of [...keys, "items", "results", "data"]) {
      const v = (data as Record<string, unknown>)[key];
      if (Array.isArray(v)) return v as T[];
    }
  }
  return [];
}

/** Pull an array of strings out of whatever shape the server uses for scopes. */
export function extractScopes(data: unknown): string[] {
  const candidates = [
    (data as any)?.scopes,
    (data as any)?.tokenScopes,
    (data as any)?.apiToken?.scopes,
    (data as any)?.token?.scopes,
    (data as any)?.caller?.scopes,
  ];
  for (const c of candidates) {
    if (Array.isArray(c)) return c.map(String);
    if (typeof c === "string") return c.split(/[,\s]+/).filter(Boolean);
  }
  return [];
}

/** Normalize the /api/v1/org payload into a flat shape. */
export function extractOrg(data: unknown): {
  id?: number | string;
  name?: string;
  slug?: string;
  role?: string;
  scopes: string[];
} {
  const d = (data ?? {}) as Record<string, any>;
  const org = (d.org ?? d.organization ?? d) as Record<string, any>;
  return {
    id: org.id,
    name: org.name ?? org.slug,
    slug: org.slug,
    role: d.role ?? d.caller?.role,
    scopes: extractScopes(d),
  };
}
