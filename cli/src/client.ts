/**
 * Thin fetch wrapper over the RootWatch REST API.
 *
 * - `get`/`post`/… hit `<baseUrl>/api/v1<path>` with `Authorization: Bearer`.
 * - `raw` hits an arbitrary path on the same host (e.g. the session-auth'd
 *   `/api/org/tokens` endpoints, best-effort).
 * - Success envelope `{ data, meta? }` is unwrapped; `{ error: { code, message } }`
 *   becomes a CliError with a stable code.
 */

import { resolveAuth, type ResolvedAuth } from "./config.js";

export const CLI_VERSION = "0.1.0";

export class CliError extends Error {
  readonly code: string;
  readonly status?: number;
  /** process exit code: 1 = API/threshold failure, 2 = usage error */
  readonly exitCode: number;

  constructor(message: string, opts: { code?: string; status?: number; exitCode?: number } = {}) {
    super(message);
    this.name = "CliError";
    this.code = opts.code ?? "error";
    this.status = opts.status;
    this.exitCode = opts.exitCode ?? 1;
  }
}

export interface ApiResult<T> {
  data: T;
  meta?: Record<string, unknown>;
  status: number;
}

interface RequestOptions {
  query?: Record<string, string | number | undefined>;
  body?: unknown;
}

function mapHttpError(status: number, parsed: any, baseUrl: string): CliError {
  const serverMsg = parsed?.error?.message ?? parsed?.message ?? parsed?.error ?? undefined;
  const serverCode = typeof parsed?.error?.code === "string" ? parsed.error.code : undefined;

  switch (status) {
    case 401:
      return new CliError(
        "invalid or expired token — run `rootwatch login` (or set ROOTWATCH_TOKEN)",
        { code: serverCode ?? "unauthorized", status },
      );
    case 403:
      return new CliError(`forbidden: ${serverMsg ?? "your API token lacks the required scope"}`, {
        code: serverCode ?? "forbidden",
        status,
      });
    case 404:
      return new CliError(
        `not found: ${serverMsg ?? "the endpoint does not exist on this server"} (${baseUrl})`,
        { code: serverCode ?? "not_found", status },
      );
    case 429:
      return new CliError(`rate limited: ${serverMsg ?? "too many requests — try again shortly"}`, {
        code: serverCode ?? "rate_limited",
        status,
      });
    default:
      return new CliError(serverMsg ? String(serverMsg) : `request failed with HTTP ${status}`, {
        code: serverCode ?? `http_${status}`,
        status,
      });
  }
}

export class ApiClient {
  readonly baseUrl: string;
  readonly token?: string;

  constructor(baseUrl: string, token?: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
  }

  async request<T = unknown>(
    method: string,
    path: string,
    opts: RequestOptions = {},
  ): Promise<ApiResult<T>> {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
    }

    const headers: Record<string, string> = {
      accept: "application/json",
      "x-rootwatch-version": "1",
      "user-agent": `rootwatch-cli/${CLI_VERSION}`,
    };
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    if (opts.body !== undefined) headers["content-type"] = "application/json";

    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const cause = (e as { cause?: { message?: string } }).cause?.message;
      throw new CliError(`cannot reach ${this.baseUrl}${cause ? ` — ${cause}` : ` — ${msg}`}`, {
        code: "network",
      });
    }

    const text = await res.text();
    let parsed: any;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }

    if (!res.ok) throw mapHttpError(res.status, parsed, this.baseUrl);
    if (parsed && typeof parsed === "object" && parsed.error) {
      throw new CliError(String(parsed.error.message ?? "API error"), {
        code: parsed.error.code ?? "api_error",
        status: res.status,
      });
    }

    if (parsed && typeof parsed === "object" && "data" in parsed) {
      return {
        data: parsed.data as T,
        meta: parsed.meta as Record<string, unknown> | undefined,
        status: res.status,
      };
    }
    return { data: parsed as T, meta: undefined, status: res.status };
  }

  /** Arbitrary path on the same host (session API, health endpoints…). */
  raw<T = unknown>(method: string, path: string, opts: RequestOptions = {}): Promise<ApiResult<T>> {
    return this.request<T>(method, path, opts);
  }

  get<T = unknown>(
    path: string,
    query?: Record<string, string | number | undefined>,
  ): Promise<ApiResult<T>> {
    return this.request<T>("GET", `/api/v1${path}`, { query });
  }

  post<T = unknown>(
    path: string,
    body?: unknown,
    query?: Record<string, string | number | undefined>,
  ): Promise<ApiResult<T>> {
    return this.request<T>("POST", `/api/v1${path}`, { body, query });
  }

  patch<T = unknown>(path: string, body?: unknown): Promise<ApiResult<T>> {
    return this.request<T>("PATCH", `/api/v1${path}`, { body });
  }

  delete<T = unknown>(path: string): Promise<ApiResult<T>> {
    return this.request<T>("DELETE", `/api/v1${path}`);
  }
}

export interface GlobalOpts {
  json?: boolean;
  profile?: string;
}

/** Resolve credentials for a command; throws a friendly error when logged out. */
export function requireAuth(globals: GlobalOpts): {
  client: ApiClient;
  auth: ResolvedAuth;
} {
  const auth = resolveAuth(globals.profile);
  if (!auth.token) {
    throw new CliError(
      `not logged in (profile '${auth.profile}') — run \`rootwatch login\` or set ROOTWATCH_TOKEN`,
      { code: "unauthorized" },
    );
  }
  return { client: new ApiClient(auth.url, auth.token), auth };
}
