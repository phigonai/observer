import * as http from "node:http";
import * as https from "node:https";
import type { Socket } from "node:net";

/**
 * Corporate proxies. The observer's HTTPS calls (pairing, removal, update
 * checks, Guardian and the doctor probe) use `fetch`, which ignores
 * HTTPS_PROXY unless Node.js is told to read it, and the telemetry stream
 * uses @grpc/grpc-js, which reads only the lowercase names. This module
 * points both at the same proxy, using what Node.js offers natively.
 *
 * HTTPS goes through the proxy as a CONNECT tunnel, and TLS is negotiated
 * with the server itself inside it, so the usual certificate checks,
 * including an authority pinned for a company's own server, still apply.
 */
export type ProxySettings = Readonly<{
  https?: URL;
  http?: URL;
  /** NO_PROXY as written: comma- or space-separated host names. */
  noProxy: string;
}>;

/** The variable names, lowercase first: Node.js lets lowercase win. */
const variables = {
  https: ["https_proxy", "HTTPS_PROXY"],
  http: ["http_proxy", "HTTP_PROXY"],
  noProxy: ["no_proxy", "NO_PROXY"],
} as const;

function variable(environment: NodeJS.ProcessEnv, names: readonly string[]): string | undefined {
  for (const name of names) {
    const value = environment[name]?.trim();
    if (value) return value;
  }
  if (process.platform === "win32") {
    // Windows names are case-insensitive, but a copied environment is not.
    const wanted = names[0]!.toLowerCase();
    const found = Object.entries(environment).find(([key]) => key.toLowerCase() === wanted)?.[1]?.trim();
    if (found) return found;
  }
  return undefined;
}

function proxyURL(value: string | undefined, name: string): URL | undefined {
  if (value === undefined) return undefined;
  let url: URL;
  try {
    // A bare host:port is read the way Node.js and curl read it.
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//iu.test(value) ? value : `http://${value}`);
  } catch {
    // Never echo the value: it can hold the proxy's password.
    throw new Error(`${name} is not a valid proxy address. Use a form such as http://proxy.example.com:8080.`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`${name} must be an http:// or https:// proxy address.`);
  }
  return url;
}

/** Reads HTTPS_PROXY, HTTP_PROXY and NO_PROXY (either case) from `environment`. */
export function proxySettings(environment: NodeJS.ProcessEnv): ProxySettings {
  const httpsProxy = proxyURL(variable(environment, variables.https), "HTTPS_PROXY");
  const httpProxy = proxyURL(variable(environment, variables.http), "HTTP_PROXY");
  return Object.freeze({
    ...(httpsProxy === undefined ? {} : { https: httpsProxy }),
    ...(httpProxy === undefined ? {} : { http: httpProxy }),
    noProxy: variable(environment, variables.noProxy) ?? "",
  });
}

type NoProxyEntry = Readonly<{ host: string; port: number }>;

function noProxyEntries(value: string): NoProxyEntry[] {
  return value.split(/[,\s]+/u).filter(Boolean).map((entry) => {
    // An IPv6 address carries a port only in brackets: [::1]:8443.
    const withPort = /^(\[[^\]]+\]|[^:]+):(\d+)$/u.exec(entry);
    const host = (withPort?.[1] ?? entry).toLowerCase().replace(/^\[|\]$/gu, "");
    return { host, port: withPort === null ? 0 : Number(withPort[2]) };
  });
}

/**
 * The proxy `target` goes through, or undefined to connect directly. It
 * follows Node.js: an entry matches its host and every host under it
 * (`example.com`, `.example.com` and `*.example.com` all cover
 * `a.example.com`), `*` matches everything, and `host:port` only that port.
 */
export function proxyForUrl(target: URL, settings: ProxySettings): URL | undefined {
  const proxy = target.protocol === "https:" ? settings.https ?? settings.http : settings.http;
  if (proxy === undefined) return undefined;
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/gu, "");
  const port = Number(target.port || (target.protocol === "https:" ? 443 : 80));
  for (const entry of noProxyEntries(settings.noProxy)) {
    if (entry.host === "*") return undefined;
    if (entry.port !== 0 && entry.port !== port) continue;
    const suffix = entry.host.replace(/^\*?\./u, "");
    if (host === suffix || host.endsWith(`.${suffix}`)) return undefined;
  }
  return proxy;
}

/**
 * NO_PROXY in the form @grpc/grpc-js reads, which matches plain host name
 * endings only: `*.example.com` and `.example.com` become `example.com`, and
 * an entry for another port is left out because the stream cannot check
 * ports.
 */
export function grpcNoProxy(noProxy: string, streamPort: number): string {
  return noProxyEntries(noProxy)
    .filter((entry) => entry.host !== "*" && (entry.port === 0 || entry.port === streamPort))
    .map((entry) => entry.host.replace(/^\*?\./u, ""))
    .join(",");
}

/** Whether NO_PROXY turns the proxy off for every host, which grpc-js cannot express. */
export function noProxyForAll(environment: NodeJS.ProcessEnv): boolean {
  const value = environment["no_grpc_proxy"] ?? variable(environment, variables.noProxy) ?? "";
  return noProxyEntries(value).some((entry) => entry.host === "*");
}

type SetGlobalProxy = (environment: NodeJS.ProcessEnv) => () => void;

export type ProxySetup = Readonly<{
  /** Puts back the global agents and the variables changed for the stream. */
  restore: () => void;
  /** A plain sentence to show when part of the setup could not be applied. */
  notice?: string;
}>;

export type ProxySetupOptions = Readonly<{
  /** `http.setGlobalProxyFromEnv`, Node.js 24.14 and newer. */
  setGlobalProxyFromEnv?: SetGlobalProxy | undefined;
  /** The environment @grpc/grpc-js reads: process.env. */
  processEnvironment?: NodeJS.ProcessEnv;
  /** Whether Node.js already applied the proxy variables when it started. */
  startedWithEnvProxy?: boolean;
  nodeVersion?: string;
  /** The telemetry endpoint, to keep NO_PROXY port entries for it. */
  streamUrl?: URL;
}>;

/**
 * Sends `fetch` (and `http`/`https` requests) through the proxy that
 * `environment` names, and gives the telemetry stream the same proxy and
 * NO_PROXY list. Does nothing when no proxy is set.
 */
export function useProxyFromEnvironment(
  environment: NodeJS.ProcessEnv,
  options: ProxySetupOptions = {},
): ProxySetup {
  const settings = proxySettings(environment);
  const proxy = settings.https ?? settings.http;
  if (proxy === undefined) return Object.freeze({ restore: () => undefined });

  const notices: string[] = [];
  const setGlobal = "setGlobalProxyFromEnv" in options
    ? options.setGlobalProxyFromEnv
    : (http as unknown as { setGlobalProxyFromEnv?: SetGlobalProxy }).setGlobalProxyFromEnv;
  let restoreFetch: () => void = () => undefined;
  if (typeof setGlobal === "function") {
    restoreFetch = setGlobal({
      ...(settings.https === undefined ? {} : { HTTPS_PROXY: settings.https.href }),
      ...(settings.http === undefined ? {} : { HTTP_PROXY: settings.http.href }),
      ...(settings.noProxy === "" ? {} : { NO_PROXY: settings.noProxy }),
    });
  } else if (!(options.startedWithEnvProxy ?? startedWithEnvProxy())) {
    notices.push(
      `This computer sets a proxy, but Node.js ${options.nodeVersion ?? process.versions.node} uses it ` +
        "only when NODE_USE_ENV_PROXY=1 is set before the observer starts. Set it, or update Node.js to 24.14 or newer.",
    );
  }

  // @grpc/grpc-js reads grpc_proxy, then https_proxy and http_proxy, in
  // lowercase only, and supports only http:// proxies.
  const target = options.processEnvironment ?? process.env;
  const saved = new Map<string, string | undefined>();
  const assign = (name: string, value: string) => {
    if (target[name] !== undefined && target[name] !== "") return;
    saved.set(name, target[name]);
    target[name] = value;
  };
  const streamProxy = settings.https ?? settings.http;
  if (streamProxy !== undefined && streamProxy.protocol === "http:") {
    assign("grpc_proxy", streamProxy.href);
  } else if (streamProxy !== undefined && target["grpc_proxy"] === undefined) {
    notices.push(
      "The telemetry stream can use only an http:// proxy address, so it connects directly. " +
        "Set grpc_proxy to an http:// proxy if direct connections are blocked.",
    );
  }
  if (settings.noProxy !== "") {
    const port = Number(options.streamUrl?.port || 443);
    const list = grpcNoProxy(settings.noProxy, port);
    if (list !== "") assign("no_grpc_proxy", list);
  }

  return Object.freeze({
    restore: () => {
      restoreFetch();
      for (const [name, value] of saved) {
        if (value === undefined) delete target[name];
        else target[name] = value;
      }
      saved.clear();
    },
    ...(notices.length === 0 ? {} : { notice: notices.join(" ") }),
  });
}

function startedWithEnvProxy(): boolean {
  return process.env["NODE_USE_ENV_PROXY"] === "1" ||
    process.execArgv.includes("--use-env-proxy");
}

/**
 * Opens a CONNECT tunnel through `proxy` to `host:port`, for a raw TLS
 * connection that `fetch` does not cover. Messages name the proxy by host
 * only, never with its credentials.
 */
export async function connectThroughProxy(
  proxy: URL,
  host: string,
  port: number,
  timeoutMs = 15_000,
): Promise<Socket> {
  const authority = host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
  const credentials = proxy.username === ""
    ? undefined
    : Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64");
  const request = (proxy.protocol === "https:" ? https : http).request({
    host: proxy.hostname.replace(/^\[|\]$/gu, ""),
    port: Number(proxy.port || (proxy.protocol === "https:" ? 443 : 80)),
    method: "CONNECT",
    path: authority,
    agent: false,
    headers: {
      host: authority,
      ...(credentials === undefined ? {} : { "proxy-authorization": `Basic ${credentials}` }),
    },
  });
  return await new Promise<Socket>((resolve, reject) => {
    const timer = setTimeout(() => {
      request.destroy();
      reject(new Error(`The proxy ${proxy.host} did not answer in time.`));
    }, timeoutMs);
    request.once("connect", (response, socket) => {
      clearTimeout(timer);
      if (response.statusCode === 200) {
        resolve(socket);
        return;
      }
      socket.destroy();
      reject(new Error(`The proxy ${proxy.host} refused to connect to ${authority} (HTTP ${response.statusCode}).`));
    });
    request.once("error", (error) => {
      clearTimeout(timer);
      reject(new Error(`Could not reach the proxy ${proxy.host}: ${error.message}`));
    });
    request.end();
  });
}
