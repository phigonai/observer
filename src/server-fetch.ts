import { Agent, ProxyAgent, fetch as undiciFetch, type Dispatcher } from "undici";
import { proxyForUrl, type ProxySettings } from "./proxy.js";
import { relayHost, relayNeedsAuthorityMessage } from "./relay-host.js";

/**
 * HTTPS to a company's own Phigon server. Its certificates come from the
 * authority this computer pinned when it paired, and nothing else may vouch
 * for it: the server is reached at names under phigon.online too (through
 * Phigon's relay), and whoever runs that name or its DNS could otherwise
 * get a public certificate for it and read or forge what the observer
 * sends and receives with the machine key. Requests to other hosts, such
 * as the npm registry, keep the system's authorities.
 */
export type PinnedFetch = typeof fetch & Readonly<{
  /** Closes the connections it keeps open. */
  close: () => Promise<void>;
}>;

type ProxyFor = (url: URL) => URL | undefined;

/**
 * A fetch that trusts only `authority` for HTTPS, directly or through the
 * proxy `proxyFor` picks (a CONNECT tunnel; TLS still runs end to end with
 * the server). Plain http:// requests go through the global fetch.
 */
export function pinnedFetch(authority: string, proxyFor: ProxyFor = () => undefined): PinnedFetch {
  // One per proxy address in use: at most a few.
  const dispatchers = new Map<string, Dispatcher>();
  const dispatcherFor = (url: URL): Dispatcher => {
    const proxy = proxyFor(url);
    const key = proxy?.href ?? "";
    let dispatcher = dispatchers.get(key);
    if (dispatcher === undefined) {
      // `ca` replaces the system's authorities for these connections.
      const trust = { ca: [authority] };
      dispatcher = proxy === undefined
        ? new Agent({ connect: trust })
        : new ProxyAgent({ uri: proxy.href, requestTls: trust });
      dispatchers.set(key, dispatcher);
    }
    return dispatcher;
  };
  const fetcher = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    if (typeof input !== "string" && !(input instanceof URL)) {
      throw new TypeError("Requests to the Phigon server take a URL.");
    }
    const url = new URL(input);
    if (url.protocol !== "https:") return await fetch(url, init);
    const response = await undiciFetch(url, { ...(init as object), dispatcher: dispatcherFor(url) } as Parameters<typeof undiciFetch>[1]);
    return response as unknown as Response;
  }) as typeof fetch;
  return Object.assign(fetcher, {
    close: async () => {
      const open = [...dispatchers.values()];
      dispatchers.clear();
      await Promise.allSettled(open.map((dispatcher) => dispatcher.close()));
    },
  });
}

let pinned: Readonly<{ authority: string; fetch: PinnedFetch }> | undefined;
let proxy: ProxySettings | undefined;
/** Why HTTPS requests to the paired server are refused, when they are. */
let refusal: string | undefined;

/**
 * The authority requests to the paired server trust from now on, in this
 * process; undefined for a server with a public certificate, which the
 * system's authorities check as usual.
 */
export function trustServerAuthority(authority: string | undefined): void {
  refusal = undefined;
  if (pinned?.authority === authority) return;
  void pinned?.fetch.close();
  pinned = authority === undefined
    ? undefined
    : { authority, fetch: pinnedFetch(authority, (url) => proxy === undefined ? undefined : proxyForUrl(url, proxy)) };
}

/**
 * Refuses every HTTPS request to the paired server with `message` until an
 * authority is trusted again: the computer was paired under an authority it
 * no longer has, and the system's authorities must not stand in for it.
 */
export function refuseServerRequests(message: string): void {
  void pinned?.fetch.close();
  pinned = undefined;
  refusal = message;
}

/** The authority `serverFetch` trusts, if one is pinned. */
export function trustedServerAuthority(): string | undefined {
  return pinned?.authority;
}

/** The proxy settings (HTTPS_PROXY, NO_PROXY…) requests to the paired server follow. */
export function useServerProxy(settings: ProxySettings | undefined): void {
  proxy = settings;
}

/**
 * Fetch for requests to the server this computer is paired with: only the
 * pinned authority when there is one, otherwise the global fetch. Without
 * one, an address on Phigon's relay is refused: TLS through the relay runs
 * end to end with the company's server, so a public certificate for its
 * name proves nothing.
 */
export const serverFetch: typeof fetch = async (input, init) => {
  if (pinned !== undefined) return await pinned.fetch(input, init);
  const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
  if (url.protocol === "https:" && refusal !== undefined) throw new Error(refusal);
  if (url.protocol === "https:" && relayHost(url.hostname)) throw new Error(relayNeedsAuthorityMessage);
  return await fetch(input, init);
};
