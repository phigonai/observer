/** Phigon's relay, which reaches a Phigon app's server from any network. */
export const RELAY_DOMAIN = "relay.phigon.online";

/** Whether `hostname` is a server's name on Phigon's relay. */
export function relayHost(hostname: string, domain = RELAY_DOMAIN): boolean {
  return hostname.toLowerCase().replace(/\.$/u, "").endsWith(`.${domain}`);
}

/**
 * Why a relay address is refused without a pinned authority. TLS through
 * the relay runs end to end with the company's server, under the authority
 * pinned at pairing; a public certificate for a name under the relay's
 * domain proves nothing about that server.
 */
export const relayNeedsAuthorityMessage =
  "This computer has no certificate authority saved for its Phigon server, and addresses on Phigon's relay are trusted only with one. " +
  "Copy the whole command from Connect machine, including --server-ca-sha256, and run it again.";

/** Why a computer paired with a pinned authority refuses to connect once it is gone. */
export const pinnedAuthorityMissingMessage =
  "The certificate authority this computer pinned for its Phigon server is missing from its data directory or has changed, so it will not connect. " +
  "Copy the whole command from Connect machine, including --server-ca-sha256, and run it again.";
