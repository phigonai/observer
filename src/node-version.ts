// Loaded before anything else, so it imports nothing: an older Node.js must
// reach the plain message below instead of failing on a newer API.

/**
 * The oldest Node.js the observer runs on. Trusting a company's own server
 * needs `tls.setDefaultCACertificates`, which Node.js 24.5 added.
 */
export const minimumNodeVersion = "24.5.0";

/** Why this Node.js cannot run the observer, or undefined when it can. */
export function nodeVersionProblem(version: string): string | undefined {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/u.exec(version);
  const major = match === null ? 0 : Number(match[1]);
  const minor = match === null ? 0 : Number(match[2]);
  if (major > 24 || (major === 24 && minor >= 5)) return undefined;
  return `Phigon observer needs Node.js 24.5 or newer; this computer has ${version.replace(/^v/u, "")}.`;
}
