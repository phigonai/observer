import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as tls from "node:tls";
import { connectionEnvironment } from "../src/connection-config.js";
import {
  forgetServerAuthority,
  parseAuthorityFingerprint,
  pinServerAuthority,
  serverAuthorityPath,
  trustSavedAuthority,
} from "../src/server-authority.js";

// A throwaway test authority; only its certificate is kept.
const AUTHORITY = `-----BEGIN CERTIFICATE-----
MIIBlzCCAT2gAwIBAgIULJuOXFgUkkeJIgd/SpI9mzwtk1wwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVUGhpZ29uIHRlc3QgYXV0aG9yaXR5MCAXDTI2MTEwMTA1MjA1
NloYDzIxMjYxMDA4MDUyMDU2WjAgMR4wHAYDVQQDDBVQaGlnb24gdGVzdCBhdXRo
b3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASfoVjMspiJGTY6aYChFSs/
98QHhJHl4H76TMh1BJSIRoioi3Hr8zKI0aClSUWgLUUDtAayyYq2X4LAydh/gl+n
o1MwUTAdBgNVHQ4EFgQUUTmv3giUis45PwIfU0MdvjKqp+wwHwYDVR0jBBgwFoAU
UTmv3giUis45PwIfU0MdvjKqp+wwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
AgNIADBFAiB0SMBOvNGl8BJ8aZOFWGD0/rV8xNvSUwoC5JnOtQZ4nwIhAISVaoWz
MzwLE5B2zbYJ2rqxkFgxlBjHkXz2ZII1W1Hb
-----END CERTIFICATE-----
`;
const FINGERPRINT = "6a099db5ea98af28e0527090b130e4f5f14e0f36adc9bf5e3769b03a397aaa1a";

/** A connection that presents a leaf and then the test authority. */
function presenting(seen: tls.ConnectionOptions[]) {
  return (options: tls.ConnectionOptions, listener: () => void) => {
    seen.push(options);
    const authority = new X509Certificate(AUTHORITY);
    const root = { raw: authority.raw, fingerprint256: authority.fingerprint256 } as tls.DetailedPeerCertificate;
    root.issuerCertificate = root;
    const leaf = { raw: Buffer.from("leaf"), fingerprint256: "LEAF", issuerCertificate: root } as tls.DetailedPeerCertificate;
    const socket = Object.assign(new EventEmitter(), {
      getPeerCertificate: () => leaf,
      end: () => undefined,
      destroy: () => undefined,
    }) as unknown as tls.TLSSocket;
    queueMicrotask(listener);
    return socket;
  };
}

test("fingerprints from the Connect machine dialog are read with or without colons", () => {
  assert.equal(parseAuthorityFingerprint(` ${FINGERPRINT.toUpperCase()} `), FINGERPRINT);
  assert.equal(parseAuthorityFingerprint(FINGERPRINT.match(/../gu)!.join(":")), FINGERPRINT);
  for (const bad of ["", "abc", `${FINGERPRINT}00`, FINGERPRINT.replace("a", "g")]) {
    assert.throws(() => parseAuthorityFingerprint(bad), /64-character fingerprint/u);
  }
});

test("pairing pins the server's authority, and later commands trust it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-authority-"));
  try {
    const seen: tls.ConnectionOptions[] = [];
    const file = await pinServerAuthority(new URL("https://192.168.1.20:17080"), FINGERPRINT, directory, presenting(seen));
    assert.equal(file, serverAuthorityPath(directory));
    assert.equal(new X509Certificate(await readFile(file, "utf8")).fingerprint256, new X509Certificate(AUTHORITY).fingerprint256);
    assert.equal(seen[0]?.host, "192.168.1.20");
    assert.equal(seen[0]?.port, 17080);
    assert.equal(seen[0]?.servername, undefined);
    const trusted = tls.getCACertificates("default").map((pem) => pem.replace(/\s+/gu, ""));
    assert.ok(trusted.includes(AUTHORITY.replace(/\s+/gu, "")), "the pinned authority is trusted for HTTPS");

    // Every later command trusts it, for gRPC too.
    assert.equal(trustSavedAuthority(directory), file);
    const environment = await connectionEnvironment({ PHIGON_DATA_DIR: directory });
    assert.equal(environment["PHIGON_TLS_CA_FILE"], file);

    await forgetServerAuthority(directory);
    assert.equal(trustSavedAuthority(directory), undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a server whose chain does not match the fingerprint is refused, and nothing is saved", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-authority-"));
  try {
    await assert.rejects(
      pinServerAuthority(new URL("https://phigon.acme.lan:17080"), "0".repeat(64), directory, presenting([])),
      /does not match the fingerprint/u,
    );
    assert.equal(trustSavedAuthority(directory), undefined);
    await assert.rejects(
      pinServerAuthority(new URL("http://phigon.acme.lan:17080"), FINGERPRINT, directory, presenting([])),
      /needs an https/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
