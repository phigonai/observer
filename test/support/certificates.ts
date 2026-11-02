import {
  X509Certificate,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { isIPv4 } from "node:net";

// Throwaway certificates for TLS tests, made at run time so that no key is
// ever stored in the repository. Minimal DER (X.509 v3, P-256, SHA-256).

function length(value: number): Buffer {
  if (value < 0x80) return Buffer.from([value]);
  const bytes: number[] = [];
  for (let rest = value; rest > 0; rest >>= 8) bytes.unshift(rest & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), length(body.length), body]);
}

const sequence = (...parts: Buffer[]) => tlv(0x30, ...parts);
const set = (...parts: Buffer[]) => tlv(0x31, ...parts);

function objectIdentifier(value: string): Buffer {
  const parts = value.split(".").map(Number);
  const bytes = [parts[0]! * 40 + parts[1]!];
  for (const part of parts.slice(2)) {
    const encoded = [part & 0x7f];
    for (let rest = part >> 7; rest > 0; rest >>= 7) encoded.unshift((rest & 0x7f) | 0x80);
    bytes.push(...encoded);
  }
  return tlv(0x06, Buffer.from(bytes));
}

function integer(bytes: Buffer): Buffer {
  const positive = (bytes[0]! & 0x80) === 0 ? bytes : Buffer.concat([Buffer.from([0]), bytes]);
  return tlv(0x02, positive);
}

function utcTime(date: Date): Buffer {
  const text = date.toISOString().replace(/[-:T]/gu, "").slice(2, 14);
  return tlv(0x17, Buffer.from(`${text}Z`));
}

function name(commonName: string): Buffer {
  return sequence(set(sequence(objectIdentifier("2.5.4.3"), tlv(0x0c, Buffer.from(commonName)))));
}

const ecdsaWithSHA256 = sequence(objectIdentifier("1.2.840.10045.4.3.2"));

export type TestCertificate = Readonly<{
  /** PEM certificate. */
  certificate: string;
  /** PEM private key, for a test server only. */
  key: string;
  /** SHA-256 of the DER certificate, as --server-ca-sha256 takes it. */
  fingerprint: string;
  signingKey: KeyObject;
  commonName: string;
}>;

function issue(options: Readonly<{
  commonName: string;
  issuer?: TestCertificate;
  authority: boolean;
  hosts?: readonly string[];
}>): TestCertificate {
  const keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const now = Date.now();
  // Positive, and without a leading zero byte, as DER requires.
  const serial = randomBytes(12);
  serial[0] = (serial[0]! & 0x7f) | 0x40;
  const extensions = [
    sequence(
      objectIdentifier("2.5.29.19"),
      tlv(0x01, Buffer.from([0xff])),
      tlv(0x04, sequence(...(options.authority ? [tlv(0x01, Buffer.from([0xff]))] : []))),
    ),
  ];
  if (options.hosts !== undefined) {
    const names = options.hosts.map((host) => isIPv4(host)
      ? tlv(0x87, Buffer.from(host.split(".").map(Number)))
      : tlv(0x82, Buffer.from(host)));
    extensions.push(sequence(objectIdentifier("2.5.29.17"), tlv(0x04, sequence(...names))));
  }
  const toBeSigned = sequence(
    tlv(0xa0, integer(Buffer.from([2]))),
    integer(serial),
    ecdsaWithSHA256,
    name(options.issuer?.commonName ?? options.commonName),
    sequence(utcTime(new Date(now - 86_400_000)), utcTime(new Date(now + 30 * 86_400_000))),
    name(options.commonName),
    keys.publicKey.export({ type: "spki", format: "der" }),
    tlv(0xa3, sequence(...extensions)),
  );
  const signature = sign("sha256", toBeSigned, options.issuer?.signingKey ?? keys.privateKey);
  const der = sequence(toBeSigned, ecdsaWithSHA256, tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const certificate = new X509Certificate(der);
  return Object.freeze({
    certificate: certificate.toString(),
    key: keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    fingerprint: certificate.fingerprint256.replace(/:/gu, "").toLowerCase(),
    signingKey: keys.privateKey,
    commonName: options.commonName,
  });
}

/** A certificate authority for one test. */
export function testAuthority(commonName = "Phigon test authority"): TestCertificate {
  return issue({ commonName, authority: true });
}

/** A server certificate for `hosts` (names or IPv4 addresses), signed by `issuer`. */
export function serverCertificate(issuer: TestCertificate, hosts: readonly string[] = ["localhost", "127.0.0.1"]): TestCertificate {
  return issue({ commonName: hosts[0] ?? "localhost", issuer, authority: false, hosts });
}
