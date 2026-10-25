import { lstat, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export function verifyNativeHeader(bytes, platform, architecture) {
  if (bytes.length < 256) throw new Error("Guardian executable is incomplete.");
  const arm = architecture === "arm64";
  if (platform === "windows") {
    const pe = bytes.readUInt32LE(0x3c);
    if (bytes.toString("ascii", 0, 2) !== "MZ" || pe > bytes.length - 6 || bytes.readUInt32LE(pe) !== 0x4550 || bytes.readUInt16LE(pe + 4) !== (arm ? 0xaa64 : 0x8664)) {
      throw new Error("Guardian Windows executable has the wrong format or architecture.");
    }
  } else if (platform === "linux") {
    if (!bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) || bytes[4] !== 2 || bytes[5] !== 1 || bytes.readUInt16LE(18) !== (arm ? 183 : 62)) {
      throw new Error("Guardian Linux executable has the wrong format or architecture.");
    }
  } else if (platform === "darwin") {
    if (bytes.readUInt32LE(0) !== 0xfeedfacf || bytes.readUInt32LE(4) !== (arm ? 0x100000c : 0x1000007)) {
      throw new Error("Guardian macOS executable has the wrong format or architecture.");
    }
  } else throw new Error("Unknown Guardian platform.");
}

export async function verifyGuardianRelease() {
  for (const platform of ["windows", "linux", "darwin"]) {
    for (const architecture of ["amd64", "arm64"]) {
      const name = `guardian-runner-${platform}-${architecture}${platform === "windows" ? ".exe" : ""}`;
      const file = new URL(`../dist/bin/${name}`, import.meta.url);
      const stat = await lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Release requires a regular native executable: ${name}`);
      verifyNativeHeader(await readFile(file), platform, architecture);
      if (platform !== "windows" && (stat.mode & 0o111) !== 0o111) {
        throw new Error(`${name} lacks Unix executable permissions. Build and pack the portable release on Linux or macOS using the release workflow.`);
      }
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await verifyGuardianRelease();
  process.stdout.write("Guardian release verified: six native executables with correct architectures and permissions.\n");
}
