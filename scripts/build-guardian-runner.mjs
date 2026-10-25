import { mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// The runner is built from the observer's own Go module, never a parent workspace.
const goModule = fileURLToPath(new URL("../go/", import.meta.url));
const destination = fileURLToPath(new URL("../dist/bin/", import.meta.url));
mkdirSync(destination, { recursive: true });
const all = process.argv.includes("--all");
const targets = all ? ["windows", "linux", "darwin"] : [process.platform === "win32" ? "windows" : process.platform];
for (const os of targets) {
  if (!["windows", "linux", "darwin"].includes(os)) throw new Error("Unsupported Guardian platform.");
  for (const arch of all ? ["amd64", "arm64"] : [process.arch === "x64" ? "amd64" : process.arch]) {
    if (!["amd64", "arm64"].includes(arch)) throw new Error("Unsupported Guardian architecture.");
    const name = `guardian-runner-${os}-${arch}${os === "windows" ? ".exe" : ""}`;
    const result = spawnSync("go", ["build", "-trimpath", "-ldflags=-s -w", "-o", destination + name, "./cmd/guardian-runner"], {
      cwd: goModule, env: { ...process.env, CGO_ENABLED: "0", GOOS: os, GOARCH: arch, GOWORK: "off" }, windowsHide: true, stdio: "inherit",
    });
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
}
