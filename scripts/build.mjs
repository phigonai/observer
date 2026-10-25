import { rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const project = fileURLToPath(new URL("../", import.meta.url));
const output = fileURLToPath(new URL("../dist/", import.meta.url));
// TypeScript does not remove artifacts for deleted source modules. A clean
// build ensures retired authorization paths cannot remain in npm releases.
rmSync(output, { recursive: true, force: true });
const result = spawnSync(process.execPath, [require.resolve("typescript/bin/tsc"), "-p", "tsconfig.json"], {
  cwd: project,
  stdio: "inherit",
  windowsHide: true,
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
if (result.status === 0) {
  const runner = spawnSync(process.execPath, [fileURLToPath(new URL("./build-guardian-runner.mjs", import.meta.url))], {
    cwd: project, stdio: "inherit", windowsHide: true,
  });
  if (runner.error) throw runner.error;
  process.exitCode = runner.status ?? 1;
}
