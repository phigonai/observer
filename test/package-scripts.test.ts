import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The observer is published on its own, so its npm scripts must not read
// anything outside its own directory, such as a parent repository's .env.
test("package scripts stay inside the observer directory", () => {
  const manifest = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { scripts: Record<string, string> };
  const outside = Object.entries(manifest.scripts).filter(([, command]) => /(?:^|[\s="'])\.\.[\\/]/u.test(command));
  assert.deepEqual(outside, []);
  for (const name of ["doctor", "discover", "pair", "start"]) {
    assert.match(manifest.scripts[name] ?? "", /--env-file-if-exists=\.env /u, `${name} reads the observer's own .env`);
  }
});
