// Writes THIRD_PARTY_NOTICES.md for the Go modules linked into the Guardian
// runner binaries that ship inside the npm package. Run after changing
// go/go.mod: `node scripts/third-party-notices.mjs`.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const goModule = fileURLToPath(new URL("../go/", import.meta.url));
const output = fileURLToPath(new URL("../THIRD_PARTY_NOTICES.md", import.meta.url));
const env = { ...process.env, GOWORK: "off", CGO_ENABLED: "0" };

// Every module linked into the runner on any released platform.
const modules = new Map();
for (const goos of ["linux", "darwin", "windows"]) {
  const listed = execFileSync("go", ["list", "-deps", "-f", "{{with .Module}}{{.Path}} {{.Version}} {{.Dir}}{{end}}", "./cmd/guardian-runner"], {
    cwd: goModule, env: { ...env, GOOS: goos }, encoding: "utf8",
  });
  for (const line of listed.split("\n")) {
    const [path, version, dir] = line.trim().split(" ");
    if (path && version && !path.startsWith("github.com/phigonai/")) modules.set(path, { version, dir });
  }
}

const licenseFile = (dir, pattern) => readdirSync(dir).find((name) => pattern.test(name));
const sections = [...modules.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([path, { version, dir }]) => {
  const license = licenseFile(dir, /^(license|copying)(\.(md|txt))?$/iu);
  const notice = licenseFile(dir, /^notice(\.(md|txt))?$/iu);
  if (!license) throw new Error(`${path} has no license file`);
  const text = readFileSync(join(dir, license), "utf8").trim();
  const kind = /Apache License\s+Version 2\.0/u.test(text) ? "Apache-2.0" : /Redistribution and use in source and binary forms/u.test(text) ? "BSD-3-Clause" : "See license text";
  return [
    `## ${path} ${version}`,
    "",
    `License: ${kind}`,
    "",
    ...(notice ? ["Notice:", "", "```text", readFileSync(join(dir, notice), "utf8").trim(), "```", ""] : []),
    "```text",
    text,
    "```",
  ].join("\n");
});

writeFileSync(output, `# Third-party notices

The Guardian runner binaries in this package (\`dist/bin/guardian-runner-*\`)
are built from \`go/\` and statically link the Go modules below. Their license
terms and notices are reproduced here. npm dependencies are installed
separately by npm and carry their own licenses.

${sections.join("\n\n")}
`);
console.log(`Wrote notices for ${modules.size} modules`);
