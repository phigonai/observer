#!/usr/bin/env node

// The command's entry point. It checks the Node.js version before loading
// the rest of the observer, which an older Node.js may not be able to load.
import { nodeVersionProblem } from "./node-version.js";

const problem = nodeVersionProblem(process.versions.node);
if (problem === undefined) {
  const { run } = await import("./cli.js");
  process.exitCode = await run(process.argv.slice(2));
} else {
  process.stderr.write(`${problem}\n`);
  process.exitCode = 1;
}
