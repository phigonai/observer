#!/usr/bin/env node

// The command's entry point. It checks the Node.js version before loading
// the rest of the observer, which an older Node.js may not be able to load.
import { logServiceStartupFailure, nodeVersionProblem, trimServiceErrors } from "./node-version.js";

const argv = process.argv.slice(2);
// A background service's start failures are written to its log, since
// nobody reads what a service prints.
await trimServiceErrors(argv);
const problem = nodeVersionProblem(process.versions.node);
if (problem === undefined) {
  let run: (argv: readonly string[]) => Promise<number>;
  try {
    ({ run } = await import("./cli.js"));
  } catch (error) {
    await logServiceStartupFailure(
      argv,
      `The observer could not start: ${(error instanceof Error ? error.message : String(error)).replace(/\.?\s*$/u, ".")} ` +
        "Install it again with npm install --global @phigon/observer, then run phigon-observer service install.",
    );
    throw error;
  }
  process.exitCode = await run(argv);
} else {
  process.stderr.write(`${problem}\n`);
  await logServiceStartupFailure(
    argv,
    `${problem} Run phigon-observer service install again from a terminal whose Node.js is 24.5 or newer.`,
  );
  process.exitCode = 1;
}
