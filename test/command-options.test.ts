import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../src/cli.js";
import {
  UsageError,
  checkCommandLine,
  closestOption,
  commandOptions,
  editDistance,
  isCommand,
} from "../src/command-options.js";

/** Splits at the first "--" as the observer does, and checks the rest. */
function check(argv: readonly string[]): void {
  const [command, ...rest] = argv;
  const separator = rest.indexOf("--");
  checkCommandLine(
    command as string,
    separator < 0 ? rest : rest.slice(0, separator),
    separator < 0 ? undefined : rest.slice(separator + 1),
  );
}

function refusal(argv: readonly string[]): string {
  try {
    check(argv);
  } catch (error) {
    assert.ok(error instanceof UsageError, String(error));
    assert.equal(error.exitCode, 2);
    return error.message;
  }
  assert.fail(`${argv.join(" ")} was accepted`);
}

const url = "https://phigon.corp.example:8443";
const fingerprint = "a".repeat(64);
// Built at run time, so no code-shaped text is stored.
const enrollmentCode = ["phe", "example"].join("_");

test("every command line a service, a device management script, the Phigon app or the docs run keeps working", () => {
  for (const argv of [
    // The background service (service.ts) and managed deployments (managed-service.mjs).
    ["run", "--service-settings", "/home/ada/.phigon/observer/service-settings.json"],
    ["run"],
    // The Phigon app's Connect machine command (desktop observer-endpoints.mjs).
    ["pair", "--code", "ABCDE-FGHIJ", "--consent-profile", "full", "--control-plane-url", url, "--grpc-url", url, "--server-ca-sha256", fingerprint],
    // Enrollment scripts (desktop enrollment.ts, docs/operations/mdm-rollout.md).
    ["pair", "--control-plane-url", url, "--grpc-url", url, "--json"],
    ["pair", "--control-plane-url", url, "--grpc-url", url, "--json", "--server-ca-sha256", fingerprint],
    ["pair", "--enrollment-code", enrollmentCode, "--control-plane-url", url, "--grpc-url", url, "--name", "LAPTOP-042"],
    ["pair", "--control-plane-url", url, "--grpc-url", url, "--no-remote-commands", "--json"],
    ["pair", "--control-plane-url", url, "--grpc-url", url, "--no-remote-actions", "--json"],
    ["service", "install"],
    ["doctor", "--check", "--max-delivery-age", "60"],
    ["doctor", "--json"],
    ["remove-machine", "--purge", "--yes", "--json"],
    // docs/pairing.md, the release check and the README.
    ["pair", "--code", "ABCDE-FGHIJ", "--name", "Developer Mac", "--control-plane-url", url, "--grpc-url", url, "--consent-profile", "metadata"],
    ["pair", "--code", "ABCDE-FGHIJ", "--name", "e2e", "--consent-profile", "full", "--accept-consent", "--json"],
    ["pair", "--code", "ABCDE-FGHIJ", "--consent-profile", "metadata", "--no-service"],
    ["pair", "--code", "ABCDE-FGHIJ", "--consent-profile", "metadata", "--accept-consent", "--remote-actions", "stop-agents"],
    ["run", "--profile", "full"],
    ["run", "--grpc-url", url],
    ["run", "--control-plane-url", url, "--grpc-url", url, "--profile", "metadata"],
    ["service", "install", "--profile", "full", "--json"],
    ["service", "status", "--json"],
    ["service", "uninstall"],
    ["doctor", "--profile", "full", "--json"],
    ["doctor", "--check", "--json"],
    ["update", "--check", "--json"],
    ["update", "--yes"],
    ["discover", "--json"],
    ["ingest", "--agent", "cursor", "--quiet"],
    ["ingest", "--agent", "custom", "--name", "Acme Research Agent", "--quiet", "--json"],
    ["agent", "add", "--id", "release-bot", "--name", "Release Bot", "--executable", "release-bot", "--executable", "rb",
      "--process", "release-bot-worker", "--config-path", "~/.release-bot", "--activity-dir", "~/.release-bot/sessions", "--capability", "activity", "--json"],
    ["agent", "list"],
    ["agent", "remove", "--id", "release-bot", "--yes", "--json"],
    ["authorize-action", "--agent", "codex:worker-1", "--action", "command.execute", "--resource", "git status",
      "--context-file", "./phigon-action-context.json", "--process-id", "4120", "--process-started-at", "2026-11-08T10:00:00Z", "--json"],
    ["guardian"],
    ["guardian", "--json"],
    ["guardian", "status", "--json"],
    ["guardian", "exec", "--agent", "codex:worker-1", "--", "npm", "test", "--json", "--help"],
    ["guardian", "launch", "--agent", "claude-code:worker-1", "--model", "anthropic:claude-sonnet-4-5", "--context-file", "c.json", "--", "claude"],
    ["remove-machine"],
    ["unpair", "--yes", "--json"],
    // Both "--option value" and "--option=value", and a trailing "--".
    ["doctor", "--profile=full", "--max-delivery-age=30", "--check"],
    ["pair", "--code=ABCDE-FGHIJ", "--consent-profile=metadata", "--name=-laptop-", "--"],
  ]) {
    assert.doesNotThrow(() => check(argv), argv.join(" "));
  }
});

test("a misspelled or unknown option is refused, with the option it was probably meant to be", () => {
  assert.equal(refusal(["discover", "--jsno"]), "discover has no option --jsno. Did you mean --json?");
  // Allowing everything it was meant to refuse.
  assert.equal(refusal(["pair", "--code", "ABCDE-FGHIJ", "--no-remote-command"]), "pair has no option --no-remote-command. Did you mean --no-remote-commands?");
  assert.equal(refusal(["pair", "--profile", "full"]), "pair has no option --profile. Did you mean --consent-profile?");
  assert.equal(refusal(["service", "install", "-json"]), "service install has no option -json. Did you mean --json?");
  assert.equal(refusal(["discover", "--profile", "full"]), "--profile is supported only by doctor, run and service install.");
  assert.equal(refusal(["run", "--json"]), "run has no option --json. Run phigon-observer help to see the options it takes.");
  assert.equal(refusal(["update", "--purge"]), "--purge is supported only by remove-machine and unpair.");
  // Only the option's name is repeated, never what follows the = sign.
  const message = refusal(["pair", `--enrollment-cod=${enrollmentCode}`]);
  assert.match(message, /Did you mean --enrollment-code\?/u);
  assert.equal(message.includes(enrollmentCode), false);
});

test("values must be there, given once, and only for options that take one", () => {
  assert.equal(refusal(["pair", "--code"]), "--code needs a value: --code <one-time-code>.");
  assert.equal(refusal(["pair", "--server-ca-sha256", "--json"]), "--server-ca-sha256 needs a value: --server-ca-sha256 <fingerprint>.");
  assert.equal(refusal(["pair", "--name="]), "--name needs a value: --name <machine-name>.");
  assert.equal(refusal(["doctor", "--profile", " "]), "--profile needs a value: --profile <metadata|full>.");
  assert.equal(refusal(["discover", "--json=true"]), "--json takes no value. Remove the = and what follows it.");
  assert.equal(refusal(["pair", "--consent-profile", "metadata", "--consent-profile=full"]), "--consent-profile was given more than once. Give it once.");
  assert.equal(refusal(["remove-machine", "--yes", "--yes"]), "--yes was given more than once. Give it once.");
  assert.equal(refusal(["discover", "--json", "--json"]), "--json was given more than once. Give it once.");
  // A value with spaces that was not quoted leaves a word without an option.
  assert.equal(
    refusal(["pair", "--code", "ABCDE-FGHIJ", "--name", "My", "Laptop"]),
    "pair got a value without an option. Put each value right after its option, in quotes if it has spaces.",
  );
  assert.equal(
    refusal(["guardian", "exec", "npm", "test"]),
    "Put the program to run after --: phigon-observer guardian exec [options] -- <program> [arguments...].",
  );
});

test("only guardian exec and launch take anything after --", () => {
  assert.equal(refusal(["discover", "--", "--json"]), "discover takes nothing after --. Remove the -- and what follows it.");
  assert.equal(refusal(["guardian", "--", "status"]), "guardian status takes nothing after --. Remove the -- and what follows it.");
  assert.doesNotThrow(() => check(["guardian", "exec", "--", "git", "--help"]));
});

test("a subcommand a command does not have is left to the command, which says which it has", () => {
  for (const argv of [["guardian", "off"], ["guardian", "containment", "off"], ["service", "instal", "--x"], ["agent"], ["service", "--json"]]) {
    assert.doesNotThrow(() => check(argv), argv.join(" "));
  }
  assert.equal(isCommand("service"), true);
  assert.equal(isCommand("unpair"), true);
  assert.equal(isCommand("serv"), false);
  assert.equal(isCommand("observe"), false);
});

test("suggestions allow a typo or two, a swap, or a unique part of the name", () => {
  assert.equal(editDistance("jsno", "json"), 1);
  assert.equal(editDistance("profle", "profile"), 1);
  assert.equal(editDistance("", "abc"), 3);
  assert.equal(editDistance("kitten", "sitting"), 3);
  assert.equal(closestOption("--yse", ["--yes", "--json"]), "--yes");
  assert.equal(closestOption("--js", ["--json"]), undefined);
  assert.equal(closestOption("--remote", ["--no-remote-commands", "--no-remote-actions"]), undefined);
  assert.equal(closestOption("--", ["--json"]), undefined);
  assert.equal(closestOption("--enrollment", ["--code", "--enrollment-code"]), "--enrollment-code");
});

test("a misspelled option stops the command before it does anything", async () => {
  let stdout = "";
  let stderr = "";
  const code = await run(["discover", "--jsno"], {}, {
    stdout: (value) => { stdout += value; },
    stderr: (value) => { stderr += value; },
  });
  assert.equal(code, 2);
  assert.equal(stdout, "");
  assert.equal(stderr, "Observer command failed: discover has no option --jsno. Did you mean --json?\n");
});

test("the help text and the table of options agree", async () => {
  let help = "";
  assert.equal(await run(["help"], {}, { stdout: (value) => { help += value; }, stderr: () => undefined }), 0);
  const documented = new Map<string, Set<string>>();
  for (const line of help.split("\n")) {
    const at = line.indexOf("phigon-observer ");
    if (at < 0 || !line.startsWith("  ")) continue;
    const words = line.slice(at + "phigon-observer ".length).split(" ");
    const label = [words[0], words[1]].filter((word) => word !== undefined && /^[a-z][a-z-]*$/u.test(word)).join(" ");
    const name = commandOptions[label] !== undefined ? label : words[0] ?? "";
    if (commandOptions[name] === undefined) continue;
    const options = documented.get(name) ?? new Set<string>();
    for (const option of line.match(/--[a-z][a-z0-9-]*/gu) ?? []) options.add(option);
    documented.set(name, options);
  }
  for (const [name, spec] of Object.entries(commandOptions)) {
    const options = documented.get(name);
    assert.ok(options !== undefined, `help has no usage line for ${name}`);
    for (const option of options) assert.ok(spec.options[option] !== undefined, `help shows ${option} for ${name}, which does not take it`);
    for (const [option, details] of Object.entries(spec.options)) {
      if (details.unlisted === true) continue;
      assert.ok(options.has(option), `help does not show ${option} for ${name}`);
    }
  }
});
