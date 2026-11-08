import assert from "node:assert/strict";
import test from "node:test";
import type { StoredMachineCredential } from "../src/credential-store.js";
import { UsageError } from "../src/command-options.js";
import { containmentAllowed, remoteActionConsent, remoteActionSentence, remoteActionsAllowed, statedRemoteActions } from "../src/remote-actions.js";

// Machine keys are built at run time, so no key-shaped text is stored.
const paired: StoredMachineCredential = {
  machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
  tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
  credential: ["phg", "m", "r".repeat(43)].join("_"),
  controlPlaneOrigin: "https://192.168.1.11:17080",
  createdAt: "2026-11-04T00:00:00.000Z",
};
const off = { remoteActionsEnabled: false, remoteCommandsEnabled: false };

test("pairing lets administrators stop agents and run approved commands unless the owner leaves them out", () => {
  for (const consent of ["prompt", "accepted", "enrollment"] as const) {
    assert.equal(remoteActionConsent(["--no-remote-commands"], consent), "stop_agents");
    assert.equal(remoteActionConsent(["--no-remote-actions"], consent), "none");
    assert.equal(remoteActionConsent(["--no-remote-commands", "--no-remote-actions"], consent), "none");
    assert.equal(remoteActionConsent(["--remote-actions", "all"], consent), "all");
    assert.equal(remoteActionConsent(["--remote-actions=stop-agents"], consent), "stop_agents");
    assert.equal(remoteActionConsent(["--remote-actions", "none"], consent), "none");
    // Saying the same thing twice is no contradiction.
    assert.equal(remoteActionConsent(["--remote-actions", "stop-agents", "--no-remote-commands"], consent), "stop_agents");
    assert.equal(remoteActionConsent(["--remote-actions", "none", "--no-remote-actions", "--no-remote-commands"], consent), "none");
  }
});

test("without a choice, only an owner who read the consent prompt, or a company's code, allows both", () => {
  // The prompt says administrators may stop agents and run commands, and how to allow less.
  assert.equal(remoteActionConsent([], "prompt"), "all");
  // --accept-consent (and so --json) skips the prompt: the owner never read that sentence.
  assert.equal(remoteActionConsent(["--accept-consent", "--json"], "accepted"), "none");
  // The company's enrollment policy is the consent.
  assert.equal(remoteActionConsent(["--json"], "enrollment"), "all");
  assert.equal(statedRemoteActions(["--accept-consent"]), undefined);
});

test("contradictory or unknown remote action choices are refused as usage errors", () => {
  for (const [flags, message] of [
    [["--remote-actions", "all", "--no-remote-commands"], "--remote-actions all contradicts --no-remote-commands. Use --remote-actions alone."],
    [["--remote-actions", "all", "--no-remote-actions"], "--remote-actions all contradicts --no-remote-actions. Use --remote-actions alone."],
    [["--remote-actions", "stop-agents", "--no-remote-actions"], "--remote-actions stop-agents contradicts --no-remote-actions. Use --remote-actions alone."],
    [["--remote-actions", "stop_agents"], "--remote-actions must be all, stop-agents or none."],
    [["--remote-actions=everything"], "--remote-actions must be all, stop-agents or none."],
    // Names every object has are not choices either.
    [["--remote-actions", "constructor"], "--remote-actions must be all, stop-agents or none."],
    [["--remote-actions=toString"], "--remote-actions must be all, stop-agents or none."],
    [["--remote-actions", "__proto__"], "--remote-actions must be all, stop-agents or none."],
  ] as const) {
    assert.throws(() => remoteActionConsent(flags, "prompt"), (error: unknown) =>
      error instanceof UsageError && error.exitCode === 2 && error.message === message, flags.join(" "));
  }
});

test("a computer allows what was consented to when it paired", () => {
  assert.deepEqual(remoteActionsAllowed({ ...paired, remoteActions: "all" }, {}, off), { stopAgents: true, commands: true });
  assert.deepEqual(remoteActionsAllowed({ ...paired, remoteActions: "stop_agents" }, {}, off), { stopAgents: true, commands: false });
  assert.deepEqual(remoteActionsAllowed({ ...paired, remoteActions: "none" }, {}, off), { stopAgents: false, commands: false });
  // Paired before it was asked: nothing is turned on without consent.
  assert.deepEqual(remoteActionsAllowed(paired, {}, off), { stopAgents: false, commands: false });
});

test("the observer's settings can narrow the consent stored with the pairing, never widen it", () => {
  const consented = { ...paired, remoteActions: "all" as const };
  assert.deepEqual(
    remoteActionsAllowed(consented, { PHIGON_REMOTE_ACTIONS_ENABLED: "false", PHIGON_REMOTE_COMMANDS_ENABLED: "false" }, off),
    { stopAgents: false, commands: false },
  );
  // Settings saved before 8.8 to make Stop work do not overrule an owner who said no since.
  const on = { remoteActionsEnabled: true, remoteCommandsEnabled: true };
  const settings = { PHIGON_REMOTE_ACTIONS_ENABLED: "true", PHIGON_REMOTE_COMMANDS_ENABLED: "true" };
  assert.deepEqual(remoteActionsAllowed({ ...paired, remoteActions: "none" }, settings, on), { stopAgents: false, commands: false });
  assert.deepEqual(remoteActionsAllowed({ ...paired, remoteActions: "stop_agents" }, settings, on), { stopAgents: true, commands: false });
  // A computer paired before the question follows the settings alone, as it always did.
  assert.deepEqual(
    remoteActionsAllowed(paired, { PHIGON_REMOTE_ACTIONS_ENABLED: "true" }, { ...off, remoteActionsEnabled: true }),
    { stopAgents: true, commands: false },
  );
  // An empty setting is no setting.
  assert.deepEqual(remoteActionsAllowed(consented, { PHIGON_REMOTE_ACTIONS_ENABLED: " " }, off), { stopAgents: true, commands: true });
});

test("Guardian stops agents only where the owner did not refuse it", () => {
  // Paired before the question: Guardian keeps the containment it always had.
  assert.equal(containmentAllowed(paired, {}, off), true);
  assert.equal(containmentAllowed({ ...paired, remoteActions: "all" }, {}, off), true);
  assert.equal(containmentAllowed({ ...paired, remoteActions: "stop_agents" }, {}, off), true);
  assert.equal(containmentAllowed({ ...paired, remoteActions: "none" }, {}, off), false);
  assert.equal(containmentAllowed({ ...paired, remoteActions: "all" }, { PHIGON_REMOTE_ACTIONS_ENABLED: "false" }, off), false);
});

test("the person at the computer is told what administrators may do", () => {
  assert.match(remoteActionSentence("all"), /stop AI agents on this computer and run the commands they approve\. You see a notification each time\./u);
  assert.match(remoteActionSentence("stop_agents"), /can stop AI agents on this computer\./u);
  assert.match(remoteActionSentence("none"), /cannot stop agents or run commands/u);
});
