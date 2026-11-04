import assert from "node:assert/strict";
import test from "node:test";
import type { StoredMachineCredential } from "../src/credential-store.js";
import { remoteActionConsent, remoteActionSentence, remoteActionsAllowed } from "../src/remote-actions.js";

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
  assert.equal(remoteActionConsent([]), "all");
  assert.equal(remoteActionConsent(["--no-remote-commands"]), "stop_agents");
  assert.equal(remoteActionConsent(["--no-remote-actions"]), "none");
  assert.equal(remoteActionConsent(["--no-remote-commands", "--no-remote-actions"]), "none");
});

test("a computer allows what was consented to when it paired", () => {
  assert.deepEqual(remoteActionsAllowed({ ...paired, remoteActions: "all" }, {}, off), { stopAgents: true, commands: true });
  assert.deepEqual(remoteActionsAllowed({ ...paired, remoteActions: "stop_agents" }, {}, off), { stopAgents: true, commands: false });
  assert.deepEqual(remoteActionsAllowed({ ...paired, remoteActions: "none" }, {}, off), { stopAgents: false, commands: false });
  // Paired before it was asked: nothing is turned on without consent.
  assert.deepEqual(remoteActionsAllowed(paired, {}, off), { stopAgents: false, commands: false });
});

test("the observer's settings override the consent stored with the pairing", () => {
  const consented = { ...paired, remoteActions: "all" as const };
  assert.deepEqual(
    remoteActionsAllowed(consented, { PHIGON_REMOTE_ACTIONS_ENABLED: "false", PHIGON_REMOTE_COMMANDS_ENABLED: "false" }, off),
    { stopAgents: false, commands: false },
  );
  assert.deepEqual(
    remoteActionsAllowed(paired, { PHIGON_REMOTE_ACTIONS_ENABLED: "true" }, { ...off, remoteActionsEnabled: true }),
    { stopAgents: true, commands: false },
  );
  // An empty setting is no setting.
  assert.deepEqual(remoteActionsAllowed(consented, { PHIGON_REMOTE_ACTIONS_ENABLED: " " }, off), { stopAgents: true, commands: true });
});

test("the person at the computer is told what administrators may do", () => {
  assert.match(remoteActionSentence("all"), /stop AI agents on this computer and run the commands they approve\. You see a notification each time\./u);
  assert.match(remoteActionSentence("stop_agents"), /can stop AI agents on this computer\./u);
  assert.match(remoteActionSentence("none"), /cannot stop agents or run commands/u);
});
