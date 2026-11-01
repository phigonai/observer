import assert from "node:assert/strict";
import test from "node:test";
import { noticeAgentName, plainText, platformNoticeSender, UserNotices, type UserNotice } from "../src/user-notices.js";

test("notices say what Phigon did in plain words, once per action", async () => {
  const sent: UserNotice[] = [];
  let now = 1_000_000;
  const notices = new UserNotices({ enabled: true, now: () => now, send: async (notice) => { sent.push(notice); } });
  notices.agentStopped({ key: "a1", agent: "Claude Code", forced: false, reason: "Stopped Claude Code from the Phigon app." });
  notices.agentStopped({ key: "a1", agent: "Claude Code", forced: false, reason: "Repeated." });
  notices.agentStopped({ key: "a2", agent: "Codex", forced: true, reason: " " });
  notices.agentBlocked({ key: "b1", agent: "Cursor", reason: "" });
  notices.commandRan({ key: "c1", program: "node", reason: "Check the Node version" });
  notices.powerChange({ key: "p1", restart: true, reason: "Monthly updates." });
  now += 61_000;
  notices.agentStopped({ key: "a1", agent: "Claude Code", forced: false, reason: "Again, a minute later." });
  assert.deepEqual(sent, [
    { title: "Claude Code was stopped by Phigon", body: "Stopped Claude Code from the Phigon app." },
    { title: "Codex was force-stopped by Phigon", body: "Your workspace administrator's rules stopped it." },
    { title: "Cursor was stopped by Phigon", body: "Cursor is blocked on this computer by your workspace administrator." },
    { title: "Phigon ran node on this computer", body: "Check the Node version" },
    { title: "Phigon will restart this computer in 1 minute", body: "Save your work now. Monthly updates." },
    { title: "Claude Code was stopped by Phigon", body: "Again, a minute later." },
  ]);
});

test("turned off, or failing, a notice never affects anything", async () => {
  let sent = 0;
  new UserNotices({ enabled: false, send: async () => { sent++; } }).agentStopped({ key: "a", agent: "Codex", forced: false, reason: "x" });
  assert.equal(sent, 0);
  const failing = new UserNotices({ enabled: true, send: async () => { throw new Error("no desktop session"); } });
  assert.doesNotThrow(() => failing.agentStopped({ key: "a", agent: "Codex", forced: false, reason: "x" }));
  await new Promise((resolve) => setImmediate(resolve));
});

test("notice text is one bounded line, and agents keep their own names", () => {
  assert.equal(plainText("Line one\r\n\tline\u0007 two  ", 100), "Line one line two");
  assert.equal(plainText("x".repeat(300), 10), `${"x".repeat(9)}…`);
  assert.equal(noticeAgentName("Claude Code · PID 4120"), "Claude Code");
  assert.equal(noticeAgentName(""), "An AI agent");
  assert.equal(typeof platformNoticeSender("win32"), "function");
  assert.equal(typeof platformNoticeSender("darwin"), "function");
  assert.equal(typeof platformNoticeSender("linux"), "function");
  assert.equal(platformNoticeSender("aix"), undefined);
});
