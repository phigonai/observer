import assert from "node:assert/strict";
import test from "node:test";
import { negotiateNativeCapabilities } from "../src/activity/native-capabilities.js";

test("native capability negotiation fails closed when the module is absent", async () => {
  const report = await negotiateNativeCapabilities(
    ["macOS Endpoint Security", "unknown"],
    async () => {
      throw new Error("not installed");
    },
  );

  assert.equal(report.nativeLoaded, false);
  assert.ok(report.capabilities.every((item) => !item.available));
  assert.ok(
    report.capabilities.every(
      (item) => item.permission === "native_unavailable",
    ),
  );
});

test("native capability negotiation validates module responses", async () => {
  const report = await negotiateNativeCapabilities(
    ["native_bridge"],
    async () => ({
      negotiateCapabilities: () => [{
        name: "native_bridge",
        available: true,
        permission: "granted",
        detail: "Loaded.",
      }],
    }),
  );

  assert.equal(report.nativeLoaded, true);
  assert.deepEqual(report.capabilities, [{
    name: "native_bridge",
    available: true,
    permission: "granted",
    detail: "Loaded.",
  }]);
});

test("compiled native module reports privileged capabilities unavailable", {
  skip: process.env["PHIGON_RUN_NATIVE_TESTS"] !== "1",
}, async () => {
  const report = await negotiateNativeCapabilities([
    "native_bridge",
    "macos_endpoint_security",
    "linux_ebpf",
    "windows_etw",
  ]);

  assert.equal(report.nativeLoaded, true);
  assert.equal(report.capabilities[0]?.available, true);
  assert.ok(report.capabilities.slice(1).every((item) => !item.available));
});
