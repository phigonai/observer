import assert from "node:assert/strict";
import { serviceFiles } from "./managed-service.mjs";

for (const platform of ["windows", "linux", "darwin"]) {
  const windows = platform === "windows";
  const files = serviceFiles({ platform, node: windows ? "C:\\Program Files\\nodejs\\node.exe" : "/usr/bin/node",
    observer: windows ? "C:\\Program Files\\Phigon\\dist\\src\\cli.js" : "/opt/phigon/dist/src/cli.js",
    dataDirectory: windows ? "C:\\ProgramData\\Phigon" : "/var/lib/phigon", controlPlane: "https://guardian.example", grpc: "https://grpc.example" });
  assert.equal(Object.keys(files).length, 1);
  const value = Object.values(files)[0];
  assert.ok(value.includes("PHIGON_DATA_DIR"));
  assert.ok(value.includes("https://guardian.example"));
  assert.ok(!value.includes("--shell"));
  if (windows) {
    assert.ok(value.includes("GetAccessRules($true, $true"));
    assert.ok(value.includes("GetOwner([Security.Principal.SecurityIdentifier])"));
  }
}
assert.throws(() => serviceFiles({ platform: "linux", node: "/usr/bin/node\nExecStart=evil", observer: "/opt/phigon/cli.js", dataDirectory: "/var/lib/phigon", controlPlane: "http://insecure", grpc: "https://grpc.example" }));
assert.throws(() => serviceFiles({ platform: "linux", node: "C:\\node.exe", observer: "/opt/phigon/cli.js", dataDirectory: "/var/lib/phigon", controlPlane: "https://guardian.example", grpc: "https://grpc.example" }));
assert.throws(() => serviceFiles({ platform: "linux", node: "/usr/bin/node", observer: "/opt/phigon/cli.js", dataDirectory: "/var/..", controlPlane: "https://guardian.example", grpc: "https://grpc.example" }));
assert.throws(() => serviceFiles({ platform: "windows", node: "C:\\node.exe", observer: "C:\\Phigon\\cli.js", dataDirectory: "C:\\", controlPlane: "https://guardian.example", grpc: "https://grpc.example" }));
process.stdout.write("Guardian service renderers verified for Windows, Linux, and macOS.\n");
