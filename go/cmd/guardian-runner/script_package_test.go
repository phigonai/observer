package main

import (
	"reflect"
	"testing"
)

// The same cases are in test/script-package.test.ts, so the helper
// and the PowerShell fallback agree.
func TestScriptPackageFromWindowsCommandLines(t *testing.T) {
	for _, test := range []struct {
		image, commandLine, want string
	}{
		// npm's global .cmd shim, with its doubled separator.
		{"node.exe", `"C:\Program Files\nodejs\node.exe"  "C:\Users\dev\AppData\Roaming\npm\\node_modules\@google\gemini-cli\dist\index.js" --yolo`, "@google/gemini-cli"},
		{"node.exe", `"C:\Program Files\nodejs\node.exe" C:\Users\dev\AppData\Roaming\npm\node_modules\@google\gemini-cli\dist\index.js`, "@google/gemini-cli"},
		// npm's PowerShell shim mixes separators.
		{"NODE.EXE", `"C:\Program Files\nodejs\node.exe" C:\Users\dev\AppData\Roaming\npm/node_modules/@anthropic-ai/claude-code/cli.js --resume`, "@anthropic-ai/claude-code"},
		// A user folder with a space, and nvm-windows.
		{"node.exe", `"C:\nvm4w\nodejs\node.exe" "C:\Users\Dev User\AppData\Local\nvm\v22.12.0\node_modules\@github\copilot\npm-loader.js"`, "@github/copilot"},
		// Gemini CLI relaunches itself with memory options first.
		{"node.exe", `"C:\Program Files\nodejs\node.exe" --max-old-space-size=8192 --require C:\hooks\preload.js C:\Users\dev\AppData\Roaming\npm\node_modules\@google\gemini-cli\dist\index.js`, "@google/gemini-cli"},
		{"node.exe", `node -r C:\x\node_modules\@google\gemini-cli\register.js C:\work\server.js`, ""},
		// pnpm's store keeps the real package after the last node_modules.
		{"node.exe", `node C:\Users\dev\AppData\Local\pnpm\global\5\node_modules\.pnpm\@sourcegraph+amp@0.0.1\node_modules\@sourcegraph\amp\dist\main.js`, "@sourcegraph/amp"},
		{"bun.exe", `bun run C:\Users\dev\.bun\install\global\node_modules\@google\gemini-cli\dist\index.js`, "@google/gemini-cli"},
		{"node.exe", `node C:\work\project\server.js --port 3000`, ""},
		{"node.exe", `node C:\work\build.js C:\work\node_modules\@google\gemini-cli\dist\index.js`, ""},
		{"node.exe", `node -e "require('C:/x/node_modules/@google/gemini-cli')"`, ""},
		{"node.exe", `node C:\work\node_modules\.bin\gemini`, ""},
		{"node.exe", `node C:\work\node_modules\@google`, ""},
		{"node.exe", ``, ""},
		// Only interpreters are attributed.
		{"codex.exe", `codex.exe C:\Users\dev\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js`, ""},
	} {
		if got := scriptPackage(test.image, test.commandLine); got != test.want {
			t.Errorf("scriptPackage(%q, %q) = %q, want %q", test.image, test.commandLine, got, test.want)
		}
	}
}

func TestWindowsArgumentsFollowTheCRuntimeRules(t *testing.T) {
	for _, test := range []struct {
		commandLine string
		want        []string
	}{
		{`"C:\Program Files\nodejs\node.exe" a "b c" d`, []string{`C:\Program Files\nodejs\node.exe`, "a", "b c", "d"}},
		{`node  "C:\a b\\node_modules\x"`, []string{"node", `C:\a b\\node_modules\x`}},
		{`node a\\\"b "c\\" d`, []string{"node", `a\"b`, `c\`, "d"}},
		{`node "say ""hi"""`, []string{"node", `say "hi"`}},
		{`  node	tab`, []string{"node", "tab"}},
		{``, []string{""}},
	} {
		if got := windowsArguments(test.commandLine); !reflect.DeepEqual(got, test.want) {
			t.Errorf("windowsArguments(%q) = %q, want %q", test.commandLine, got, test.want)
		}
	}
}

func TestPackageNamesAreValidated(t *testing.T) {
	for path, want := range map[string]string{
		"/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js": "@anthropic-ai/claude-code",
		"/x/node_modules/Left-Pad/index.js":                            "left-pad",
		"/x/node_modules/_private/index.js":                            "",
		"/x/node_modules/@scope/.hidden/index.js":                      "",
		"/x/node_modules/na me/index.js":                               "",
		"/x/node_modules":                                              "",
		"/x/lib/cli.js":                                                "",
	} {
		if got := packageFromScriptPath(path); got != want {
			t.Errorf("packageFromScriptPath(%q) = %q, want %q", path, got, want)
		}
	}
}
