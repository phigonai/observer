package main

import "strings"

// Agents installed with npm (Gemini CLI, GitHub Copilot CLI, Amp, Claude
// Code) run as their JavaScript runtime, so the image name (node.exe) does
// not say which agent a process is. For interpreter processes only, the
// listing reads the command line and reports just the npm package that owns
// the script being run: the folder after the last node_modules.
//
// A command line can hold secrets. It is parsed in memory and dropped; it is
// never printed, logged or returned. The observer applies the same rules to
// PowerShell's listing (src/discovery/script-package.ts); keep the
// two in step.

const (
	maxPackageNameLength = 214
	// Windows limits a command line to 32,767 UTF-16 characters.
	maxCommandLineCharacters = 32_767
)

// Interpreter options that take their value as the next argument.
var separateValueOptions = map[string]bool{
	"-r": true, "--require": true, "--import": true, "--loader": true,
	"--experimental-loader": true, "-C": true, "--conditions": true,
	"--input-type": true, "--env-file": true, "--title": true,
	"--inspect-port": true, "--preload": true, "--cwd": true, "--config": true,
}

// Options after which the interpreter runs code that is not a script file.
var inlineCodeOptions = map[string]bool{
	"-e": true, "--eval": true, "-p": true, "--print": true, "-pe": true,
}

// interpreterName is an image name as the observer normalizes it: lower
// case, without .exe.
func interpreterName(imageName string) string {
	return strings.TrimSuffix(strings.ToLower(imageName), ".exe")
}

func isInterpreter(imageName string) bool {
	switch interpreterName(imageName) {
	case "node", "bun", "deno":
		return true
	}
	return false
}

// scriptPackage returns the npm package whose script an interpreter's
// Windows command line runs, or "".
func scriptPackage(imageName, commandLine string) string {
	if !isInterpreter(imageName) {
		return ""
	}
	script, ok := scriptArgument(interpreterName(imageName), windowsArguments(commandLine))
	if !ok {
		return ""
	}
	return packageFromScriptPath(script)
}

// windowsArguments splits a command line as CommandLineToArgvW and the
// Microsoft C runtime do: the program name ends at the first space outside
// quotes, and later arguments follow the quote and backslash rules. The
// special characters are ASCII, so walking UTF-8 bytes is safe.
func windowsArguments(commandLine string) []string {
	line := commandLine
	if len(line) > 3*maxCommandLineCharacters {
		line = line[:3*maxCommandLineCharacters]
	}
	blank := func(index int) bool { return line[index] == ' ' || line[index] == '\t' }
	index := 0
	for index < len(line) && blank(index) {
		index++
	}
	var program strings.Builder
	quoted := false
	for ; index < len(line); index++ {
		if line[index] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted && blank(index) {
			break
		}
		program.WriteByte(line[index])
	}
	values := []string{program.String()}
	for {
		for index < len(line) && blank(index) {
			index++
		}
		if index >= len(line) {
			return values
		}
		var value strings.Builder
		quoted = false
		for index < len(line) && (quoted || !blank(index)) {
			switch character := line[index]; character {
			case '\\':
				backslashes := 0
				for index < len(line) && line[index] == '\\' {
					backslashes++
					index++
				}
				if index < len(line) && line[index] == '"' {
					value.WriteString(strings.Repeat(`\`, backslashes/2))
					if backslashes%2 == 1 {
						value.WriteByte('"')
						index++
					}
				} else {
					value.WriteString(strings.Repeat(`\`, backslashes))
				}
			case '"':
				if quoted && index+1 < len(line) && line[index+1] == '"' {
					value.WriteByte('"')
					index += 2
					continue
				}
				quoted = !quoted
				index++
			default:
				value.WriteByte(character)
				index++
			}
		}
		values = append(values, value.String())
	}
}

// scriptArgument returns the script an interpreter runs: the first argument
// that is not one of its options. Code given inline (node -e) or on standard
// input has no script.
func scriptArgument(interpreter string, values []string) (string, bool) {
	index := 1
	if (interpreter == "bun" || interpreter == "deno") && index < len(values) && values[index] == "run" {
		index++
	}
	for ; index < len(values); index++ {
		value := values[index]
		switch {
		case value == "--":
			if index+1 < len(values) {
				return values[index+1], true
			}
			return "", false
		case value == "-":
			return "", false
		case strings.HasPrefix(value, "-"):
			name, _, hasValue := strings.Cut(value, "=")
			if inlineCodeOptions[name] {
				return "", false
			}
			if !hasValue && separateValueOptions[name] {
				index++
			}
		default:
			return value, true
		}
	}
	return "", false
}

// packageFromScriptPath returns the npm package that owns a script: the
// folder after the last node_modules (@scope/name or name), in lower case.
// Anything that is not a valid package name, such as .bin, gives "".
func packageFromScriptPath(path string) string {
	segments := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
	last := -1
	for index := len(segments) - 1; index >= 0; index-- {
		if strings.EqualFold(segments[index], "node_modules") {
			last = index
			break
		}
	}
	if last == -1 || last+1 >= len(segments) {
		return ""
	}
	name := strings.ToLower(segments[last+1])
	if strings.HasPrefix(name, "@") {
		if last+2 >= len(segments) {
			return ""
		}
		name += "/" + strings.ToLower(segments[last+2])
	}
	if !validPackageName(name) {
		return ""
	}
	return name
}

func validPackageName(name string) bool {
	if name == "" || len(name) > maxPackageNameLength {
		return false
	}
	scope, rest, scoped := strings.Cut(name, "/")
	if !scoped {
		return validPackageSegment(name)
	}
	return strings.HasPrefix(scope, "@") && validPackageSegment(scope[1:]) && validPackageSegment(rest)
}

// validPackageSegment matches ^[a-z0-9~-][a-z0-9._~-]*$.
func validPackageSegment(segment string) bool {
	if segment == "" || segment[0] == '.' || segment[0] == '_' {
		return false
	}
	for index := 0; index < len(segment); index++ {
		character := segment[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '.' && character != '_' && character != '~' && character != '-' {
			return false
		}
	}
	return true
}
