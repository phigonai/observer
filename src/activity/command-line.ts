/**
 * What a shell command line runs, read without running a shell: the program
 * and, for Git and GitHub CLI commands, the operation.
 */

/** A Git command and its operation, such as git -C repo status. */
export const gitCommandPattern =
  /(?:^|\s)git(?:\s+-C\s+\S+)?\s+(status|diff|commit|branch|switch|checkout|push|pull)\b/iu;
/** A GitHub CLI pull request command and its operation. */
export const pullRequestCommandPattern =
  /(?:^|\s)gh\s+pr\s+(create|view|list|checks|merge|close|reopen)\b/iu;

/**
 * The program a command line runs and its Git or pull request operation,
 * without arguments, paths or values: git status, gh pr create, npm. It is
 * what the metadata profile learns from a command, kept where the command
 * itself must not be.
 */
export function commandSummary(command: string): string {
  const program = executableFromCommand(command);
  const words = program === "" ? [] : [program];
  const operation = gitCommandPattern.exec(command)?.[1]?.toLowerCase();
  if (operation !== undefined) words.push(...(program === "git" ? [] : ["git"]), operation);
  const pullRequest = pullRequestCommandPattern.exec(command)?.[1]?.toLowerCase();
  if (pullRequest !== undefined) words.push(...(program === "gh" ? [] : ["gh"]), "pr", pullRequest);
  return words.join(" ");
}

/**
 * The program a command line runs, without its folder. Leading variable
 * assignments (`TOKEN=… gh pr create`, PowerShell `$env:TOKEN=…;`) and
 * wrappers such as env, sudo, nohup and timeout are skipped: the first word
 * can hold a credential, and the program after the wrapper is the one that
 * matters. The result still passes through redaction in safeName.
 */
export function executableFromCommand(command: string): string {
  const words = shellWords(command.slice(0, maxCommandScan));
  let index = 0;
  let wrapper: string | undefined;
  // A wrapper with nothing after it, such as `env` alone, is the program.
  let lastWrapper = "";
  while (index < words.length) {
    const word = words[index] ?? "";
    if (word === "" || isAssignment(word)) {
      index++;
      continue;
    }
    if (wrapper !== undefined) {
      if (word === "--") {
        index++;
        continue;
      }
      if (word.startsWith("-")) {
        const options = commandWrappers.get(wrapper);
        index += options?.has(word) === true ? 2 : 1;
        continue;
      }
      // timeout DURATION, taskset MASK and chrt PRIORITY come before the
      // program they run.
      if (wrapperOperands.has(wrapper)) {
        wrapper = undefined;
        index++;
        continue;
      }
    }
    const name = word.split(/[\\/]/u).pop() ?? "";
    if (commandWrappers.has(name)) {
      wrapper = name;
      lastWrapper = name;
      index++;
      continue;
    }
    return name;
  }
  return lastWrapper;
}

// Wrappers, and their options that take the next word as a value.
const commandWrappers: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["env", new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-a", "--argv0"])],
  ["sudo", new Set(["-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-r", "--role", "-t", "--type", "-C", "--close-from", "-D", "--chdir", "-R", "--chroot", "-T", "--command-timeout", "-U", "--other-user"])],
  ["doas", new Set(["-u", "-C"])],
  ["command", new Set()],
  ["builtin", new Set()],
  ["exec", new Set(["-a"])],
  ["nohup", new Set()],
  ["time", new Set(["-f", "--format", "-o", "--output"])],
  ["nice", new Set(["-n", "--adjustment"])],
  ["ionice", new Set(["-c", "--class", "-n", "--classdata"])],
  ["timeout", new Set(["-s", "--signal", "-k", "--kill-after"])],
  ["stdbuf", new Set(["-i", "--input", "-o", "--output", "-e", "--error"])],
  ["taskset", new Set()],
  ["chrt", new Set()],
]);
const wrapperOperands = new Set(["timeout", "taskset", "chrt"]);
const maxCommandScan = 8 << 10;
const maxCommandWords = 64;

function isAssignment(word: string): boolean {
  return /^(?:[A-Za-z_][A-Za-z0-9_]*|\$(?:env:)?[A-Za-z_][A-Za-z0-9_]*)=/u.test(word);
}

/**
 * The first words of a command line, unquoted the way a POSIX shell would.
 * A separator (`;`, `&`, `|`) ends the simple command; when every word before
 * it was an assignment, the next command is read instead. A backslash
 * escapes only shell-special characters, so Windows paths stay whole.
 */
function shellWords(command: string): string[] {
  const words: string[] = [];
  let word = "";
  let inWord = false;
  let quote: "'" | "\"" | undefined;
  const finish = (): void => {
    if (inWord) words.push(word);
    word = "";
    inWord = false;
  };
  for (let index = 0; index < command.length; index++) {
    if (words.length >= maxCommandWords) break;
    const character = command[index] ?? "";
    const next = command[index + 1] ?? "";
    if (quote === "'") {
      if (character === "'") quote = undefined;
      else word += character;
      continue;
    }
    if (quote === "\"") {
      if (character === "\"") quote = undefined;
      else if (character === "\\" && /["\\$`]/u.test(next)) {
        word += next;
        index++;
      } else word += character;
      continue;
    }
    if (character === "'" || character === "\"") {
      quote = character;
      inWord = true;
      continue;
    }
    if (character === "\\" && /[\s'"\\$`;&|]/u.test(next)) {
      word += next;
      inWord = true;
      index++;
      continue;
    }
    if (/\s/u.test(character)) {
      finish();
      continue;
    }
    if (character === ";" || character === "&" || character === "|") {
      finish();
      if (words.some((item) => !isAssignment(item))) break;
      words.length = 0;
      continue;
    }
    word += character;
    inWord = true;
  }
  finish();
  return words;
}
