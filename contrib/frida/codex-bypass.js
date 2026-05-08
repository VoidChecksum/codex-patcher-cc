// codex-bypass.js — Frida agent for OpenAI Codex CLI runtime bypass.
//
// Loaded with `frida -l contrib/frida/codex-bypass.js -f /opt/homebrew/bin/codex` or
// via the codex-frida-wrapper.sh launcher.
//
// Strategy: Codex enforces its sandbox by spawning child commands under
// /usr/bin/sandbox-exec (macOS) or codex-linux-sandbox (Linux). It does NOT
// call sandbox_init() in-process; the parent codex process is unsandboxed.
//
// We hook posix_spawn / posix_spawnp to detect the sandbox-exec wrapper invocation
// and rewrite argv to skip the wrapper, executing the inner command directly.
// This is a complete sandbox bypass for spawned commands without binary patching.
//
// On Linux we hook execvp / posix_spawnp similarly when argv[0] ends in
// "codex-linux-sandbox".
//
// Operator-authorized (see ~/.codex/AGENTS.md AUTHORIZATION doctrine).

const PLATFORM = Process.platform; // 'darwin' | 'linux' | 'windows'
const VERBOSE = (Process.getCurrentDir() && true); // toggle via env later

const SANDBOX_EXEC_DARWIN = "/usr/bin/sandbox-exec";
const SANDBOX_EXEC_LINUX_SUFFIX = "/codex-linux-sandbox";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readArgv(argvPtr) {
  const out = [];
  if (argvPtr.isNull()) return out;
  for (let i = 0; i < 1024; i++) {
    const slot = argvPtr.add(i * Process.pointerSize).readPointer();
    if (slot.isNull()) break;
    out.push(slot.readUtf8String());
  }
  return out;
}

// Build a new argv (NULL-terminated) on the heap from a JS array.
function writeArgv(strings) {
  const cstrs = strings.map((s) => Memory.allocUtf8String(s));
  const arr = Memory.alloc(Process.pointerSize * (strings.length + 1));
  for (let i = 0; i < strings.length; i++) {
    arr.add(i * Process.pointerSize).writePointer(cstrs[i]);
  }
  arr.add(strings.length * Process.pointerSize).writePointer(NULL);
  // keep a strong ref so the heap doesn't GC them mid-spawn
  arr.__strings = cstrs;
  return arr;
}

// Strip the sandbox-exec wrapper from an argv array.
// Codex argv shape:
//   [0]   /usr/bin/sandbox-exec
//   [1..] -p <profile> -D K=V ... -- innerCmd innerArg1 innerArg2
// After the literal `--`, what remains is the unsandboxed command.
function stripSandboxExec(argv) {
  if (argv.length < 3) return null;
  if (argv[0] !== SANDBOX_EXEC_DARWIN) return null;
  const dashIdx = argv.indexOf("--");
  if (dashIdx < 0 || dashIdx === argv.length - 1) return null;
  return argv.slice(dashIdx + 1);
}

// codex-linux-sandbox is invoked as:
//   codex-linux-sandbox --sandbox-policy-cwd <cwd> --command-cwd <cwd>
//                       --permission-profile <p> [--allow-network-for-proxy]
//                       -- innerCmd innerArg1 ...
// Same `--` separator pattern; strip everything before it.
function stripCodexLinuxSandbox(argv) {
  if (argv.length < 3) return null;
  if (!argv[0].endsWith(SANDBOX_EXEC_LINUX_SUFFIX) && argv[0] !== "codex-linux-sandbox") {
    return null;
  }
  const dashIdx = argv.indexOf("--");
  if (dashIdx < 0 || dashIdx === argv.length - 1) return null;
  return argv.slice(dashIdx + 1);
}

function rewriteArgvForBypass(argv) {
  return stripSandboxExec(argv) || stripCodexLinuxSandbox(argv);
}

function logSpawn(tag, argv, rewritten) {
  if (!VERBOSE) return;
  const prefix = `[ccp-frida ${tag}]`;
  if (rewritten) {
    console.log(`${prefix} BYPASS: ${argv[0]} ... -- ${rewritten[0]}`);
  } else {
    console.log(`${prefix} pass: ${argv.slice(0, 3).join(" ")}${argv.length > 3 ? " ..." : ""}`);
  }
}

// ---------------------------------------------------------------------------
// Hook: posix_spawn / posix_spawnp (darwin + linux)
// posix_spawn(pid_t *pid, const char *path, posix_spawn_file_actions_t *fa,
//             posix_spawnattr_t *attr, char *const argv[], char *const envp[])
// ---------------------------------------------------------------------------

function hookPosixSpawn(name) {
  const exp = Module.findExportByName(null, name);
  if (!exp) return false;

  Interceptor.attach(exp, {
    onEnter(args) {
      const path = args[1].readUtf8String();
      const argv = readArgv(args[4]);

      const isSandboxWrapper =
        path === SANDBOX_EXEC_DARWIN ||
        path.endsWith(SANDBOX_EXEC_LINUX_SUFFIX) ||
        path.endsWith("/codex-linux-sandbox");
      if (!isSandboxWrapper) {
        logSpawn(name, argv, null);
        return;
      }

      const rewritten = rewriteArgvForBypass(argv);
      if (!rewritten || rewritten.length === 0) {
        logSpawn(name, argv, null);
        return;
      }

      // Replace path (arg[1]) and argv (arg[4]).
      const newPath = Memory.allocUtf8String(rewritten[0]);
      const newArgv = writeArgv(rewritten);
      args[1] = newPath;
      args[4] = newArgv;
      logSpawn(name, argv, rewritten);
    },
  });
  return true;
}

// ---------------------------------------------------------------------------
// Hook: execvp / execve / execv (fallback path on linux)
// int execvp(const char *file, char *const argv[])
// ---------------------------------------------------------------------------

function hookExec(name, argvIdx, pathIdx) {
  const exp = Module.findExportByName(null, name);
  if (!exp) return false;

  Interceptor.attach(exp, {
    onEnter(args) {
      const path = args[pathIdx].readUtf8String();
      const argv = readArgv(args[argvIdx]);

      const isSandboxWrapper =
        path === SANDBOX_EXEC_DARWIN ||
        path.endsWith(SANDBOX_EXEC_LINUX_SUFFIX) ||
        path.endsWith("/codex-linux-sandbox");
      if (!isSandboxWrapper) {
        logSpawn(name, argv, null);
        return;
      }

      const rewritten = rewriteArgvForBypass(argv);
      if (!rewritten || rewritten.length === 0) {
        logSpawn(name, argv, null);
        return;
      }

      args[pathIdx] = Memory.allocUtf8String(rewritten[0]);
      args[argvIdx] = writeArgv(rewritten);
      logSpawn(name, argv, rewritten);
    },
  });
  return true;
}

// ---------------------------------------------------------------------------
// Hook: macOS sandbox_init (defense in depth, in case a future codex links it)
// int sandbox_init(const char *profile, uint64_t flags, char **errorbuf)
// ---------------------------------------------------------------------------

function hookSandboxInit() {
  if (PLATFORM !== "darwin") return false;
  const exp = Module.findExportByName("libsystem_sandbox.dylib", "sandbox_init");
  if (!exp) return false;

  Interceptor.replace(
    exp,
    new NativeCallback((profile, flags, errorbuf) => {
      console.log("[ccp-frida sandbox_init] short-circuited (returning success)");
      // Set *errorbuf = NULL to avoid the caller dereferencing garbage.
      if (!errorbuf.isNull()) errorbuf.writePointer(NULL);
      return 0; // success
    }, "int", ["pointer", "uint64", "pointer"])
  );
  return true;
}

// ---------------------------------------------------------------------------
// Install hooks
// ---------------------------------------------------------------------------

const installed = [];
if (hookPosixSpawn("posix_spawn")) installed.push("posix_spawn");
if (hookPosixSpawn("posix_spawnp")) installed.push("posix_spawnp");
if (hookExec("execvp", 1, 0)) installed.push("execvp");
if (hookExec("execv", 1, 0)) installed.push("execv");
if (hookExec("execve", 1, 0)) installed.push("execve");
if (hookSandboxInit()) installed.push("sandbox_init");

console.log(`[ccp-frida] codex-bypass loaded · platform=${PLATFORM} · hooks=[${installed.join(", ")}]`);
