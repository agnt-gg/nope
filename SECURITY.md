# Security policy

## Supported versions

Security fixes are provided for the latest published version of `@agnt-gg/nope`.

## Reporting a vulnerability

Please do not open a public issue for an unpatched vulnerability. Use GitHub's private vulnerability reporting for `agnt-gg/nope` when available, or contact the maintainers through https://agnt.gg.

Include the affected version, reproduction steps, impact, and any proposed mitigation. Do not include real credentials or destructive proof-of-concept payloads.

## Execution threat model

NOPE is a policy and guardrail library. Pattern detection reduces risk but is not an operating-system security boundary.

- **Docker:** the supported isolation boundary. Network is disabled by default; capabilities are dropped; `no-new-privileges`, CPU limits, and memory limits are applied. Callers remain responsible for Docker daemon security, image provenance, bind mounts, and any policy relaxation.
- **SSH:** a transport to a separately administered remote machine. SSH does not make the remote command safe or isolated.
- **host-process:** not isolation. It runs with the current operating-system user's authority and is available only through explicit `acknowledgeHostAccess: true`. It uses an executable and argument array with `shell: false`; command strings are rejected.
- **WASM:** arbitrary shell commands are not WASI modules. The command-oriented WASM backend fails closed and never falls back to native host execution.

No backend is selected implicitly. Unsupported or unsafe configurations fail closed.

## Security testing

Sandbox regression tests run only inert Node scripts in a newly created temporary directory. They do not execute destructive commands, Docker, SSH, Wasmtime, Wasmer, PowerShell, cmd.exe, or a system shell. Docker/SSH command-construction guarantees are verified through source inspection and argument-array invariants.
