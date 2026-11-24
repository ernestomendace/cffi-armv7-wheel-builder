# Native Linux x86-64 lifecycle smoke

This separate manual workflow runs the curated 47-file private source archive
on the standard `ubuntu-24.04` GitHub-hosted runner, in a digest-pinned CPython
3.9.25 x86-64 container. It does not invoke QEMU and does not change the
ARMv7 workflow, its wheel lock, image, or recorded results.

The six x86-64/universal wheels have a distinct lock. The runner verifies the
PyPI release metadata and SHA-256 of each downloaded wheel before mounting the
wheelhouse read-only. Installation uses `--no-index --require-hashes` inside a
container launched with `--network none`. The test container runs unprivileged,
with all capabilities dropped, `no-new-privileges`, read-only root filesystem,
dedicated tmpfs mounts, and a bounded cgroup. A throwaway NTLM credential file
and the other test state live only in the private non-executable tmpfs.

The private source archive is supplied at dispatch time through the distinct
Actions secrets `MCP_NATIVE_LINUX_SOURCE_B64_01` through
`MCP_NATIVE_LINUX_SOURCE_B64_08`; diagnostic encryption uses
`MCP_NATIVE_LINUX_DIAGNOSTIC_KEY_HEX`. Each segment is bounded at 40,000
characters. The workflow emits only the encrypted diagnostic envelope and
public phase statuses; it does not print source, secret values, test logs, or
the decrypted report. The diagnostic key must be retained privately until the
encrypted report is recovered, then the nine temporary Actions secrets should
be deleted and their names checked for absence.

The native suite exercises the production process-identity inspector against
real Linux child processes, repeats parent/child `/proc` identity comparison
five times, checks both fail-closed identity-rejection branches, and runs the
OAuth/MCP gateway, supervisor, watchdog, synthetic tunnel, probes, persisted
lease deadline, stop, and reconciliation tests. It uses loopback only. The SMB
SESSION_SETUP smoke is in-memory with fake credentials; it does not connect to
an SMB server. Measurements are for the x86-64 runner/container, include the
container cgroup scope as described in the encrypted report, and cannot open
the WD EX4100 memory gate.

Run only by manual `workflow_dispatch` after all nine temporary secrets have
been set from protected local files. The workflow is intended for one
authorized run; it has no schedule, no ARM emulation, and no paid runner.
