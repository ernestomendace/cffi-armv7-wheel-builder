# Manual ARMv7 MCP bundle smoke

This public repository contains only the test workflow and generic tooling. The application source archive is transferred to the hosted runner through seven Actions secrets; it is not committed here. The wheel installer runs with `--no-index` inside the pinned ARMv7 manylinux container. The container has no network, is read-only except for private tmpfs/results, has no Linux capabilities, and is not connected to the NAS.

The workflow has only `workflow_dispatch`; it uses the standard `ubuntu-24.04` runner, pinned QEMU/binfmt and the exact manylinux image digest used by the successful CFFI build. It does not install Docker on the Mac, run a real SMB server, open Cloudflare, read documents or use real credentials.

## Private source preparation

From a trusted local checkout of the MCP project, use the public `package_private_source.py` and the project’s existing curated staging script. Choose a private output directory with mode 0700. The command writes seven 0600 text files, each at most 40,000 Base64 characters, plus a private summary. It does not print chunk contents. Confirm that the summary SHA-256 equals `private_source_archive_sha256` in `wheel-lock.json`; stop if it does not.

Create these repository Actions secrets, pasting each corresponding local chunk file into the secret value:

* `MCP_ARMV7_SOURCE_B64_01` through `MCP_ARMV7_SOURCE_B64_07`
* `MCP_ARMV7_DIAGNOSTIC_KEY_HEX`: a random 32-byte key encoded as 64 hexadecimal characters; preserve a local copy privately for report recovery.

Do not put the chunk files or key in Git, issues, comments, workflow inputs, or chat. The workflow never prints source or secret values. If any secret is missing or the assembled source digest differs from the pinned lock, preparation fails before Docker starts.

Example key generation on a trusted local machine: `openssl rand -hex 32`. Save the output directly into a private password manager or a file with mode 0600; do not paste it into a terminal transcript.

## What the manual run checks

The hosted runner recovers CFFI’s previously audited wheel archive from Actions run `45214904747`, verifies its archive and wheel SHA-256, then downloads the other five exact PyPI wheel filenames and SHA-256 values from the official project JSON metadata. It constructs a hash-checked requirements lock. The ARM container installs with `--no-index --require-hashes`; if any input is missing or differs, it fails closed.

The test exercises package imports, `_cffi_backend`, a known ARC4 answer, RSA-SHA256 sign/verify, synthetic NTLM SMB SESSION_SETUP against an in-memory peer, OAuth/Streamable HTTP, the real local MCP gateway subprocess, CAS lease, supervisor/watchdog, and a local tunnel fixture. Test credentials are fabricated fixture values only. No public service is contacted from the container.

RSS and PSS are sampled for the measured child process trees. The container cgroup peak is also recorded where readable. The guest metrics include QEMU effects; cgroup figures include QEMU and container overhead; neither is a NAS measurement or an exact host-runner total. RSS sums are explicitly not treated as unique physical memory.

## Recovery of diagnostics

The workflow encrypts the bounded run directory with AES-256-CBC plus HMAC-SHA256 before printing Base64. The public Actions log therefore contains only authenticated ciphertext inside the two `MCP_ARMV7_ENCRYPTED_DIAGNOSTICS_*` markers. It uploads no raw log or private source artifact. Recover the ciphertext with `recover_diagnostics.py <run-id> --output <private-file>`, then decrypt with `decrypt_diagnostics.py <private-file> --output <private-report.tar.gz>` and enter the locally held key at the non-echoing prompt. The recovery tool does not print the log or ciphertext. Keep the decrypted archive private and remove it when no longer needed.

The test workflow is not started by this change. To run it once later, configure the eight source secrets and diagnostic key, inspect the main commit and manual workflow on GitHub, then use **Actions → ARMv7 offline MCP bundle smoke → Run workflow**. A single click starts one run; failed jobs do not retry automatically.
