# Dirty Frag primitive-only PoC

Readable N4C demonstrator for CVE-2026-43284 (XFRM/ESP) and
CVE-2026-43500 (RxRPC/RXKAD).

The PoC answers one question: **can an unprivileged process change the page
cache of a root-owned, read-only file through a shared `sk_buff` fragment?**
It does not overwrite `/usr/bin/su` or `/etc/passwd`, install a payload, invoke
PAM/NSS, or start a shell. The full public exploit remains on the `exploit`
branch.

## Files

- `dirtyfrag-poc.c` — the two page-cache primitives and a small CLI.
- `prepare-lab.sh` — creates two harmless root-owned fixtures.
- `run_as_1000.c` / `run-as-1000` — drops the VM's root shell to uid/gid 1000.
- `Makefile` — reproducible static build.

## What each path proves

### ESP (`--esp`)

```text
read-only fixture
  -> splice(file -> pipe -> UDP socket)
  -> skb paged frag
  -> ESP authencesn in-place STORE
  -> first four cached bytes become "N4C!"
```

Only one XFRM SA and one four-byte write are used. The root-shell ELF and its
48-trigger assembly loop from the public exploit were removed.

### RxRPC (`--rxrpc`)

```text
read-only fixture
  -> splice(file -> forged RxRPC DATA packet)
  -> RXKAD pcbc(fcrypt) in-place decrypt
  -> one key-selected 8-byte write
  -> the cached bytes differ from the original fixture
```

The PoC does not search for a password-shaped plaintext because any changed
eight-byte block already proves the primitive. The offline fcrypt brute-force,
overlapping-write planner, PAM, `getent`, passwordless `su`, PTY handling, and
shell code were removed.

## Build and run

Use only in a disposable, authorized Linux VM containing the required kernel
features.

```sh
make

# Run once as the VM's root user to recreate known fixture bytes.
./prepare-lab.sh

# The helper then runs the PoC as uid/gid 1000.
./run-as-1000 ./dirtyfrag-poc --esp --verbose

./prepare-lab.sh
./run-as-1000 ./dirtyfrag-poc --rxrpc --verbose
```

Exit status:

- `0` — marker appeared in the page cache; primitive observed.
- `1` — marker did not appear; the shared-frag write was rejected.
- `2` — invalid fixture, unsupported environment, or setup failure.
- `3` — RxRPC trigger failed before verification.

Recreate the fixtures, or reboot the disposable VM, between runs.

## Reading order

1. `main()` selects one primitive and refuses to run as uid 0.
2. `esp_poc()` shows the four-byte XFRM/ESP case.
3. `rxrpc_poc()` shows one trigger and a direct before/after comparison.
4. Protocol helpers are grouped directly above the path that uses them.

## Provenance

Protocol construction was derived from Linux kernel source and the public
[V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) reference implementation
at commit `aab16fcada27142dd8ce8704906cf6736cf213b8`. N4C rewrote the execution
flow into this fixture-only demonstrator and removed the privilege-escalation
payload and consumer stages.
