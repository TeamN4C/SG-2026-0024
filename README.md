# SG-2026-0024 Dirty Frag Exploit

This branch contains the end-to-end local privilege-escalation exploit used by
N4C to validate CVE-2026-43284 and CVE-2026-43500. The separate `poc` branch
keeps the non-destructive fixture-only proof of concept.

## Flow

`dirtyfrag-exploit` has two exploit paths and one common privilege transition:

1. **ESP** enters a user and network namespace, installs attacker-controlled
   XFRM ESP state, then uses splice-backed receive processing to replace the
   cached beginning of the setuid-root `/usr/bin/su` with a 192-byte x86-64
   ELF. Executing `su` therefore executes the embedded root shell payload.
2. **RxRPC** derives three RXKAD session keys for overlapping eight-byte
   decryptions, triggers those decryptions against the read-only page cache of
   `/etc/passwd`, and changes the first entry to `root::0:0:...`. A privileged
   `su` consumer configured to accept an empty password then yields root.
3. After either target change is verified, the exploit starts `su -` in a PTY
   and bridges it to the caller's terminal.

The default order is ESP first with RxRPC as a fallback. A method can be
selected explicitly:

```bash
./dirtyfrag-exploit --esp --verbose
./dirtyfrag-exploit --rxrpc
```

For a non-interactive disposable-lab check, `LPE_AUTO_VERIFY=1` makes the root
shell print a marker, `id`, and `whoami`, then exit:

```bash
LPE_AUTO_VERIFY=1 ./dirtyfrag-exploit --esp --verbose </dev/null
```

## Build

```bash
make
```

The included binary is a statically linked x86-64 Linux build.

## Files

- `dirtyfrag-exploit.c` — readable combined exploit source.
- `dirtyfrag-exploit` — statically linked x86-64 build.
- `Makefile` — reproducible static build.

## Validation boundary

N4C validated both paths from uid/gid 1000 to a real uid/gid 0 shell in a
disposable Linux 7.0.4 QEMU guest. The RxRPC guest uses a dedicated setuid-root
lab consumer that models the PAM `nullok` decision; that result is not evidence
that every distribution's PAM configuration accepts an empty password.

Both methods are expected to fail without changing the target on Linux 7.0.6,
which contains the tested rejection fixes.

## Provenance

The exploitation primitives and low-level protocol code are derived from the
public [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) implementation at
commit `aab16fcada27142dd8ce8704906cf6736cf213b8`. N4C reorganized that code into
the single flow documented above, removed duplicate/dead validation paths, and
added the common PTY transition and reproducible lab build. The underlying
exploit technique is not claimed as an N4C clean-room implementation.

Use this code only in an authorized, disposable test environment. Both paths
modify privileged file contents in the page cache and can destabilize a host.
