# CVE-2026-43284 / CVE-2026-43500 Dirty Frag Exploit

This branch contains the public combined Dirty Frag exploit and the static
x86-64 build used for N4C end-to-end validation.

## Files

- `dirtyfrag-exp.c`: ESP-first exploit with RxRPC fallback.
- `dirtyfrag-exp`: statically linked x86-64 build.

## Exploit paths

- ESP replaces the cached image of a setuid-root `/usr/bin/su` with a small
  root-shell ELF.
- RxRPC changes the cached root entry in `/etc/passwd` to an empty password
  field. The final transition depends on a privileged consumer accepting that
  field, such as a PAM `nullok` configuration.

N4C confirmed both paths from uid/gid 1000 to a real uid/gid 0 shell in a
disposable Linux 7.0.4 QEMU guest. The RxRPC test used an explicit setuid-root
lab consumer that models the `nullok` decision; it was not a distribution PAM
runtime test.

This is a local privilege-escalation exploit. Run it only in a disposable,
authorized test VM.
