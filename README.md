# CVE-2026-43284 / CVE-2026-43500 Dirty Frag PoC

This branch contains the N4C analyst copy of the public Dirty Frag proof of
concept and the static x86-64 build used in disposable QEMU validation.

## Files

- `dirtyfrag-exp.c`: combined ESP and RxRPC source with the
  `DIRTYFRAG_LAB_NO_SHELL` verification guard.
- `dirtyfrag-exp`: statically linked x86-64 build.
- `run_as_1000.c` / `run-as-1000`: lab helper that drops a QEMU init shell to
  uid/gid 1000 before starting the PoC.
- `dirtyfrag-lab-no-shell.patch`: the small guard added to the public source.

## Primitive-only verification

Run only in a disposable, authorized test VM:

```sh
/run-as-1000 env DIRTYFRAG_VERBOSE=1 DIRTYFRAG_LAB_NO_SHELL=1 \
  ./dirtyfrag-exp --force-esp --verbose

/run-as-1000 env DIRTYFRAG_VERBOSE=1 DIRTYFRAG_LAB_NO_SHELL=1 \
  ./dirtyfrag-exp --force-rxrpc --verbose
```

The vulnerable Linux 7.0.4 test kernel showed page-cache mutation on both
paths. Linux 7.0.6, containing both fixes, rejected the same mutations.

This code can modify the page cache of privileged files. Do not run it on a
production host.
