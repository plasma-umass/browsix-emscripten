V2 Browsix support
==================

There are several high-level goals of this work to rebase the Browsix patchset on
top of the most recent emscripten:

- WebAssembly support.
- Fix ./configure issues.
  - With the existing Browsix patchset, if a `./configure` check tries
    not just compiling but executing a file compiled by our branch of
    Browsix, it will likely throw an error.  For example, checking
    `vsprintf` works correctly.  The configure script then thinks that
    function doesn't work correctly (or doesn't exist) and either
    fails or (more likely) tries to use a hacky workaround.  This
    hacky workaround can cause issues when linking (multiple symbols
    defined), and when running, and is only "fixed" by manually
    editing the autoconf-generated `config.h` file.
- Easier builds.
  - Some projects do not correctly distinguish HOSTCC vs. CC, which
    makes cross-compiling them for Browsix harder than it should be.
  - For example, texlive builds + uses `tangle` to parse files, but it
    compiles it with `cc`, causing this program to fail when cross
    compiling texlive for Browsix (requiring manual intervention).
  - The output under the default flags should not only compile for
    Browsix, but should run under node when reasonable.

I think the easiest way to achieve this is to produce a JavaScript
file that runs correctly under both `node` and Browsix.

I think we can achieve that easiest in the following way:

- (mostly done) Changes to `preamble.js`, `postamble.js` and
  `shell.js` (for example) with Browsix-specific logic should be
  guarded by if-statements and if appropriate preprocessor macros:

```c
    if (ENVIRONMENT_IS_BROWSIX)
        ...
```

```c
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
        ...
    }
#endif
```

- Browsix syscall implemenations are going to live in
  `src/library_browsix.js`.  This library is only linked into the
  binary if `-D BROWSIX=1` is true.  At runtime, the library will
  check to see if `ENVIRONMENT_IS_BROWSIX` is true, and if so replace
  all syscalls with Browsix-specific ones.

