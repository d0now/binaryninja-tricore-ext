# Binary Ninja TriCore Workaround Architecture Hook

## ~~Support for the "Absolute Addressing" instructions (LD, ST, SWAP, ...)~~
- [issue#6342](https://github.com/Vector35/binaryninja-api/issues/6342)

## ~~Support for the "Absolute Target Branch" instructions (CALLA, JA, ...)~~
- [issue#6342](https://github.com/Vector35/binaryninja-api/issues/6342)

## Support for the "Conditional Move" (CMOV[N])
- [issue#6617](https://github.com/Vector35/binaryninja-api/issues/6617)

## Notes

- Binary Ninja doesn't fully support TriCore's ArchitectureHook at this time.
  If we try to register ArchitectureHook at plugin load time, it will fail because TriCore is not registered architecture at that moment.
  So, you need to enable the ArchitectureHook by command "TriCore Architecture Extension Hook" after loading a view.
  Reanalyzing the view will make the ArchitectureHook available.

- Also, I don't know why, but, If we register two ArchitectureHook at once, it will showing intrinsics instructions strange.
