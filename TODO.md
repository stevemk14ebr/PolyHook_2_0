# TODO

## Immediate PR

- [x] Update Catch.hpp to latest v2
    - Reason: `Catch.hpp:10881:33: error: variable length array declaration not allowed at file scope`
- [x] Inline helper for `volatile int i = 0; PH_UNUSED(i);` with documentation
- [x] Fix scheme retry logic:
    - Reason: Current impl doesn't try other schemes if the chosen scheme does not fit into the prologue
- [ ] Fix instruction translation (Displacement is not handled properly)
- [ ] Test linux-gcc
- [ ] Tests in CI/CD

## Future PR

- [ ] Release lifecycle
    - [ ] Semver
    - [ ] Replace submodules with CPM
- [ ] Refactor implementation:
    - [ ] Refactor private static functions into an anonymous namespace
    - [ ] Refactor implementations into explicit pure and side-effect functions
- [ ] Tests:
    - [ ] Deduplicate tests
    - [ ] Move test headers/sources to UnitTests
    - [ ] Test specific schemas in addition to recommended
    - [ ] Test different hooking functions with explicit calling conventions on windows
- [ ] Misc:
    - [ ] Adopt a consistent naming convention (right now it's a mix of camelCase, snake_case, and hungarian)
    - [ ] Create a glossary

## Unplanned

- [ ] Windows-clang support
- [ ] Generate test hooks with asmjit?

## Questions

- When do we use StackCanary, and we do we not?