# TODO

## Immediate PR

- [x] Update Catch.hpp to latest v2
    - Reason: `Catch.hpp:10881:33: error: variable length array declaration not allowed at file scope`
- [x] Inline helper for `volatile int i = 0; PH_UNUSED(i);` with documentation
- [ ] Fix INLINE scheme (need to check if function is large enough before choosing this schema)
    - [ ] Fix instruction translation (Displacement is not handled properly)
- [ ] Tests in CI/CD
- [ ] Move test headers/sources to UnitTests
- [ ] Deduplicate tests

## Future PR

- [ ] Semver
- [ ] Replace submodules with CPM

## Unplanned

- [ ] Generate test hooks with asmjit?
- [ ] Windows-clang support

## Questions

- When do we use StackCanary, and we do we not?