# TODO

## Immediate PR

- [x] Update Catch.hpp to latest v2
    - Reason: `Catch.hpp:10881:33: error: variable length array declaration not allowed at file scope`
- [x] Inline helper for `volatile int i = 0; PH_UNUSED(i);` with documentation
- [x] Fix scheme retry logic:
    - Reason: Current impl doesn't try other schemes if the chosen scheme does not fit into the prologue
- [x] Fix safe_mem_read (Trampoline in code cave detour is not disassembled properly because it's allocated at the end
  of a memory map)
- [x] Fix mem_protect (same as above, i.e. support for memory regions that span multiple mappings)
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
    - [ ] Do not use global static values (leads to C++ static initialization order fiasco)
- [ ] Tests:
    - [ ] Deduplicate tests
    - [ ] Move test headers/sources to UnitTests
    - [ ] Test specific schemas in addition to recommended
    - [ ] Test different hooking functions with explicit calling conventions on windows
    - [ ] Add optional diagnostic data to hooks, like instructions that were translated
        - Reason: Ensure during translations tests that translation did actually occur
- [ ] Logging:
    - [ ] Use lambda callback instead of a class (less boilerplate)
    - [ ] Don't add newline at the end of log lines (should be up to the consumer)
- [ ] Misc:
    - [ ] Adopt a consistent naming convention (right now it's a mix of camelCase, snake_case, and hungarian)
    - [ ] Create a glossary
    - [ ] Goal: Zero clang-tidy warnings

## Unplanned

- [ ] Windows-clang support
- [ ] Generate test hooks with asmjit?

## Questions

- When do we use StackCanary, and we do we not?