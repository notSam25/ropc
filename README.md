# ropc
A Windows 11 kernel ROP chain compiler API.

`ropc` searches a target binary (e.g. `ntoskrnl.exe`) for usable ROP gadgets and
stitches them into a chain that products arbitrary code logic. Register
setup, stack arguments, call, and cleanup all without relying on any single
"universal" gadget being present.

> **Status:** early design/scaffolding. The public API (`include/ropc.hpp`) and
> implementation (`src/ropc.cpp`) are not yet implemented; this README tracks
> the intended design.

## Motivating example

Given a target function such as:

```c
void* memcpy(void* dst, const void* src, size_t len);
```

calling it from a ROP chain on x64 Windows requires:

- setting up `rcx`, `rdx`, `r8` (dst, src, len) via gadgets, without one
  gadget's side effects clobbering a register another gadget already set,
- transferring control into `memcpy` and recovering its return value (`rax`),
- doing all of the above using only instruction sequences that already exist
  in the target binary.

`ropc` aims to automate that process end to end, and expose it as a typed C++
API rather than a one-off exploit script.

## Pipeline

1. **Gadget discovery**: scan the target binary for candidate gadgets
   (Boyer-Moore-style byte scanning over executable sections).
2. **Clobber classification**: tag each gadget with the registers/memory it
   modifies (e.g. "gadget # 69,420 modifies `rax`").
3. **Semantic classification**: for the gadgets that satisfy a given clobber
   constraint, symbolically execute them to determine *how* they set a
   register, not just *that* they do:
   - `mov rax, 0x0` (immediate load)
   - `mov rax, qword ptr [rcx]` / `mov rax, qword ptr [rcx + 0x8]` (memory read
     through a controlled pointer)
   - `pop rax` (stack pop; cheapest class, only needs stack layout control)
   - register-to-register move/arithmetic
4. **Chain stitching**: combine classified gadgets to satisfy the full
   calling-convention contract for a target call (args in `rcx`, `rdx`, `r8`,
   `r9`, remaining args on the stack in reverse order, stack pointer
   adjustment around the call).
5. **Verification**: symbolically execute the concretized chain end to end
   and assert the final register/memory state matches the intended ABI setup
   at the call site, catching cross-gadget interaction bugs (e.g. gadget A's
   write getting clobbered by gadget B) that step 3's per-gadget analysis
   alone can't.

### Symbolic execution backend (Triton)

Classification and verification are built on
[Triton](https://triton-library.github.io/), used per-gadget in isolation:

- Symbolize all input registers/memory, run the gadget's instructions through
  `processing()`, then inspect the resulting AST for each register.
- An unmodified/self-referential output AST means the register wasn't
  touched — cheaper and more reliable than syntactic clobber detection.
- The AST *shape* (not the instruction mnemonic) drives classification:
  - a `bv` constant -> immediate/zeroing gadget
  - a reference to the initial stack pointer at a fixed offset -> a pure
    stack pop
  - a reference to a symbolized register input -> a register move/arithmetic
    gadget
  - a `select`/memory-read node keyed off a symbolized register -> the
    `[rcx + 0x8]`-style gadget, which needs a controlled pointer at
    chain-build time
- Register *liveness* ("must stay unclobbered until used") is checked the
  same way: symbolize the register where it's set, run every subsequent
  gadget in the chain, and check whether the AST at the point of use still
  equals the original symbol.
- Because gadget candidates can number in the thousands for a large binary
  like `ntoskrnl.exe`, a fast syntactic pre-filter narrows the candidate set
  before anything is handed to Triton. Full symbolic execution only runs on
  survivors.

## API sketch

The intended C++ API represents a target call as a typed function call, and
returns a value that can be threaded into subsequent calls in the same chain:

```cpp
auto result = engine::function_call<decltype(&memcpy)>(memcpy, source, dst, size);
```

Rather than a concrete value, `function_call`'s result wraps a symbolic
variable/AST node, so chain-building operations compose naturally:

```cpp
auto result = engine::function_call<...>(...);
engine::save_memory(result);

auto result2 = engine::function_call<...>(functionAddr, {}, engine::get_memory(lookup_ip), result);
```

`save_memory` records that a memory write depends on symbol `result`;
`get_memory` reads back the AST for what's stored at an address after the
chain is concretized. This reuses Triton's own AST context and symbolic
variable aliasing instead of a separate IR for chain-local dataflow.

Argument placement (which gadgets are eligible for `rcx`/`rdx`/`r8`/`r9`
without disturbing registers the caller still needs) is driven by a
dependency graph rather than a greedy per-argument search, since a greedy
choice for one argument can eliminate the only viable gadget for another.

## Building

Requirements: CMake >= 3.13, a C++23 compiler, ninja(optional).

```sh
mkdir build && cd build/
cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug -GNinja
ninja
```

## Project layout

```
include/ropc.hpp   public API
src/ropc.cpp       implementation
tests/integration  integration tests, built against the ropc library
bins/              sample target binaries (Git LFS) used by tests/tooling
docs/              design notes
```

## License
MIT, see [LICENSE](LICENSE) if you don't believe me
