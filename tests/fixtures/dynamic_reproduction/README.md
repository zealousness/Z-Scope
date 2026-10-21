# Dynamic reproduction fixtures (V01 / V02)

These are **new, minimal, deliberately vulnerable or deliberately safe** C
samples used only by the controlled dynamic-reproduction runner. They are not
part of `test/range`: the implanted defects there must never be modified, and
nothing in this directory is derived from benchmark truth.

Runner rules for everything in this directory:

* Only `SanitizerReproductionRunner` / `FakeDynamicReproductionRunner` may
  execute it. It is never run through a project build script (`make`, `cmake`,
  `pytest` plugins) and never through a model-generated command.
* Each run gets its own temporary build directory and its own binary digest.
* The marker comment `ZSCOPE_CANDIDATE_SITE` pins the exact source line the
  candidate is about, so the expected site is program-derived rather than
  guessed after the fact.

| File | Kind | Purpose |
|---|---|---|
| `heap_overflow_positive.c` | ASAN positive | Deliberate heap out-of-bounds write at the marked site. |
| `heap_overflow_negative.c` | ASAN negative | Same shape, correctly bounded: no report may be produced. |
| `unrelated_crash.c` | ASAN wrong-object | The candidate site is safe; an unrelated helper overflows. A report in the helper must never confirm the candidate. |
| `broken_build.c` | build failure | Deliberate compile error, used to prove build failure stays undecided. |
| `allocation_oversize.c` | resource exhaustion | Allocates the caller's size, so an oversized argument produces a real sanitizer allocation-limit report. |
| `data_race_positive.c` | TSAN positive | Two threads update one shared global without synchronization. |
| `data_race_negative.c` | TSAN negative | The same update under a mutex. |
| `data_race_flaky.c` | TSAN non-deterministic | A relaxed-atomic gate that may or may not let the second thread touch the shared slot, so the race is not guaranteed on every run. |
