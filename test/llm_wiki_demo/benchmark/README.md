# LLM Wiki demo scoring data

`ground_truth.json` is read only by the post-run scorer. It must never be copied
into the isolated scan input or exposed to Wiki discovery, the Wiki compiler, or
the Validator. This directory is not part of the CMake source tree.

Both the Wiki-off baseline and Wiki-active scan must enable optional Clang
tooling so both modes receive the same enriched AST/CFG evidence:

```bash
export ZSCOPE_ENABLE_CLANG_TOOLING=1
```

Keep this setting identical across the two scans. The transition target is the
high-confidence `clang_cfg_unbounded_count_indexes_fixed_array` candidate in
`wiki_copy_label`; optional Clang tooling supplies additional evidence but does
not define the expected answer.

After a scan has completed, save the two reports outside this fixture and run:

```bash
python scripts/score_llm_wiki_demo.py \
  --off-report /path/to/off/report.json \
  --active-report /path/to/active/report.json \
  --truth test/llm_wiki_demo/benchmark/ground_truth.json \
  --output /path/to/artifact/llm-wiki-demo-metrics.json
```

The scorer writes both `confirmed` and `with_needs_review` views for each mode,
including Precision, Recall, matched pairs, and the expected disposition
transition for the documented label precondition.

The canonical fixture configuration intentionally contains only currently
supported public v2 fields. Wiki `off`/`active` mode is supplied by the caller
or a temporary configuration overlay after the Wiki runtime is enabled; it is
not encoded as answer metadata in this fixture.
