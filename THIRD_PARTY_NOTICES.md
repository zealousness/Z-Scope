# Third-Party Software Notices and Redistribution Terms

Z-SCOPE itself is licensed under the MIT License (see [LICENSE](LICENSE)).

This document summarizes third-party components bundled in the Z-SCOPE source
repository, declared as Python/Java dependencies, or redistributed in optional
Z-SCOPE Linux Portable release bundles.

---

## 1. Vendored WebUI Assets (Bundled in Source and Wheel)

The following third-party browser libraries are vendored under
`zscope/web/static/vendor/` together with their full upstream license texts and
checksum locks (`requirements/portable/web-assets.lock.json`):

| Component | Version | License | License File |
|---|---|---|---|
| Alpine.js | 3.14.9 | MIT | `zscope/web/static/vendor/alpine.LICENSE` |
| DaisyUI | 4.4.19 | MIT | `zscope/web/static/vendor/daisyui.LICENSE` |
| fflate | 0.8.2 | MIT | `zscope/web/static/vendor/fflate.LICENSE` |
| js-yaml | 4.1.1 | MIT | `zscope/web/static/vendor/js-yaml.LICENSE` |
| markdown-it | 14.1.1 | MIT | `zscope/web/static/vendor/markdown-it.LICENSE` |
| PrismJS | 1.29.0 | MIT | `zscope/web/static/vendor/prism.LICENSE` |
| Tailwind CSS (generated CSS only) | 3.4.17 | MIT | `zscope/web/static/vendor/tailwind.LICENSE` |

---

## 2. Python Runtime Dependencies

Locked Python runtime dependencies are governed by `requirements/license-policy.json`
and validated via `scripts/check_dependency_licenses.py`. Approved runtime licenses:

- **MIT**: `annotated-types`, `anyio`, `charset-normalizer`, `h11`, `jiter`,
  `pydantic`, `pydantic-core`, `pyyaml`, `ruamel-yaml`, `ruamel-yaml-clib`,
  `typing-inspection`, `urllib3`
- **Apache-2.0**: `cpgqls-client` (optional `java` extra), `distro`, `openai`,
  `requests`
- **BSD-3-Clause**: `click`, `httpcore`, `httpx`, `idna`, `websockets`
- **MIT OR Apache-2.0**: `sniffio`
- **MPL-2.0**: `certifi`
- **MPL-2.0 AND MIT**: `tqdm`
- **PSF-2.0**: `typing-extensions`
- **Apache-2.0 AND CNRI-Python**: `regex`

---

## 3. Optional External Toolchains & Linux Portable Release Bundles

Z-SCOPE invokes all external static-analysis backends (`clangd`, `zscope-clang-indexer`,
`gllvm`, `SVF`, `Joern`, and the Java Maven runner JARs under `tools/`) as **isolated
external subprocesses** over CLI arguments, JSON, or LSP/HTTP protocols. None of these
copyleft components are linked into the MIT-licensed Z-SCOPE Python package.

When distributing prebuilt **Linux Portable** archives (`zscope-*-portable.tar.gz`),
the following upstream components are included in the corresponding language bundle,
with upstream license files placed under `licenses/` inside each archive, SPDX 2.3
SBOMs emitted alongside each release asset, and corresponding source archives published
via `source-materials.json`:

### C/C++ Portable Bundle

| Component | Locked Version | License | Corresponding Source / Notes |
|---|---|---|---|
| CPython | 3.13.15 | PSF-2.0 | Locked in `requirements/portable/toolchain.lock.json` |
| LLVM / Clang / `clangd` | 22.1.7 & 18.1.0 | Apache-2.0 WITH LLVM-exception | Locked in `requirements/portable/toolchain.lock.json` |
| SVF (`wpa`, `saber`) | 3.2 | GPL-3.0-only | Executed as standalone CLI subprocesses; corresponding source tarball published in `zscope-*-third-party-sources-*.tar.gz` |
| gllvm (`gclang`, `get-bc`) | 1.3.0 | BSD-3-Clause | Locked in `requirements/portable/toolchain.lock.json` |
| Ubuntu runtime shared libraries | Ubuntu 23.10 baseline | Various (see bundle `licenses/system/*/copyright`) | Debian/Ubuntu source packages locked in `requirements/portable/system-sources.lock.json` and published alongside releases |

### Java Portable Bundle & Sidecar Runners (`tools/`)

| Component | Locked Version / Module | License | Corresponding Source / Notes |
|---|---|---|---|
| Eclipse Temurin (OpenJDK 21) | 21.0.12+101.0.LTS | GPL-2.0-only WITH Classpath-exception-2.0 | Full upstream JDK source tarball locked in `requirements/portable/redistribution.lock.json` and published alongside releases |
| Apache Maven | 3.9.16 | Apache-2.0 | Official binary distribution; upstream license preserved in bundle `licenses/` |
| Joern CLI (Java frontend only) | v4.0.620 | Apache-2.0 | Only `javasrc2cpg` frontend included; JAR notices preserved in `licenses/maven/` |
| JavaParser (`tools/java-structure-javaparser`) | `com.github.javaparser:javaparser-core` | Apache-2.0 OR LGPL-3.0-or-later | Used under Apache-2.0 |
| Spoon (`tools/java-structure-spoon`) | `fr.inria.gforge.spoon:spoon-core` | CeCILL-C / MIT | Shaded standalone CLI runner |
| SootUp (`tools/java-signal-sootup`) | `org.soot-oss:sootup.*` | LGPL-2.1-only | Standalone CLI runner; see LGPL relinking notice below |
| WALA (`tools/java-signal-wala`) | `com.ibm.wala:*` | EPL-2.0 | Standalone CLI runner; Maven source & POM included in `zscope-*-source.tar.gz` |

---

## 4. Copyleft & LGPL-2.1 Relinking Notice

1. **Corresponding Source Availability**: Every official Portable release publishes
   `source-materials.json` referencing the exact product source snapshot
   (`zscope-<version>-source.tar.gz`) and split third-party source archives
   (`zscope-<version>-third-party-sources-*.tar.gz`) containing the exact locked
   sources for SVF (GPL-3.0-only), OpenJDK 21 (GPL-2.0-only WITH Classpath-exception-2.0),
   LLVM/Clang, CPython, gllvm, and Ubuntu runtime system packages.
2. **LGPL-2.1 Relinking (`tools/java-signal-sootup`)**: The Java SootUp signal runner
   is built as a standalone CLI JAR using `maven-shade-plugin`. Because the complete
   Java runner source code and `pom.xml` (`tools/java-signal-sootup/`) are distributed
   under the MIT License inside both this repository and `zscope-<version>-source.tar.gz`,
   any user can modify or replace the SootUp LGPL-2.1 dependency version in `pom.xml`,
   rebuild the JAR with `mvn package`, and point Z-SCOPE to the rebuilt runner via
   `indexing.java.provider_commands.sootup` (or by replacing `tools/java-jars/zscope-java-signal-sootup.jar`
   in a writable copy of the portable bundle).
3. **CodeQL Non-Redistribution**: GitHub CodeQL CLI is governed by proprietary terms
   and is **never** bundled or redistributed in Z-SCOPE source or Portable release
   assets. CodeQL integration only probes a user-supplied local installation.
