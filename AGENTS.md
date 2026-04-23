# AGENTS.md

## Scope and source of truth
- Work in the top-level tree (`/scapy`), not the vendored release snapshot (`/scapy-2.7.1.dev...`) or `build/` artifacts.
- Start with `README.md`, `CONTRIBUTING.md`, `tox.ini`, and `test/run_tests` before changing behavior.

## Big-picture architecture
- Public API aggregation is import-driven: `scapy/all.py` pulls core modules, then `scapy/layers/all.py` autoloads layer modules from `conf.load_layers` (`scapy/config.py`).
- Core packet model is `Packet` (`scapy/packet.py`): layers are stacked with `/`, dissection/build behavior hangs off `fields_desc`, `payload_guess`, and `post_build`.
- Layer binding is declarative and two-way via `bind_layers()` / `split_layers()` (`scapy/packet.py`); this controls both build-time field overloading and dissect-time next-layer guessing.
- Runtime/CLI bootstrapping lives in `scapy/main.py` (`interact`, `load_layer`, `load_contrib`, extension loading).
- Platform socket backends are selected centrally in `scapy/config.py` (`conf.use_pcap`, `conf.use_bpf`, OS-specific `scapy/arch/*`).

## Where to place new code
- Common protocols -> `scapy/layers/`; uncommon/vendor-specific -> `scapy/contrib/` (see `CONTRIBUTING.md`).
- `scapy/layers/*` must not import `scapy/contrib/*`; `contrib` may import either.
- Contrib modules must declare metadata headers near the top, e.g. in `scapy/contrib/automotive/scanner/graph.py`:
  - `# scapy.contrib.description = ...`
  - `# scapy.contrib.status = ...`

## Developer workflows that match CI
- Fast local baseline (no extra external tools): `./test/run_tests`
- Direct UTScapy run with config file: `python -m scapy.tools.UTscapy -c test/configs/linux.utsc`
- Lint/type/docs parity with CI: `tox -e flake8`, `tox -e mypy`, `tox -e docs`, `tox -e spell`
- Full matrix behavior is driven by `.github/workflows/unittests.yml` + `.config/ci/test.sh` (keyword skips via `UT_FLAGS`, root/non-root split, OS-specific toggles).

## Project-specific conventions
- Keep hot-path core changes lean (`scapy/packet.py`, `scapy/base_classes.py`): performance and allocation overhead matter.
- Logging policy is strict (`CONTRIBUTING.md`): prefer `scapy.error.log_runtime` for runtime behavior; use `log_interactive` only for interactive-shell-only messages.
- Test style is UTScapy-first (`test/*.uts`, `test/scapy/**/*.uts`): last expression decides pass/fail; keyword include/exclude (`-k` / `-K`) is heavily used.
- Preserve SPDX/license headers and existing typing-comment style (`# type:`) where present.

## Integration points and dependencies
- Optional features are capability-gated in `scapy/config.py` (notably `cryptography`, libpcap/bpf selection, extension manager `conf.exts`).
- Some features depend on external binaries configured via `conf.prog` (`tcpdump`, `tshark`, `wireshark`, `dot`).
- Docs and API tree are Sphinx-based (`doc/scapy/`, `tox -e docs`, `tox -e apitree`).
- Test selection/behavior depends on `test/configs/*.utsc` preexec hooks (for example loading `tls` or contrib modules before campaigns).

