# PR 0001: Dot11 Element ID Extension and HE Operation

Scope:

- Adds `Dot11EltExtension` dispatch for Element ID `255`.
- Adds `Dot11EltExtensionGeneric` for unknown or unsupported extension IDs.
- Adds `Dot11EltHEOperation` for Extended ID `36`.
- Adds `Dot11HE6GOperationInfo` when the HE Operation element indicates that
  6 GHz operation information is present.
- Adds focused `test/scapy/layers/dot11.uts` tests for generic, short, HE, and
  HE 6 GHz extended elements.

Spec references used in code comments:

- IEEE Std 802.11ax-2021, `9.4.2.1` and Table `9-92`: Element ID Extension.
- IEEE Std 802.11ax-2021, `9.4.2.249`: HE Operation element.
- IEEE Std 802.11ax-2021, Figure `9-788k`: 6 GHz Operation Information field.

Intentional partial support:

- Element ID Extension is a registry for many 802.11 information elements. This
  patch does not try to implement all of them.
- Unknown and unsupported extension IDs intentionally remain
  `Dot11EltExtensionGeneric`.
- EHT Operation and Multi-Link are left for separate follow-up patches so this
  first PR is reviewable on its own.

Focused test command used:

```sh
test/run_tests -t test/scapy/layers/dot11.uts -n 57-61 -F
```

Result:

```text
PASSED=5 FAILED=0
```

Full dot11 suite note:

- A full `test/scapy/layers/dot11.uts` run reached and passed the existing
  tests up through `Dot11EltVHTOperation in isolation` before I interrupted it
  in this local environment because it was taking longer than expected.
  The focused tests for this patch passed.

