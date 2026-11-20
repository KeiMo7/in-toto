# API

The in-toto API provides various functions and {doc}`classes <model>` that you
can use to generate, consume, modify and verify in-toto metadata, as a more
feature-rich, programmable alternative to the {doc}`command line tools
<command-line-tools/index>`.

```{admonition} Cryptographic Signatures
:class: tip

in-toto metadata is signed with cryptographic keys via the *Signer API*
in [securesystemslib](https://github.com/secure-systems-lab/securesystemslib)
Please refer to its [documentation](https://python-securesystemslib.readthedocs.io/en/latest/signer.html)
for details about loading a `Signer` for "Evidence Generation".

Loading verification keys for "Supply Chain Verification" is
documented [in-toto#663](https://github.com/in-toto/in-toto/issues/663).
```

## Evidence Generation

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_run
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_record_start
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_record_stop
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_match_products

```

## Supply Chain Verification

```{eval-rst}
.. autofunction:: in_toto.verifylib.in_toto_verify
```

### Structured verification reports

`verify_layout_report` runs the same verification as `in_toto_verify`, but
returns a `VerificationReport` instead of raising on the first failed check.
Every step and inspection gets its own conclusion, including the number of
distinct authorized signers that were satisfied and are still missing.

```{eval-rst}
.. autofunction:: in_toto.verifylib.verify_layout_report
```

```{eval-rst}
.. autoclass:: in_toto.verify_report.VerificationReport
   :members:
```

```{eval-rst}
.. autoclass:: in_toto.verify_report.ItemResult
   :members:
```

```{eval-rst}
.. autoclass:: in_toto.verify_report.VerificationIssue
   :members:
```
