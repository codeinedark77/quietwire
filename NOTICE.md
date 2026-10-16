# Third-party material

* `tests/data/sarif-schema-2.1.0.json` is the SARIF 2.1.0 JSON schema published by OASIS
  (https://github.com/oasis-tcs/sarif-spec), (c) OASIS Open, used unmodified for offline schema validation in the tests.
* The real packet captures used for validation (nDPI and Zeek test traces) are **not** included in this archive; see
  docs/VALIDATION.md for their origin. `scripts/validate_tshark.py` needs `tshark`; `scripts/validate_dpkt.py` needs `dpkt`.
