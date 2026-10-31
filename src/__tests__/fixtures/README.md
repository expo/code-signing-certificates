# Stage-1 wire fixtures

All keys are synthetic test credentials. Never use them for production. These files were captured against the unchanged node-forge 1.4.0 implementation on Node 22.23.4. The pre-existing `test-private-key.pem` and `test-certificate.pem` remain unchanged. `other-private-key.pem` was generated once using Node's RSA-2048 key generator; tests reuse it instead of generating many keys.

The nine baseline `*-certificate.pem` fixtures were built with Forge using the existing test key, serial `0123456789abcdef01`, SHA-256, subject/issuer CN `Fixture signing key`, and validity 2020-01-01 through 2040-01-01 UTC. Variants change only the named fact: expired ends 2021-01-01; future starts 2031-01-01; issuer-mismatch uses CN `Different issuer`; absent-ku/eku omit the extension entirely; false-ku/eku include a signed extension with the usage flag false. Invalid-signature flips the last signature byte. `other-issuer-certificate.pem` has the valid certificate facts but uses the second key and is self-signed with that key. Issuance tests therefore distinguish the CSR key from the issuer key. Every fixture is serialized before validation; none depends on mutation of cached digests.

`historical-csr.pem` was signed with the existing key using Forge/SHA-256, CN `Historical CSR`, O `Expo test fixtures`. The SHA-1, SHA-384, SHA-512 and MD5 variants use the same subject/key and their named digest. `tampered-csr.pem` flips its last signature byte. `requested-extensions-csr.pem` adds an extensionRequest for CA=true, keyCertSign, serverAuth, and Expo value `attacker,scope`. Issuance must ignore these requests. Historical here means captured before migration, not an external production artifact.

`external-csr.pem` and `pss-csr.pem` were generated with the host LibreSSL 3.3.6 CLI:

```
openssl req -new -sha256 -key test-private-key.pem -subj '/CN=External CSR/OU=one/OU=two/O=Expo' -out external-csr.pem
openssl req -new -sha256 -key test-private-key.pem -subj '/CN=PSS CSR' -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out pss-csr.pem
openssl req -in historical-csr.pem -noout -verify
```

The last command independently reported `verify OK`. Tests verify generated and persisted CSR signed bytes using Node crypto, including PSS with SHA-256/MGF1-SHA256 and salt length 32. This bounded pass confirms CSR verification accepts SHA-1, MD5, SHA-256, SHA-384, SHA-512, and this PSS form on the baseline runtime; it does not establish every algorithm/parameter combination or certificate algorithm policy.

`pss-mgf384-csr.pem` is an independently OpenSSL-verified synthetic CSR from the dependency-feasibility probe, using a separate RSA key, SHA-256, MGF1-SHA384, and a 32-byte salt. It verifies with Forge and OpenSSL. Generic Node RSA verification cannot select that independent MGF hash; the regression test requires issuance to verify it using validated RSA-PSS parameters while preserving its original public key and full CSR DER. Its private key is not needed or retained in this repository.

## Baseline observations and deliberate migration changes

- At baseline, absent KU/EKU threw a TypeError because Forge returned null. Both signed absent fixtures now require the intended package usage diagnostic. False usage fixtures already required that diagnostic. The initial green baseline asserted rejection without endorsing the TypeError wording.
- Corrupted RSA signatures can throw incidental Forge padding errors; preserve rejection, not that parser wording.
- Native key objects, rejection of incorrect key roles/non-RSA keys, removed Forge methods, defensive Date copies, and generated Date whole-second normalization are new source/API behavior. Baseline tests only require second precision after PEM encoding and parsing.
- Complete CSR DER preservation is asserted for historical/generated/external requests, including PSS. Forge reserialized the external PSS AlgorithmIdentifier by adding NULL hash parameters while preserving signed request-info bytes and signatures. Exact original whole-DER preservation is an intentional improvement in the new parser.
- Strict trailing-byte, malformed/duplicate-usage and inconsistent algorithm/parameter rejection are tested at the new parser boundaries. The baseline covered truncation, malformed length, signed-content tampering, and invalid proof of possession. Resource limits use the selected parser's defaults; no separate package limits were added.
- Development validity deliberately preserves local calendar arithmetic, including the March/January overflow bug and DST transitions. Dates in the table are fixed local wall times converted to UTC for assertions, making the characterization independent of the machine timezone. Arithmetic correction is separate work.

The snapshot file is unchanged. Full PEM text equality and Forge's incidental error strings are not contracts. Tests now use native cryptographic verification and ASN.1 schemas for representation inspection and CSR signed-byte extraction. Baseline fixture facts remain unchanged; Forge is no longer a test or runtime dependency.
