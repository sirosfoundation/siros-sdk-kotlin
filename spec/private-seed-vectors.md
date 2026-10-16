# private_seed derivation test vectors

`private-seed-vectors.json` holds test vectors for the holder's `private_seed`
derivation, defined in privatedata-spec SPEC.md section 5.4:

    private_seed = HKDF-SHA256(root, salt = empty, info = "org.siros.private_seed/v1" || credentialType)[:16]
    psc          = SHA256(private_seed)

`root` is the container `mainKey` (32 bytes); the vectors use fixed roots.
`credentialType` is an opaque string, UTF-8 encoded; no separator follows the
label. HKDF is RFC 5869 with an empty salt (a 32-byte zero salt, as for any
HKDF with no salt), a single output block.

**Status: self-generated, not yet cross-checked with the TypeScript wallet or
the privatedata-spec owner.** The label is a proposal.

Fields per vector: `name`, `root_hex`, `credential_type`, `seed_hex` (16
bytes), `psc_hex` (32 bytes). The Kotlin SDK's `PrivateSeedTest` consumes the
file; it is meant to be copied unchanged into siros-sdk-swift and the
privatedata-spec repository, each with a parity check against this copy.

## How the expected values were generated

`tools/gen_private_seed_vectors.py` implements HKDF from RFC 5869 with Python's
`hmac` and `hashlib` and does not call the Kotlin code. Regenerate with
`python3 tools/gen_private_seed_vectors.py`; verify with `--check`.
