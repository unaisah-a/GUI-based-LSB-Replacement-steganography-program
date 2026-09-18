# Saved-artifact and API compatibility

The supported application bundle format is the current version-1 `SMIV`
envelope plus a version-1 JSON manifest. The verifier deliberately rejects
unknown versions instead of guessing how older data should be interpreted.

The low-level image and audio carrier APIs remain available for experiments.
Image payloads still use a four-byte big-endian length followed by opaque
payload bytes. Audio payloads still use `INF2005`, a four-byte big-endian
length, and opaque payload bytes. Existing low-level files using those carrier
formats can be extracted when their exact LSB depth and numeric start location
are known. They are not authenticated application bundles and cannot produce an
`AUTHENTIC` verdict without a supported signed envelope and manifest.

Historical passcode-derived starts and signature blocks are not wire-compatible
with the current application protocol. Early start helpers used different HMAC
input strings, and early RSA-PSS helpers signed without the current domain
separator and used a different salt policy. No historical signed fixture is
retained in this repository. Such artifacts require the original revision and
settings for extraction or verification; the current application does not label
them as version-1 bundles or silently migrate them.

The callable compatibility helpers in `app.crypto.start_location` and
`app.crypto.signatures` preserve convenient function shapes for source-level
callers. That does not imply saved-byte compatibility with revisions before the
versioned envelope was introduced. New integrations should use
`protect_media`, `verify_media`, and `estimate_protection_capacity`.
