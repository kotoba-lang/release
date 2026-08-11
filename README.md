# Kotoba release assurance

Fail-closed release admission and signed-tag verification for Kotoba artifacts.

This repository is an assurance consumer of the language contract. It does not
define language semantics. Callers pass the version policy from
`kotoba-lang/kotoba-lang` to `kotoba.release.tag/verify`; release publication
requests are evaluated by `kotoba.release.admission/evaluate` or admitted with
`kotoba.release.admission/admit!`.

```sh
clojure -M:test
clojure -M:lint
```

Operational signing is offline and fail-closed. The Ed25519 seed is accepted
only on stdin; the signer DID embedded in the envelope must already be active in
the separate trust document.

```sh
kagi get kotoba-language-release-ed25519 --compartment personal |
  clojure -M:tag sign --policy version-policy.edn --trust release-trust.edn \
    --envelope unsigned.edn > signed.edn

clojure -M:tag verify --policy version-policy.edn --trust release-trust.edn \
  --envelope signed.edn
```
