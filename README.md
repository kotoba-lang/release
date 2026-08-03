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
