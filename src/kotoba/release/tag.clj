(ns kotoba.release.tag
  "Fail-closed verification of release-tag envelopes described by a Kotoba
  language version policy."
  (:require [ed25519.core :as ed]
            [kotoba.lang.version-policy :as version])
  (:import [java.util Base64]))

(defn canonical-body [envelope]
  (pr-str (into (sorted-map) (dissoc envelope :signature))))

(defn verify
  "Verify tag shape, v<semver>, complete content binding, signer trust/status,
  and Ed25519 signature. TRUST maps DID to {:status :active}."
  [policy trust envelope]
  (let [release-version (:version envelope)
        signer (:signer envelope)
        tag (:tag envelope)
        required (get-in policy [:release-tags :binds])
        body (canonical-body envelope)
        signature (try (.decode (Base64/getDecoder)
                                ^String (:signature envelope))
                       (catch Exception _ nil))
        missing (remove #(contains? envelope %) required)
        code (cond
               (nil? (version/parse-semver release-version))
               :tag/invalid-version
               (not= tag (str (get-in policy [:release-tags :prefix])
                              release-version))
               :tag/name-mismatch
               (seq missing) :tag/incomplete-binding
               (not= :active (get-in trust [signer :status]))
               :tag/signer-untrusted
               (nil? signature) :tag/invalid-signature
               (not (try
                      (ed/verify-did signer (.getBytes body "UTF-8") signature)
                      (catch Exception _ false)))
               :tag/invalid-signature
               :else nil)]
    {:valid? (nil? code) :code code :tag tag :version release-version
     :signer signer}))
