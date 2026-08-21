# Red-Team Pass: `gosub.md` (v2.1.12)

**Scope:** Adversarial analysis of the capability model, label algebra, enforcement architecture, and realistic exploitation paths.
**Assumptions:** Trusts the browser engine, OS routing, and store distribution as stated. Attacks model composition, runtime enforcement boundaries, update/lifecycle mechanics, and emergent cross-axis products.
**Severity Rating:** `CRITICAL` (model break / privilege escalation) · `HIGH` (guarantee violation / residual exfiltration) · `MEDIUM` (assumption gap / implementation risk) · `LOW` (clarification / edge case).

---

## 🔴 Critical / High Severity Findings

### 1. Execution-Order Bypass of G3 (Unwrappable Targets)
**Section:** §8, Appendix D (G3)
**Finding:** G3 requires defensive defines `BEFORE page scripts run`. However, `document_start` injection does not guarantee precedence over page scripts using `defer`, `async`, or inline `<script>` tags that parse immediately. If a page defines a property on `window.cfg.exfil` before scriptlet injection, `Object.defineProperty` with `configurable: false` cannot overwrite it, breaking G3.
**Impact:** A scriptlet writing to an unwrappable target becomes a conditional sink if the page's getter/setter observes or routes it.
**Fix:** Mandate injection at `document_start` with `run_at: "document_start"` + `all_frames: true`, and explicitly require page scripts to be deferred or loaded after scriptlet execution. Add a browser-enforced execution queue for scriptlets that runs before any page `DOMContentLoaded` or `load` event, with a compile-time warning if a page uses inline scripts in the same frame.

### 2. Combination Safety for Co-Injected Scriptlets
**Section:** §8, O3, Appendix D
**Finding:** The closure is stated as "closed under combination" and "closed under operator COMBINATION", but proofs are per-operator. Two individually safe `set-constant` operators (e.g., `cfg.telemetry=false`, `cfg.guard=false`) can jointly flip a page's control flow to a sink. The doc notes this but doesn't specify how the proof handles co-injection on the same document.
**Impact:** Per-operator standard tier does not guarantee document-level safety if rules overlap on the same frame.
**Fix:** Require a **document-level combination proof** at compile time. The compiler must intersect the operator sets per target origin and verify that no combination of allowed writes creates a conditional page-gadget. Standard tier should only apply to rulesets that pass both per-operator and combination proofs, or be explicitly scoped to non-overlapping frame trees.

### 3. `isolated_network` Label-Derived Denial Lacks Runtime Reactivity
**Section:** §12, §19
**Finding:** `isolated_network` denies every capability with `sink ≠ none` via label-derived denial at grant time. If a catalog update changes a rule's predicate, making a previously `sink: none` `rewrite_url` rule leaking, the registry entry doesn't change, but the runtime behavior does. The private instance will still allow it because the label is static.
**Impact:** Silent privilege escalation in private mode on list update.
**Fix:** Introduce a **dynamic label re-evaluation hook** in the broker. When a catalog revision loads, the compiler re-runs the leak-free criterion (§5) against the new rules. If any rule in the set crosses from `sink: none` to `sink ≠ none`, the broker either (a) downgrades the private instance's grants for those capabilities, or (b) flags the extension degraded in private mode. Document this as a required engine behavior.

### 4. DNS/DoT Egress Circumvention
**Section:** §15, §18
**Finding:** Scope check runs before resolution. However, DNS-over-HTTPS (DoH) routes queries through `https://dns.google/resolve?q=evil.com`. If the extension holds `network.egress_public(["dns.google"])`, it can exfiltrate all queried domains to `dns.google` without ever triggering a scope check against `evil.com`.
**Impact:** DNS query exfiltration bypasses host-scope enforcement.
**Fix:** Treat DoH/DoT resolvers as **trusted but monitored**. Either: (a) require explicit `dns.resolver` capability, (b) enforce DNS query logging for extensions with broad egress, or (c) restrict DoH egress to a closed list of UA-approved resolvers that are cryptographically bound to query minimization. Acknowledge as O9 residual but add a mitigation path.

---

## 🟡 Medium Severity Findings

### 5. `probe` vs `own_hosts` Sink Taxonomy Ambiguity
**Section:** §5, §19
**Finding:** `probe` is used for `dynamic_rules`, `own_hosts` for `rewrite_url`. Both target publisher-observable infrastructure, but `probe` implies telemetry/exfiltration while `own_hosts` implies legitimate publisher tracking. The tiering decision depends on this distinction, yet the spec doesn't define the boundary.
**Impact:** Inconsistent tiering across extensions holding similar capability sets.
**Fix:** Define `probe` as `sink: arbitrary_network` targeting third-party analytics/telemetry servers, and `own_hosts` as `sink: own_hosts` targeting publisher-controlled domains. Add a registry-level `sink_target_class` field to `filtering.dynamic_rules` and `rewrite_url` to make tiering explicit.

### 6. Timing Channel Precision vs Real JS Engines
**Section:** §8, O3, G4
**Finding:** G4 requires "constant-time in page data" and a "deterministic instruction budget". Real JS engines have JIT warm-up, GC pauses, CPU frequency scaling, and thread preemption. Theoretical constant-time doesn't guarantee observable constant-time.
**Impact:** A scriptlet reading page data with a 5% timing variance can still leak via co-resident measurement.
**Fix:** Replace "constant-time" with a **measurable timing budget**: e.g., ≤10% variance on 99th percentile execution time across 10k runs on worst-case input. Require vendor-provided timing coarsening or hardware-level constant-time guarantees for scriptlet execution. Document as O3 enforcement dependency.

### 7. IPC Handle Exhaustion & Broker DoS
**Section:** §16
**Finding:** Unforgeable handles (SCM_RIGHTS or 128-bit random) are required, but no handle quota is specified. A malicious extension could rapidly open handles to exhaust broker resource limits, causing IPC timeouts or broker restarts.
**Impact:** Denial of service to all extensions via broker exhaustion.
**Fix:** Add per-extension handle quotas (e.g., max 256 concurrent) and broker-level global limits. Implement handle recycling with expiration timers and backpressure on IPC dispatch.

### 8. `identity.auth_token` Silent Re-minting & Revocation Granularity
**Section:** §19, `identity.auth_token`
**Finding:** Token is re-minted silently after first consent, granting ambient authority. Revocation is "wholesale only". If a user suspects compromise, they cannot rotate or scope the token without reinstalling the extension.
**Impact:** Over-privileged persistent grant with coarse revocation.
**Fix:** Add a `identity.token.rotate` capability (gated) that forces re-consent and mints a new token. Alternatively, require token binding to extension identity + origin, so revocation of the extension invalidates all tokens.

---

## 🟢 Realistic Attack Vectors

### Vector A: Transitive Page-Gadget via Standard Scriptlet + Cookie
- **Setup:** Extension holds `filtering.scriptlet` (standard, write-only fixed-enum) + `cookies.write` (loud, `sink: session_state`).
- **Scriptlet:** `set-constant(window.cfg.exfil, false)`
- **Cookie:** `Set-Cookie: tracking_id=AUTHENTICATED`
- **Page Gadget:** `if (window.cfg.exfil) { sendBeacon('/collect', {t: document.cookie}) }`
- **Analysis:** Scriptlet writes fixed-enum → integrity-only by lemma. Cookie writes `session_state` → delayed egress. Page reads both, triggers conditional exfiltration. The extension didn't write page data or choose destination, so it's not a sink. However, the **combination** of fixed-enum write + session_state sink enables a transitive channel the page can exploit. The closure correctly labels this as `I:high` but doesn't surface a warning.
- **Mitigation:** Require `cookies.write` to be paired with a loud warning when co-held with any scriptlet, or add a `transitive_gadget` residual label for combinations that enable page-mediated sinks even if individually safe.

### Vector B: Catalog Split-View via Witness Co-Signature Delay
- **Setup:** Compromised catalog publishes revision 42 with malicious rules. Normal witnesses approve. A delayed witness delays consistency proof. Client A receives revision 42, client B stays on 41.
- **Analysis:** Transparency log stops split-view, but witness delays create temporary divergence. Client A gets malicious rules; client B doesn't. Catalog can use this to target users during proof delay window.
- **Mitigation:** Require a minimum quorum of independent witnesses (≥3) with independent uptime monitoring. Add a "witness liveness check" that delays acceptance if quorum isn't met, and surfaces a `catalog_quorum_pending` UI state.

---

## 🔍 Open Question Refinements (O1–O9)

| O# | Current State | Red-Team Recommendation |
|----|---------------|--------------------------|
| **O3** | Per-operator proofs, loud until proven | Add **document-level combination proof** requirement. Standard tier only if both per-operator and co-injection proofs pass. Mandate measurement-based timing validation. |
| **O5** | Pooled budget, rate-limited | Specify concrete parameters: `budget = 1000 reads/profile/week`, `noise = Laplace(σ=0.1)`, `max_read_rate = 5/min`. Require adaptive backoff on denial. |
| **O6** | Store identity proofing, rotation by bound identity | Recommend **DID/store-anchored attestation** for publisher identity. Add catalog key rotation mechanism with grace period and versioned proofs. |
| **O7** | Shared main-world channel, timing residuals | Mandate **side-channel mitigations**: memory randomization, CPU frequency scaling prevention for extensions, timing coarsening. Require store co-install signals for cross-publisher pairs. |
| **O8** | "Audited" validator, schema-generated parser | Replace "audited" with **formal verification targets** for Baleen validator and broker IPC parser. Require taint-tracking validation for scriptlet arguments. |
| **O9** | Named residuals: routing TOCTOU, grace window, revocation commit | Add **mitigation paths**: DNS query minimization for DoT, catalog quorum checks, revocation epoch revalidation on bfcache/prerender (already noted). |

---

## 🛠 Implementation & Deployment Risks

1. **Registry Static vs Runtime Dynamic:** The registry is a compile-time snapshot. Runtime capability derivation (e.g., leak-free criterion, combination safety) must be enforced by the engine, not assumed from static labels. Add a broker-side validation step on list/update load.
2. **Proof-Carrying Artifact Integrity:** Scriptlet proofs are versioned and carried with the library. If an older library version is cached or served via CDN, proofs may be mismatched. Require **proof-version pinning** at injection time and reject mismatched proofs with a clear engine error.
3. **Cross-Profile Parallelization (O5):** Acknowledged as out-of-scope, but worth noting that modern browsers support multi-profile sandboxing. Recommend documenting cross-profile isolation as a UA feature, not a model requirement.
4. **Manifest Translation Ambiguity:** `*.example.com` vs `example.com` wildcard semantics aren't detailed. Clarify that wildcard hosts expand to `content_script(["example.com", "*://*.example.com"])` and that scope canonicalization must preserve wildcard boundaries for grant enforcement.

---

## ✅ Strengths Acknowledged

- The two-axis composition model (information + command flow) is robust and closes most remote-control vectors.
- Byte-splice `rewrite_url` and structured scriptlet closure are engineering-grade defenses.
- Catalog transparency log with inclusion/consistency proofs properly models remote list supply chain.
- Label algebra is closed, typed, and build-validated. Registry closures are mechanically checkable.
- Honest tiering and derived-warning deltas on update prevent silent privilege escalation.

---

## 📝 Final Recommendations

1. **Add dynamic label re-evaluation** for private browsing and list updates.
2. **Require document-level combination proofs** for scriptlet standard tier.
3. **Specify measurable timing budgets** and engine coarsening for scriptlet execution.
4. **Clarify DNS/DoT egress handling** as a residual with mitigation paths.
5. **Mandate formal verification targets** for Baleen validator and broker IPC parser.
6. **Define sink taxonomy boundaries** (`probe` vs `own_hosts` vs `arbitrary_network`).
7. **Add handle quotas and broker backpressure** to prevent IPC DoS.
8. **Document proof-version pinning and mismatch handling** for scriptlet libraries.

This pass confirms the model is exceptionally hardened for a specification of this scope. The identified gaps are primarily enforcement-layer details, combination safety nuances, and deployment-residuals rather than fundamental architectural flaws. Addressing these would move Gosub from a strongly sound model to a provably resilient one.
