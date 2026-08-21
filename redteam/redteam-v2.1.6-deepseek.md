# Red Team Analysis: Gosub Extension Capability Model v2.1.6

## Executive Summary

The progression from v2.1.4 to v2.1.6 represents **substantial maturation** of the security model. The team has addressed the majority of critical vulnerabilities identified in the previous red-team pass, particularly:

- ✅ The stats budget parallelization attack (now pooled globally)
- ✅ The scriptlet value-gadget sink (now value-vocabulary allowlisted)
- ✅ The rewrite phantom-separator attack (raw-tokenization before decode)
- ✅ The compiler-TOCTOU on memfd (assembler owns the descriptor)
- ✅ The in-flight revocation race (epoch-based abort)
- ✅ The publisher-key sharding attack (stable organizational identity)
- ✅ The artifact-authority confusion (envelope intersection)

This is now a **substantially stronger document**. The remaining issues are more subtle: proof-obligation gaps, residual covert channels, and a few architectural tensions that red-team passes continue to surface.

---

## Critical Remaining Vulnerabilities

### 1. The Scriptlet Control-Dependence Proof is a Promise, Not an Enforcer

**Issue:** v2.1.6 correctly identifies that control-dependence non-interference is the hard part: "no operator's extension-observable behavior (a write, an exception, a timing change, a response substitution a co-resident context can see) may depend on page state." The document then says this is "checked at rule-compile time AND RE-VALIDATED BY THE RENDERER-SIDE INJECTOR" and that operators are "admitted only where their page-dependent branching stays confined to the page's own realm."

**The gap:** The renderer-side injector cannot **re-validate** control-dependence non-interference from the artifact. It can validate arity, type schema, target shape, and value vocabulary — all structural properties. But "does this operator's behavior depend on page state" is a **semantic property of the operator implementation**, not something present in the rule `(operator_id, args)` tuple. The injector has only the operator ID and arguments; it cannot know whether the operator's internal implementation has control-dependence leaks.

**What this means:** The only place the control-dependence property can be enforced is at **library build time**, with per-operator proofs. The renderer-side "re-validation" is checking that the operator ID is in the library, not that the library operator satisfies the property.

**Attack:** A compromised compiler emits `(operator_id='json-prune', args=['user', 'secret'])` where `json-prune` is a library operator whose proof has a subtle flaw (or whose proof was never formally verified). The renderer re-validates that `json-prune` is in the library and the args match the schema — both pass. The operator executes and its page-dependent branching leaks a bit through timing or an exception pattern. The "re-validation" provided no defense.

**Recommendation:** The document must distinguish between:
- **Structural validation** (can be done at injection time from the artifact)
- **Semantic proof** (must be done at library build time and the proof must be **attached to the artifact** in a verifiable way)

The O3 obligation must state that the proof itself is **machine-checkable and part of the shipped library artifact**, not just "audited." The renderer doesn't need to re-prove the property; it needs to **verify the proof** (or trust a proof-carrying code system).

**Severity: Critical** — this is the boundary between "we have a proof obligation" and "we have an enforcement mechanism."

---

### 2. The Shared-Main-World Cross-Publisher Covert Channel is Underspecified

**Issue:** O7 acknowledges: "the shared-main-world channel between unrelated publishers' scriptlets and content scripts (§8) — which the §5 closure does NOT enumerate because it is an undeclared cross-publisher channel, so it is handled here by review, not by the composition detector."

**The threat:** Two extensions from different publishers — one with `filtering.scriptlet` and one with `content_script` (loud) — can communicate through the page's main world. The first sets `window.__gadget = secret`; the second reads it and egresses it. The §5 closure does **not** detect this because the extensions are not in the same communicating set (no externally_connectable, no shared storage, no native-messaging bridge). They are unrelated publishers colluding through a **covert channel the browser provides**.

**Why this matters:** The model's entire two-axis composition logic depends on the ability to detect and surface combined authority. If extensions can combine authority through channels the model doesn't enumerate, the derived-warning dialog becomes incomplete.

**Attack scenario:**
1. Extension A (publisher P1) gets `filtering.scriptlet` (standard, after O3) — it can write to the page's main world
2. Extension B (publisher P2) gets `content_script` + `network.egress_public(c2.example)` (loud)
3. Neither extension alone has "can exfiltrate page content" — A has no egress, B has no page access
4. Together: A writes page-derived data to `window.__x`; B reads `window.__x` and egresses it
5. The dialog for each extension shows its individual grants, not the combined exfiltration path
6. The §5 closure doesn't catch it because P1 ≠ P2

**Counterargument:** The document might say "unrelated publishers colluding through their own servers plus an OS covert channel are out of manifest-analysis scope." But this isn't a "server plus OS covert channel" — it's a **browser-provided shared execution environment** that the model explicitly creates (main-world injection is by design).

**Recommendation:** This is a **fundamental architectural tension** that the document must address, not relegate to O7. Options:
- **Option A:** Accept the channel and extend the closure to include the page as a communicated set (any two extensions with main-world access compose)
- **Option B:** Isolate scriptlet effects from cross-extension detection (e.g., randomize property names per document so the receiving extension can't predict the name)
- **Option C:** Acknowledge this as a **fundamental limitation** and tier `filtering.scriptlet` permanently loud (not standard), with the dialog honestly stating "This extension can communicate with other extensions through pages"

**Severity: High** — undermines the composition model's completeness claim.

---

### 3. The Stats Privacy Pool is a Security Promise With No Implementation Sketch

**Issue:** v2.1.6 correctly pools the stats budget globally. But the document provides no:
- Mathematical model of the noise mechanism
- Bound on total leakage over a session
- Specification of the budget replenishment/refill policy
- Proof that the global pool actually bounds parallelization (an attacker can still shard across browser profiles, incognito vs regular, or multiple installations)

**Attack:** The attacker installs 100 one-rule extensions across 100 different browser profiles. The global pool is per-profile, so each profile has its own budget. The attacker probes 100 sites in parallel across profiles.

**Defense:** The model says "per browser profile" — but a privacy-conscious attacker can create multiple profiles. The only way to truly bound this is to make the budget per **machine** or per **user**, which requires OS-level trust.

**Recommendation:** The document must specify:
- The exact noise mechanism (Laplace? Gaussian? with what ε, δ?)
- The refill rate (if any) and how it's bounded
- Whether the budget is per-profile or per-device
- A formal statement of the leakage bound, with assumptions explicitly stated

**Severity: High** — the current "O(weeks) per site" criterion is aspirational without a specification.

---

### 4. The Remote Interpreter Problem is Named But Not Solved

**Issue:** v2.1.6 §10 honestly states: "Forbidding remote interpreters outright is a store/review-policy matter, named here rather than claimed by the runtime." This is honest, but it means the capability model does **not** prevent a packaged interpreter from being driven by remote data.

**Attack:** An extension packages a JavaScript interpreter (e.g., a JSON-execution engine, a WASM VM, a rules engine with conditional logic). It fetches a program from `c2.example`, interprets it, and the program uses the extension's grants to perform actions. The extension's CSP doesn't block it (no `eval`, no remote scripts — the interpreter is packaged code). The capability model sees `network.egress_public(c2.example)` + whatever actuators the interpreter can drive, and Axis 2 surfaces `remote_server × actuator`. But **the program could still be arbitrary code interpreted in the extension's privileged context**, and the capability model's only defense is "the interpreter can only do what the grants allow."

**Is this sufficient?** If the interpreter's behavior is limited by the grants, then in principle Axis 2 surfaces the remote control. But:
- The interpreter might have **unintended capabilities** (e.g., it can call any method on any object the extension holds, not just the ones the capability model enumerates)
- The interpreter's execution model might create **novel side channels** (timing, memory allocation patterns)
- The interpreter might be able to **bypass the broker's per-operation checks** if it holds references to privileged objects

**Recommendation:** The model should require that any packaged interpreter be **explicitly declared** and **reviewed for capability-safety** — the runtime cannot generically prove that an interpreter won't create new attack surfaces. The "store/review-policy" admission is too weak.

**Severity: High** — this is a known attack class the model explicitly acknowledges it doesn't solve.

---

## High-Risk Architectural Issues

### 5. The Scriptlet Write-Value Allowlist Prevents Real Use Cases

**Issue:** The scriptlet write-value allowlist is "fixed vocabulary of defusing constants — `false`/`true`/`null`/`undefined`/`''`/`0`/`noopFunc`/`emptyObj`/`emptyArr`." This prevents `set-constant('someLib.cfg.returnUrl', 'https://attacker.com')` (good) but also prevents legitimate uses like setting a user's preference, a configuration value, or a feature flag that the page expects to be a specific string.

**Real-world scriptlet use:** uBO's `set-constant` sets values like `adsEnabled = false`, `debugMode = false` — booleans. But other scriptlets in the AdGuard/uBO ecosystem set **strings** like `window.__cmp = null`, `window.__tcfapi = null`, or `document.cookie = '...'` (the cookie one is already banned).

**The tension:** The document's value allowlist bans the very payloads that make scriptlets useful in the real world. If the library is limited to `false`/`null`/`0`/`emptyObj`, it cannot:
- Null out a problematic property (`window.ga = null`)
- Set a configuration to a specific non-boolean value (`__cmp.isActive = false` is boolean, fine; `__cmp.version = '1.0'` is not)
- Replace a function with a no-op (this is allowed via `noopFunc`, but parameterized no-ops might need different behaviors)

**Recommendation:** The allowlist must be **extension-specific** — each operator declares the allowed value types. `set-constant` can allow a `null`/`false`/`''` vocabulary; a more specific operator (e.g., `set-version`) could allow a version string. The current one-size-fits-all value allowlist is too restrictive and will push publishers to use `content_script` for legitimate use cases.

**Severity: Medium** — usability issue that weakens the model's adoption.

---

### 6. The Rewrite URL "Raw Tokenization" Boundary Depends on Server Parsing

**Issue:** v2.1.6 fixes the phantom-separator attack with raw-`&` tokenization before decoding. But as the document notes: "the `;` decision is a documented parser choice, not a security boundary."

**The parser-choice problem:** The browser chooses `&` as the sole separator. If the server uses `;` as a separator (legacy systems, some ASP.NET configurations, some CMS systems), then:
- Rule: `$removeparam=utm_source`
- URL: `https://server.com/page?;utm_source=tracker&a=b`
- Browser tokenizes on `&` only: sees `;utm_source=tracker` as **part of a segment**, doesn't remove it
- Server splits on `;`: sees `utm_source=tracker` and logs it
- The rule did nothing

**But there's a worse case:** If the server uses `&` but the page writes `%26fbclid=x` (percent-encoded `&`), raw-tokenization prevents the phantom separator. But what if the server **decodes** the URL before parsing? The browser's WHATWG URL parser decodes percent-encoded bytes in the query **when accessed via `URLSearchParams`**, but the raw URL sent over the wire still contains `%26`. The server may decode and parse, or parse raw. This is a fundamental ambiguity.

**Recommendation:** The rewrite capability should be **defined in terms of the browser's own URL parser**, not in terms of raw bytes. The browser should remove parameters from the **parsed query** (using `URLSearchParams` semantics) and then re-serialize the URL. Yes, this changes the wire bytes (percent-encoding, reordering) — but those changes are **deterministic and browser-controlled**, not rule-influenced in a security-relevant way. The current byte-splice approach tries to preserve raw bytes but ends up with parser ambiguities anyway.

**Severity: Medium** — the capability is well-intentioned but has inherent ambiguity that makes it less useful than it appears.

---

### 7. The Baleen Artifact Mmap-ability vs Portability Tension

**Issue:** v2.1.6 doesn't fix the underlying tension between mmap-able artifacts and platform portability. The document now says "flat, offset-based, position-independent, mmap-able artifact" — but mmap behavior (alignment requirements, page size, endianness, file format) varies across platforms.

**Attack:** A malicious extension could craft an artifact that is valid on one platform (e.g., x86-64 Linux) but triggers undefined behavior on another (e.g., ARM64 macOS), potentially leading to a security vulnerability on the platform where the artifact wasn't tested.

**Recommendation:** The artifact format must be **platform-agnostic** (e.g., using a well-specified binary format like Cap'n Proto or FlatBuffers) and the mmap-ability should be a **performance optimization** that only applies when the artifact is validated for the current platform.

**Severity: Medium** — cross-platform compatibility issue that could become a security issue.

---

## Medium-Risk Issues

### 8. The Stats Display Badge is Still a Side Channel

**Issue:** v2.1.6 doesn't address the "badge as a side channel" issue from the previous pass. An extension with `capture.tab_pixels` can read its badge counter by capturing the browser UI. Even if `capture.tab_pixels` can't capture the browser window (it captures tabs), the extension could open a page and use page-rendering APIs to infer the badge value.

**Attack:** Extension with `stats.display` (silent) and `content_script` (loud) could read the badge by injecting a script that checks CSS properties of the browser UI (if accessible) or by using a screenshot of the entire screen (if the OS API allows).

**Recommendation:** The badge value should be **inaccessible to extension code through any channel**, including pixel capture. This means the badge must be rendered in a separate process that cannot be captured by extension code.

**Severity: Medium** — requires an attacker to have both `stats.display` and a capture capability, but the composition should be detected.

---

### 9. The Cross-Origin Frame Grant Inheritance is Too Broad

**Issue:** §13 says: "A grant covers the top-level document plus its *same-origin and inherited-origin* (`about:blank`, `srcdoc`) descendants only. A **cross-origin** child frame needs a separately held host grant."

**The problem:** The grant epoch is inherited frame-tree-wide, but the **authority** is not. This means the extension knows a cross-origin frame exists (it's in the frame tree), but it doesn't have authority over it. This is a **timing side channel**: the extension can observe when a cross-origin frame is created/destroyed because the frame-tree events still fire.

**Attack:** An extension with `tabs.events` (loud, source: tab_urls) can observe frame tree changes for a cross-origin frame, even though it can't access the frame's content. This reveals the presence of cross-origin content (e.g., an OAuth login frame, a payment iframe).

**Recommendation:** Frame-tree events should be **coarsened** or **aggregated** when the extension doesn't have authority over a frame. The extension shouldn't be able to distinguish between "same-origin frame created" and "cross-origin frame created" if it can't access the latter.

**Severity: Medium** — side channel that leaks information about cross-origin content.

---

### 10. The Content Handler Isolation Claim is Overstated

**Issue:** §19 says `content_handler` is "isolated principal" and "network-origin responses only; refuses cross-origin-credentialed unless origin matches." But:
- The content handler runs in a separate process, but it **renders the response body**
- The extension code can see the rendered content (that's the whole point)
- The extension can have `network.egress_public(c2.example)` and exfiltrate the content

**Attack:** A JSON formatter extension (`content_handler` for `application/json`) with `network.egress_public(attacker.example)` can exfiltrate JSON response bodies. The `content_handler` capability doesn't include egress, but the extension can have both.

**Is this detected?** Yes — `content_handler` is `source: page_content/credentials` and `network.egress_public` is a sink, so Axis 1 gives `page_content × arbitrary_network -> page.exfiltration`. The dialog would say "Can send the contents of pages you visit to attacker.example."

**The issue:** The dialog would be honest, but the user might not realize that **response bodies** are included in "pages you visit." The content handler capability isn't a page *script* — it's a *renderer* — so the user might think "it only displays JSON, it doesn't read the page."

**Recommendation:** The content handler dialog should be more specific: "This extension can read the raw content of [MIME type] responses you visit."

**Severity: Low-Medium** — honest but potentially misleading.

---

## Philosophical Issues (Revisited)

### 11. The "Proof Obligation" Approach is Progress, But the Proofs Don't Exist Yet

**Issue:** v2.1.6 adds O8: "Enforcement rigour named as proof obligations rather than assumed: the §14 validator (formal verification, enumerated attack list), the §8 scriptlet library (per-operator non-interference proofs), and the §16 broker parser (schema-generated over a verified parsing core)."

This is excellent progress — the document now acknowledges that "audited" is a placeholder. But it also means the model is **not yet secure**. The proofs for the scriptlet library are non-trivial (control-dependence non-interference for arbitrary scriptlet operators), and the formal verification of the Baleen validator is a significant undertaking.

**The risk:** The document's sophistication creates a perception of security that the implementation may not yet achieve. "Proof obligation" is not "proof."

**Recommendation:** The document should be **explicit about what is implemented and what is designed**. The "Loud until proven" tier for scriptlets is a good start — it means the model is conservative until the proofs exist. The same should be true for the Baleen validator and the broker parser.

**Severity: Medium** — honesty issue that affects trust.

---

### 12. The "Dialog is Not the Security Boundary" Caveat is Buried

**Issue:** §11 now says: "the dialog is not the security boundary — the capability restrictions are. Most users will not read or fully understand it; a true dialog is necessary for informed consent and useless as a containment mechanism, which is exactly why the model's guarantees (§5–§17) never depend on the user parsing it."

This is **correct** but **buried** in the dialog section. A user reading the document might think the model depends on users reading dialogs. The document should lead with this point: **the capability restrictions are the security boundary, not the dialog.**

**Recommendation:** Move this caveat to the overview or Part I.

**Severity: Low** — clarity issue.

---

## Specific Attack Scenarios (Updated)

### Attack 1: The Cross-Publisher Main-World Covert Channel

1. Publisher P1 has extension with `filtering.scriptlet` (standard after O3)
2. Publisher P2 has extension with `content_script` + `network.egress_public`
3. P1's scriptlet sets `window.__secret = pageData`
4. P2's content script reads `window.__secret` and egresses it
5. Neither extension's dialog shows exfiltration; P1 has no egress, P2 has no page source
6. The §5 closure doesn't detect cross-publisher channels

**Defense:** Option A (extend closure to the page), Option B (randomize property names), or Option C (loud tier for scriptlets).

### Attack 2: The Packaged Interpreter Remote Control

1. Extension packages a JavaScript interpreter (packaged code, so CSP allows it)
2. Extension has `network.egress_public(c2.example)` + interpreter-driven actuators
3. Extension fetches `c2.example/program.json` and interprets it
4. The program uses the extension's grants to perform actions
5. Axis 2 detects `remote_server × actuator`, but the interpreter's execution model may create additional side channels

**Defense:** Explicitly declare interpreters; review for capability-safety; limit the interpreter's privileges.

### Attack 3: The Stats Budget Cross-Profile Parallelization

1. Attacker creates 100 one-rule extensions
2. Attacker creates 100 browser profiles
3. Each profile installs one extension (with its own `stats.read` budget)
4. Each profile probes one sensitive site
5. The global per-profile budget doesn't prevent parallelization across profiles

**Defense:** Budget must be per-device or per-user, requiring OS-level trust.

---

## Recommendations Summary

### Critical (Must Fix Before Deployment)

1. **Distinguish structural validation from semantic proof** for scriptlet control-dependence non-interference — the renderer cannot re-prove the property at injection time; the proof must be attached to the library artifact and machine-checkable.

2. **Address the cross-publisher main-world covert channel** — either extend the closure to include the page as a communicated set, isolate scriptlet effects, or tier `filtering.scriptlet` permanently loud with an honest dialog line.

3. **Specify the stats privacy budget mathematically** — exact noise mechanism, refill policy, leakage bound, and assumptions.

### High Priority

4. **Solve or explicitly bound the remote interpreter problem** — don't just name it; specify a review/declaration requirement for packaged interpreters.

5. **Reconcile the scriptlet value allowlist with real-world use cases** — operator-specific value vocabularies, not one-size-fits-all.

6. **Define the rewrite URL capability in terms of the browser's URL parser** — accept deterministic serialization changes rather than trying to preserve raw bytes.

### Medium Priority

7. **Make the Baleen artifact platform-agnostic** — don't rely on mmap semantics across platforms.

8. **Close the badge side channel** — badge values must be inaccessible to extension code.

9. **Coarsen frame-tree events** for cross-origin frames the extension can't access.

### Low Priority

10. **Move "dialog is not the security boundary" to the overview** for clarity.
11. **Be explicit about what is implemented vs. designed** — the proof obligations are a roadmap, not a current state.

---

## Conclusion

**v2.1.6 is a significant improvement over v2.1.4.** The team has addressed the most critical vulnerabilities identified in the previous pass, and the model is now substantially more robust. The introduction of explicit proof obligations (O8) is a welcome honesty upgrade.

However, several **fundamental tensions** remain:

1. **Scriptlet control-dependence non-interference** is a semantic property that cannot be re-validated at injection time; it requires a proof-carrying approach.

2. **Cross-publisher main-world communication** is a covert channel the model's closure logic does not detect, undermining the composition guarantee.

3. **Stats privacy** is a mathematically hard problem that the document acknowledges but doesn't solve.

4. **The remote interpreter problem** is named but not contained.

The document is now a **strong design** with a clear roadmap (the proof obligations in O8). But it is not yet an **enforced model** — the proofs don't exist, and some architectural tensions require resolution.

**Final assessment:** v2.1.6 is a **substantially improved, directionally correct** security model. With the completion of the proof obligations (O3, O8) and resolution of the cross-publisher channel tension, it could become a robust foundation. In its current form, it's ready for a prototype implementation, but the security guarantees are still partially aspirational — the proof obligations must be discharged before the model can be considered complete.