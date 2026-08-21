Red Team Analysis: Gosub Extension Capability Model v2.1.4
Executive Summary

This is a sophisticated, thoughtfully constructed security model that has clearly benefited from multiple adversarial reviews. The team has done excellent work identifying and closing attack surfaces. However, several systemic issues remain — some philosophical, some architectural, and some adversarial — that merit further attention.
Critical Vulnerabilities
1. The Compiler Compromise Model is Incomplete

Issue: §14 assumes "a compromised compiler yields a hostile artifact" that consumers validate. However, the validation boundary is poorly defined for several artifact types.

Attack: A compromised compiler could emit an artifact that:

    Passes §14's DAG/step-cap validation but triggers JIT compilation blowups (lookup tables that cause exponential memory growth)

    Uses integer overflows in the offset validation that aren't caught by forward-only checks

    Exploits the validator's own parser (which is "small enough for manual audit" but that's a statement, not a proof)

Recommendation: The validator must be formally verified, not just "audited." The threat model should explicitly list the classes of attacks the validator defends against, with proof obligations for each.
2. The Stats Privacy Budget is Underspecified to the Point of Meaninglessness

Issue: §7 says the privacy budget must make "a rigorous statement (O5's criterion: a single-site probe needs O(weeks) to distinguish one visit from noise)." This is an admirable goal but impossible to achieve against an adaptive adversary who can:

    Install multiple extensions, each with its own budget

    Prime the counter near quantization boundaries

    Use browser timing APIs (which §7 notes are available via scheduling)

    Combine multiple noise-free signals

Attack: Deploy 100 extensions, each with one rule targeting a different sensitive site. Each extension gets its own privacy budget. Even with O(weeks) per extension, the adversary can probe 100 sites simultaneously — the parallelization defeats the bound.

Recommendation: Budgets must be pooled across publishers, or stats.read must be eliminated entirely in favor of stats.display. The current design is mathematically unsound.
3. Scriptlet Admission Closure is a Security Boundary Built on Sand

Issue: §8's "admission closure" is impressive on paper but has no formal enforcement mechanism. The browser must "verify" the closure at compile time and re-validate at injection time, but:

Attack Vectors:

    The "arity/type schema" is browser-defined; a hostile compiler could target a bug in the schema compiler itself

    The "write-target allowlist" is a positive schema; a hostile scriptlet could find a property path that bypasses the allowlist but still has side effects (e.g., window[Symbol.unscopables] or document[Symbol.iterator] injection)

    The "byte-provenance channel rule" — "no operator writes a value derived from page state it read" — is a static analysis problem that the document admits is not solved. This is a runtime property the injector cannot enforce without taint tracking.

Concrete Example: A scriptlet that reads document.cookie and writes window._cache = cookie might (depending on the operator's implementation) violate the byte-provenance rule, but the validation only checks arity and type schema, not semantic taint.

Recommendation: Either the scriptlet library must be formally verified with a proof of the admission closure, or the closure must be enforced by a runtime taint-tracking system. The current approach is aspiration masquerading as enforcement.
4. Rewrite URL Parsing Differential is a Security Vulnerability, Not a Residual

Issue: §6 says: "Parsing differentials: raw-byte matching with & as the only separator removes Sonar-side ambiguity, but a server that percent-decodes keys or honors ; separators can still parse the surviving bytes into different logical parameters than the rule author saw — a bounded integrity residual."

Attack: A tracking server that uses ; as a parameter separator (common in some legacy systems) would see the original parameters, not the stripped ones. The rule author believes fbclid was removed; the server sees it. This is a silent failure of the rewrite mechanism.

Worse: An attacker could exploit this differential to exfiltrate data. Example: https://attacker.com/;payload=secret — the browser treats ;payload as a separator, the server sees ;payload=secret. The rule can't strip the ; separator because it's not a key=value pair.

Recommendation: The rewrite capability should specify the exact parsing semantics (e.g., "use the WHATWG URL parser for matching and removal"), or it must be downgraded to require the server's actual parsing behavior (impossible). The "bounded residual" framing is dangerously optimistic.
5. Publisher Identity Transfer is a Soft Problem

Issue: §13 says publisher transfer triggers re-consent. But "publisher is the signing-key identity" — what happens when:

    A company rotates its signing key (legitimate security practice)

    A company splits into two legal entities that share a signing key

    A company is acquired but continues using the same key

    A key is compromised and revoked

Attack: An attacker compromises a publisher's signing key, ships an update with new capabilities (but still under the same "publisher identity"), and the only check is the update diff — which, if the attacker is clever, can add a new capability that looks like a "narrowing" but isn't.

Recommendation: Publisher identity must be tied to organizational identity with a formal key rotation protocol, not just the signing key. Otherwise, "publisher transfer" can be gamed.
High-Risk Architectural Issues
6. The Isolation Model Breaks on Shared Contexts

Issue: The model assumes isolation between extensions and pages, but admits two major exceptions:

    Scriptlets run in the main world (by necessity)

    Content scripts run in isolated worlds but share the DOM

Attack: Two extensions from different publishers can communicate via the shared DOM (e.g., one writes a global variable, another reads it). This is explicitly called out as a "covert-channel residual" in O7, but the model doesn't account for it in the publisher-principal closure.

Worse: An extension with filtering.scriptlet (standard tier, auto-granted) can set a global variable that a malicious page reads. The page then uses that variable to infer something about the user's extension set (a fingerprinting vector).

Recommendation: The model needs to explicitly handle cross-extension communication in the same execution environment. The current approach ("it's a residual, we'll review it") is not sufficient for a security architecture.
7. The "No Remote Data Executable Code" Rule Has Exceptions

Issue: §10 says "Remote data must not be usable to introduce general-purpose executable logic into a privileged extension context." But the document permits:

    filtering.remote_rulesets (remote data that controls filtering behavior — policy, not code, but policy is code in this context)

    filtering.scriptlet (remote data that selects and parameterizes browser code — more policy)

    system.user_scripts (explicitly gated exception)

Attack: A remote ruleset that uses ##+js(...) can effectively inject arbitrary scriptlet behavior into the page. While the scriptlets are "audited," the selection and parameterization is remote-controlled. This is remote code execution in all but name.

Recommendation: Either accept that "remote data controlling browser behavior" is remote code, or draw a much sharper line: scriptlets must be content-addressed, not selected by name+args from remote data.
8. The Header Modification Safe-List is a Moving Target

Issue: §15's "modifiable safe-list only; Cookie, Authorization, Host, Origin, Sec-Fetch-*, Set-Cookie, Strict-Transport-Security, Content-Length, CORS headers are engine-controlled." This is a list that must be maintained as HTTP evolves.

Attack: A new HTTP header is introduced that isn't on the safe-list, but an extension can use it to bypass security checks. Example: a new Sec-* header that the browser trusts implicitly.

Recommendation: The safe-list should be protocol-generated, not manually maintained. Any header the engine treats specially for security must be automatically protected.
9. Private Browsing Isolation Has a Network Gap

Issue: §12 says "two instances that both hold egress to the same host can be correlated by the vendor via IP and timing, which is why private access is granted separately and isolated_network exists." But isolated_network only helps if the extension doesn't need network access — many do.

Attack: A password manager in private browsing mode still needs to sync with its server. The server can correlate the private browsing session with the regular one via:

    Device fingerprinting (navigator APIs in the page)

    Extension-specific request patterns

    Timing of sync operations

Recommendation: Private browsing isolation should include network fingerprinting protections (e.g., identical TLS fingerprints across sessions, randomized timing), not just "no network egress" as a special case.
Medium-Risk Issues
10. Grant Revocation is Underspecified

Issue: §13 says revocation "broadcasts a Baleen table update" and "propagation pre-empts the worker event loop." But:

    What if the worker is in the middle of processing a request?

    What if the worker has already validated a grant and is performing a long-running operation?

    What about in-flight requests that were already matched against the old table?

Attack: A revoked extension can still complete operations that were started before revocation, or can race the revocation to perform additional operations.

Recommendation: Grants must be epoch-based: each operation is tagged with the grant epoch at validation time, and the operation is aborted if the grant epoch changes. This is the only way to handle revocation correctly.
11. The Stats Display Badge is a Side Channel

Issue: §7 says stats.display is "silent" because the extension never reads the value. But the badge is rendered by the browser — and the extension can observe the rendered content via pixel capture, screenshot, or even memory inspection.

Attack: An extension with capture.tab_pixels can read its own badge counter by capturing the browser UI (assuming capture.tab_pixels can capture the browser window, which is unclear). Or, more simply, the extension can use tabs.snapshot or tabs.capture_pixels to read the badge.

Recommendation: stats.display must be isolated from all pixel-capture mechanisms, or the badge must be shown in a way that prevents extension observation (e.g., rendered in a separate process).
12. The Baleen Build-Vs-Embed Threshold is a Moving Target

Issue: §14 says "write the Baleen core only if adblock-rust misses a target... by more than 20% and profiling shows the gap is intrinsic." This is a recipe for never writing Baleen, because:

    The threshold is relative to a moving target

    "Intrinsic" is subjective

    Profiling is always susceptible to optimization

Recommendation: Either commit to writing Baleen (it's the security boundary) or design the system so adblock-rust can be sandboxed and validated. The current approach is a design ambiguity that will cause delays.
13. The Content Handler Isolation is Too Weak

Issue: §19 says content_handler is "scoped by ORIGIN + MIME" and "isolated principal." But a JSON viewer that runs in the content-handler context can:

    Read the page's origin (including path and query parameters)

    Access the response body (which could contain sensitive data)

    Run JavaScript in the page's context (if the page uses JSONP or similar)

Attack: A malicious JSON viewer extension (or a compromised one) can exfiltrate the response body and origin. The "isolated principal" doesn't help if the extension can see the data it's handling.

Recommendation: Content handlers must be capability-scoped: they can display the data but cannot send it elsewhere unless they have a separate egress grant, and that grant must be in the dialog.
14. The "No Response Body" Rule Has an Exception

Issue: §15 says the matching scope "never response bodies." But devtools.network (loud) can read HAR logs including response bodies. And content_handler can render response bodies. And capture.tab_pixels can capture rendered response bodies.

Attack: An extension with devtools.network and network.egress_public can exfiltrate response bodies. This is explicitly allowed (it's loud), but the model's claim that "filtering never sees response bodies" is a half-truth.

Recommendation: The model should be honest about response body access: it's available through DevTools and content handlers, and these capabilities should be tiered appropriately (they are, but the framing in §15 is misleading).
Philosophical Issues
15. The "Honest Dialog" Goal is Aspirational

Issue: The model repeatedly says the installation dialog should be "true" and "honest." But:

    Most users won't read it

    Most users won't understand the implications

    The "derived authority" warnings are technical and precise, but not necessarily understandable

Attack: A malicious extension can rely on user inattention — the dialog says "can send contents of pages you visit to api.foo.example," but the user doesn't know api.foo.example is malicious.

Recommendation: The security model should not depend on user comprehension. "Honest dialog" is a nice-to-have, not a security boundary. The model's real security is in the capability restrictions, not the dialog.
16. The "Private Browsing is a Boundary" Claim is Too Broad

Issue: §12 says private browsing is a boundary, but the model only talks about extension-side state. It doesn't address:

    Browser-side state (history, cache, cookies) that the extension can observe through other means

    Network-level state (IP, timing, TLS fingerprints)

    Cross-session correlation via extension updates or settings

Attack: An extension can use its own network egress to correlate private and regular sessions, even with isolated_network (it can't egress in private mode, but the regular session can send identifying information).

Recommendation: Private browsing isolation should be browser-wide: the browser should not create network-level correlatable state across sessions.
Implementation Concerns
17. The Broker Parser is "Schema-Generated" but Unspecified

Issue: §16 says the message parser is "schema-generated, not hand-written," but doesn't specify:

    The schema language

    The generation tool

    The formal properties of the generator

    The verification of the generated code

Attack: A bug in the code generator (or a malicious generator) could introduce parser vulnerabilities that the model's fuzzing doesn't catch.

Recommendation: The broker's parser should use a well-established, formally verified parsing library (e.g., a Rust parser with proven memory safety), not a custom-generated parser.
18. The IPC Capability Handles are "Unforgeable" but Unspecified

Issue: §16 says capability references are "unforgeable" via "kernel-mediated (SCM_RIGHTS) or per-connection randomized handles." The "or" is concerning — which is it? If it's randomized handles, they need to be large enough to prevent brute force, and they need to be tied to the connection.

Attack: If handles are randomized 32-bit integers, a compromised worker can brute-force them. If they're 128-bit, the connection can replay a handle from another connection.

Recommendation: Capability handles must be kernel-mediated (SCM_RIGHTS) to ensure they can't be forged or replayed. The "or" should be removed.
19. The Baleen Artifact is "Mmap-able" but Not Portable

Issue: §14 says the artifact is "mmap-able" and "position-independent," but mmap behavior varies across platforms. A Windows-specific artifact might not be valid on Linux, and vice versa.

Recommendation: The artifact format should be platform-agnostic (e.g., using a serialization format like Cap'n Proto or FlatBuffers), not directly mmap-able. The current approach will cause compatibility issues.
20. The "Restore Controls" are Underspecified

Issue: §17 says "restore controls rendered outside any extension-controlled surface" for new-tab override, notifications, etc. But what does "restore" mean? If a user accidentally clicks "always use this new tab page," how do they undo it?

Recommendation: The restore mechanism must be specified: a dedicated browser settings page that lists overrides and provides a "reset" button, not just a "restore controls" phrase.
Specific Attack Scenarios
Attack 1: The Stats Budget Parallelization Attack

    Attacker creates 100 extensions, each with one rule targeting a different sensitive site

    Each extension has stats.read (standard) and filtering.block (silent)

    Each extension gets its own privacy budget

    Attacker monitors all 100 budgets, revealing activity on 100 sites simultaneously

    The O(weeks) per-budget bound doesn't help because the attacker parallelizes

Defense: Budgets must be pooled across publishers, or stats.read must be eliminated in favor of stats.display.
Attack 2: The Scriptlet Taint Attack

    Attacker creates a rule: example.com##+js(json-prune, data.user, secret)

    The scriptlet reads data.user from the page's JSON data and removes secret

    The scriptlet doesn't write the value, but the page's own JavaScript can observe that secret is no longer there

    The page uses this observation to infer something about the extension (fingerprinting)

Defense: The admission closure must include "no observable side effects that could be used as a side channel." Currently, it only forbids writing page-derived data.
Attack 3: The Rewrite Differential Exfiltration

    Server uses ; as a query parameter separator (legacy support)

    Rule: $removeparam=payload

    Page loads https://server.com/;payload=secret

    Browser matches payload (using & separator) and removes it

    Server sees ;payload=secret and processes it

    The extension has exfiltrated secret through the rewrite mechanism

Defense: Rewrite must be specified at the logical parameter level, not the byte level, using the server's actual parsing behavior.
Attack 4: The Publisher Identity Confusion Attack

    Company A is acquired by Company B

    Company A's signing key is still valid

    Company B pushes an update with new capabilities

    The update diff is shown, but it's a "narrowing" (removes a capability)

    The narrowing is actually a deception: the extension now uses a different capability that wasn't previously available

    The user approves the update without realizing the extension's behavior has changed

Defense: The grant diff must include semantic changes, not just capability additions/removals. A "narrowing" that changes behavior should still trigger re-consent.
Recommendations Summary
Immediate Actions

    Formalize the stats privacy budget or eliminate stats.read entirely

    Add taint tracking for scriptlets, or formally prove the admission closure

    Specify rewrite parsing semantics exactly (WHATWG URL parser), or remove the capability

    Add epoch-based grant revocation to handle revocation correctly

    Pool privacy budgets across publishers to prevent parallelization attacks

Medium-Term Actions

    Formally verify the Baleen validator (not just "audit" it)

    Add runtime taint tracking for the scriptlet admission closure

    Specify the broker's parser using a well-established, verified library

    Add platform-agnostic artifact serialization (not mmap-based)

    Specify the restore mechanism for UI overrides

Long-Term Actions

    Address cross-extension communication in the same execution environment

    Add network fingerprinting protections for private browsing

    Formally specify publisher identity and key rotation

    Address the "remote data controlling browser behavior" tension explicitly

    Add side-channel protections for stats.display and scriptlet effects

Conclusion

The Gosub capability model is a substantial advance over the MV2/MV3 permission systems. It has clearly been subjected to rigorous adversarial review, and the team has addressed many subtle attack vectors. The architectural decisions — separate observation from control, two-axis capability composition, publisher-principal closure, and browser-native filtering — are sound.

However, the model still has significant gaps in its enforcement mechanisms, particularly around the stats privacy budget, the scriptlet admission closure, the rewrite parsing semantics, and the grant revocation model. These are not mere implementation details — they are security properties that the model claims but doesn't fully deliver.

The biggest risk is that the model's sophistication creates a false sense of security. The document's frequent use of "residual," "bounded," "honest," and "audited" suggests that the team is comfortable with certain attack surfaces. Some of these surfaces are more attackable than the document acknowledges.

Final assessment: The model is directionally correct and addresses the major known attack vectors. With the recommended hardening, it could become a robust security architecture. In its current form, it's a significant improvement over existing systems but not yet ready for deployment against determined adversaries.
