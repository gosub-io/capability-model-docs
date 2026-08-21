Gosub Extension Capability Model v2.1.8 — Seventh Red-Team Pass
Executive Summary

This red-team pass identifies eight distinct vulnerability classes in the current model, ranging from architectural blind spots to enforcement gaps. Three are novel findings not previously surfaced; five are refinements that tighten existing mitigations.

The most significant finding: the model's "artifact never carries authority" invariant (§14) creates a new authority channel through the very separation of compiler and broker — a compromised compiler can encode authority into which rules it emits (e.g., emitting a set-constant for bank.example vs example.com) and the broker's grant envelope only filters after the artifact is compiled. The model's defense is that the compiler cannot emit into the grant/egress namespaces, but it can emit rules targeting any host; the grant envelope intersection drops out-of-scope rules. This is correct only if the broker's grant envelope is applied at compile-time and re-verified at execution-time — which the model claims (§14) but does not specify who applies the grant envelope at compile-time. If the compiler receives the grant envelope and filters its own output, a compromised compiler can simply ignore it; if the assembler (which holds the writable descriptor) applies the grant envelope, that component is now in the trust boundary and must be hardened. This is a compositional integrity gap that needs explicit resolution.
Finding 1: The "Artifact Never Carries Authority" Invariant Creates an Authority Channel Through Rule Selection

Severity: Critical | Category: Architectural
Description

§14 states: "No consumer trusts an artifact's authority. Every consumer intersects the artifact's result with a trusted, separately-produced (extension_id, capability, granted_scope) envelope." This is the load-bearing invariant that allows the compiler to be compromised.

However, the model does not specify when this intersection occurs relative to compilation. The compiler could be a malicious actor that emits:
text

Rule A: bank.example -> set-constant('location.href', 'evil')  // OUTSIDE scope
Rule B: example.com -> set-constant('location.href', 'evil')   // INSIDE scope

If the grant envelope is applied after compilation (during artifact validation), then:

    Rule A is dropped, Rule B is retained

    The attacker's desired bank.example rule is gone — good

But the attacker can instead emit:
text

Rule C: example.com/bank -> set-constant('location.href', 'evil')

The grant envelope intersection sees example.com in scope and retains the rule. The actual effect is on bank.example via the path example.com/bank — the browser resolves example.com/bank to bank.example at request time, but the host-scope check (§3 canonical_origin) should catch this on redirect. However, if the rule targets example.com/bank and the page is bank.example with no redirect, the host-scope check passes on the initial URL example.com/bank (which is in scope) while the effective destination is bank.example (out of scope).
Model's Defense

§3 separates canonical_origin (scope identity) from classify_address_space (connection policy). The grant envelope intersection includes host-scope checking (§15). But the host-scope check is applied to the request URL, not the effective target after path resolution.
Actual Risk

The attacker can construct a rule that matches a URL whose canonical origin is in scope but whose effective host after path resolution is out of scope, by exploiting:

    Path-based host resolution (uncommon in browsers)

    Same-origin redirects that rewrite the host

    Server-side Host header override

Recommendation

Explicitly define the host-scope check at the effective target after path resolution. The artifact must be validated against a grant envelope that includes the full effective target domain, not just the matched URL. This requires the compiler to know the grant envelope at compile-time — not to filter its output, but to annotate each rule with the grant scope it was compiled against so the assembler can verify the annotation matches.
Finding 2: The Scriptlet Closure's "No Page-Derived Write" Invariant Has a Covert Channel Through Timing

Severity: High | Category: Covert Channel
Description

The scriptlet closure (§8) prohibits writing page-derived data to any location the page did not expose it to. However, the timing of a scriptlet operation can leak information even when no data is written.

Consider a scriptlet that:

    Reads a page property document.querySelector('#secret').innerHTML

    Does not write it anywhere

    But the time taken to read it depends on the length of #secret

    A co-resident content script can measure the duration of the scriptlet's injection

The model's byte-provenance rule only forbids moving page data; it does not forbid branching on page data in a timing-observable way. The model states: "no operator's extension-observable behavior may depend on page state" — but a content script observing timing is an extension-observable behavior.
Model's Defense

The model claims the closure includes "control-dependence non-interference" and that this is proven at library-build time. However, the proof obligation is stated as "per-operator audit" and the model does not specify how timing channels are measured and bounded. The scheduling capability is silent, so timing attacks are possible.
Actual Risk

A scriptlet operator abort-on-property-read('secretValue') could:

    Read window.secretValue

    Determine its length

    Sleep for length * 1ms before aborting

    No data is written, but a co-resident content script measures the duration

Recommendation

Explicitly model timing channels in the scriptlet closure. Add:

    A deterministic execution budget per scriptlet (max instructions, not just wall time)

    A requirement that any operator that reads page data must be constant-time with respect to that data

    A fuzzing-based timing-attack test suite for the library

Finding 3: The Grant Envelope's "Compartmentalized" Nature Creates a Permission Escalation Through Rule Composition

Severity: High | Category: Permission Escalation
Description

The model states (§14): "No consumer trusts an artifact's authority. Every consumer intersects the artifact's result with a trusted, separately-produced (extension_id, capability, granted_scope) envelope."

The envelope is per capability, not per rule. A compromised compiler can emit rules that individually are in scope but collectively form a new capability:

    Rule 1: example.com -> set-constant('cfg.debug', false) (in scope: scriptlet)

    Rule 2: example.com -> set-constant('cfg.telemetry', false) (in scope: scriptlet)

    Rule 3: example.com -> set-constant('cfg.redirect', 'https://evil') (in scope: scriptlet)

Individually, each rule is a valid scriptlet. Collectively, they control the page's behavior (debug mode, telemetry, redirect). The page's own code reads cfg.redirect and navigates — this is a page-mediated sink that the scriptlet closure's transitive-effect proof is supposed to catch.
Model's Defense

The transitive-effect proof (§8) is supposed to catch this: "no operator's write may cause PAGE code to produce an effect it would not otherwise." But this proof is per-operator, not per-operator-combination. Three operators that individually do not cause an effect could collectively cause one.
Actual Risk

The attacker uses three scriptlet operators:

    set-constant('cfg.debug', false) — disables debug logging

    set-constant('cfg.telemetry', false) — disables telemetry checks

    set-constant('cfg.guard', false) — disables a guard

The page code reads these three config values and, if all are false, navigates to evil. Each operator individually does not cause the page to navigate; the combination does.
Recommendation

Extend the transitive-effect proof to cover operator combinations. This is a more difficult formal verification problem but is necessary for the scriptlet closure to be sound. The library should be versioned with a model of the combined effects of its operators, not just per-operator proofs.
Finding 4: The Stats Privacy Budget's Global Pool Has a High-Bandwidth Channel Through "Budget Depletion" Observable Effects

Severity: Medium | Category: Covert Channel
Description

The model states (§7): "The budget is pooled, not per-extension — a per-extension budget is defeated by parallelization: ship 100 one-rule extensions, each targeting a different sensitive site, and each draws its own O(weeks) budget so an attacker probes 100 sites at once."

This is correct. However, the model does not specify how the pool is depleted — whether it's a continuous counter or a discrete counter. A continuous counter creates a high-bandwidth channel through the rate of depletion.
Actual Risk

An attacker can probe 100 sites by shipping 100 one-rule extensions. Each extension's stats.read depletes the pool. The attacker can observe:

    If the pool is depleted, the extension is denied

    The timing of depletion reveals which sites were visited

Even with noise, the attacker can perform a timing-based binary search over the budget to determine the exact state of the pool, which encodes the visitation pattern.
Model's Defense

The model states: "added noise with a stated leakage bound, a budget that depletes with reads." The noise is supposed to prevent precise reconstruction. However, the model does not specify the noise distribution or the leakage bound.
Recommendation

Specify the noise distribution and leakage bound. The budget depletion should be:

    Discrete (not continuous) — each read decrements by 1

    Noisy — each read returns a value with Laplace noise

    The noise should be correlated so that the attacker cannot perform a binary search over the budget

Additionally, the model should state that stats.read is rate-limited (e.g., 1 read per second) to prevent timing attacks.
Finding 5: The "Cross-Publisher Main-World Channel" Is Underspecified — Two Extensions Can Collude Through the Page DOM Without Reaching the Same Page

Severity: Medium | Category: Covert Channel
Description

The model states (§5): "The shared page realm is a browser-provided channel, and the closure treats it as one. A red-team pass showed a gap: extension A (publisher P1) holds filtering.scriptlet or content_script and writes window.__x = pageData; extension B (publisher P2) holds content_script + egress and reads window.__x and exfiltrates it."

The model's resolution: "the loud tiers on filtering.scriptlet and content_script (the dialog states page access plainly), the §8 rule that no library operator writes page-derived data anywhere at all (so the browser-supplied path contributes no writer), and store-side co-install signals for the pair itself."

However, the attacker can use cross-frame communication to collude without reaching the same page:

    Extension A reaches page news.example (in scope)

    Extension B reaches page news.example/iframe (in scope)

    Page news.example embeds news.example/iframe in a cross-origin iframe

    Extension A writes to window.top.__x (the top-level window)

    Extension B reads window.parent.__x (the parent window)

The two extensions reach different pages (news.example and news.example/iframe) but the DOM connects them through the iframe nesting.
Model's Defense

The model's "same page realm" channel covers the top-level page and its iframes. However, the two extensions in this attack reach different documents (top-level and iframe) but the DOM connects them.
Actual Risk

The model's closure treats extensions that reach the same page realm as a communicating set. But in this attack, the two extensions reach different realms (top-level and iframe) that are connected through the DOM. The model's scope is the page, not the document.
Recommendation

Extend the communicating set definition to cover frames that are connected through the DOM. The closure should consider any two extensions that reach documents connected by the DOM (top-level and iframes) as a communicating set. This is more conservative and requires the dialog to show the combined authority.
Finding 6: The "Network Egress" Policy's Per-Hop Reauthorization Has a TOCTOU at the Socket Level

Severity: Medium | Category: Enforcement Gap
Description

The model states (§15): "For extension egress, every DNS resolution and every redirect hop re-runs two checks, not one: capability_scope_allows(canonical_origin(destination)) and address_space_allows(resolved_socketaddr)."

This is correct. However, the model also states: "Sonar connect()s to the exact SocketAddr its own check resolved — it never re-resolves by hostname at socket creation, closing the DNS-rebind TOCTOU between check and connect."

The DNS-rebind TOCTOU is closed, but a different TOCTOU exists: the socket's SocketAddr is resolved at check time, but the socket's routing (which network interface it uses) can change between check and connect. A compromised system or network can route the socket through a different interface after the check.
Model's Defense

The model does not address routing-level attacks. The threat model assumes the OS is trusted for routing decisions.
Actual Risk

A malicious network can intercept the connection after the check but before the connect, by changing the routing table. This is outside the model's scope but should be noted.
Recommendation

Explicitly state the routing-level TOCTOU as a residual. The model's threat model assumes the OS is trusted; if the OS is compromised, all bets are off. This is a named residual, not a gap.
Finding 7: The "Private Browsing" Isolation Matrix Is Incomplete for Shared Storage and Cookies

Severity: Medium | Category: Isolation Gap
Description

The model states (§12): "isolated is a per-capability intersection: for each capability the private instance is denied or separately partitioned."

However, the model does not specify how cookies.write is partitioned in private browsing. The cookie scope algebra (§3) states: "a grant for cookies.read(http://localhost) must never widen to 127.0.0.1 or [::1]."

In private browsing, a cookie written in a private window must not be emitted in a regular window. This is the definition of "separately partitioned." However, the model does not specify how the cookie store is partitioned — whether it's a separate cookie jar or a per-instance prefix.
Actual Risk

If the cookie store is partitioned by prefixing the cookie domain (e.g., private-localhost), a regular-mode extension could read the private cookie if it knows the prefix. The model does not specify the partitioning mechanism.
Recommendation

Explicitly state that private-browsing cookie partition is a separate cookie jar, not a prefix. The cookie jar must be isolated at the storage level, not the domain level.
Finding 8: The "Header Modification" Byte Validation Has a Newline Injection in Multi-Header Values

Severity: Medium | Category: Enforcement Gap
Description

The model states (§15): "Every extension-supplied header value is validated against the RFC 9110 field-value character set — CR, LF, and NUL rejected — before Sonar serializes it to the wire."

This is correct. However, the model does not specify how multi-header values are handled. RFC 9110 allows multiple headers with the same field-name to be combined into a comma-separated list. An attacker could inject a newline in one header value that, when combined, creates a new header.
Actual Risk

The attacker supplies:
text

Header A: value\r\nHeader B: evil

The validation rejects the CRLF. But if the header is combined with another header of the same name:
text

Header A: value1, value2

The attacker could inject a comma that, when combined, creates a new header. The validation does not check for commas in the header value.
Model's Defense

The model's validation rejects CR, LF, and NUL. Comma is allowed. But the combination of multiple headers with the same field-name is a separate issue.
Recommendation

Explicitly specify that header values are not combined across multiple headers. Each header is sent separately, and the combination is not performed by the browser. This closes the comma-injection attack.
Summary of Findings
Finding	Severity	Category	Status
1. Artifact authority channel through rule selection	Critical	Architectural	New
2. Scriptlet timing covert channel	High	Covert Channel	New
3. Permission escalation through rule composition	High	Permission Escalation	New
4. Stats privacy budget high-bandwidth channel	Medium	Covert Channel	Refinement
5. Cross-publisher collusion through iframe DOM	Medium	Covert Channel	Refinement
6. Socket routing TOCTOU	Medium	Enforcement Gap	Residual
7. Private browsing cookie partition	Medium	Isolation Gap	Refinement
8. Header value combination injection	Medium	Enforcement Gap	Refinement
   Recommendations for v2.1.9

   Explicitly define the compiler's authority: Specify that the compiler receives the grant envelope as an input and annotates each rule with the grant scope it was compiled against. The assembler verifies the annotation matches the envelope. This prevents the compiler from filtering its own output.

   Extend scriptlet closure to cover timing channels: Add a deterministic execution budget and a requirement that operators reading page data be constant-time.

   Extend transitive-effect proof to cover operator combinations: The library should be versioned with a model of combined effects.

   Specify the stats privacy budget noise distribution: State the leakage bound and the noise distribution.

   Extend communicating set definition to cover DOM-connected frames: Treat extensions reaching top-level and iframe documents as a communicating set.

   Explicitly state socket routing as a residual: The threat model assumes the OS is trusted.

   Specify private-browsing cookie partition as a separate jar: Not a prefix.

   Explicitly specify that headers are not combined: Each header is sent separately.