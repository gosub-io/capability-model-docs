Issues Addressed (Well or Adequately)
1. Redirect-as-Observation Leak → RESOLVED

The v1 analysis flagged redirect targets encoding information via dynamic fragments or regex substitution. Section 6 now mandates static-only targets, no rule-derived components, and unobservable packaged-resource loads. Surrogate scripts further get a no-network CSP. This is a clean closure — the observation channel is eliminated at three separate points, any one of which would have sufficed. Strong.
2. Resource Limits → RESOLVED

Promoted from open question to design commitments in Section 2: compile-time budget, match-time bound (linear-time regex by construction), memory cap. The RE2-class engine commitment closes catastrophic backtracking. Malicious rulesets are rejected rather than slowly executed. Concrete enough to build against.
3. Broker Threat Model → RESOLVED

Section 16 now specifies channel-bound identity (extension never names itself), minimization (no JS runtime, no parser, no network, no DOM), and a sandboxed compiler whose output every consumer validates. The confused-deputy class is closed by construction. The compiler compromise case ("hostile artifact, not a privileged process") is exactly the right consequence.
4. Private Browsing → RESOLVED

Section 12 replaces incognito: "split" as a no-op with extension.private_browsing: denied | spanning | isolated. Isolated is preferred, grants a separate worker with memory-only storage and no cross-instance channel. The Chromium translation is corrected. This is a genuine privacy improvement over both MV2 and MV3.
5. Grant Lifecycle → RESOLVED

Section 13 defines install-time pinning, update capability diffs with re-consent on expansion, revocation as a table update with explicit semantics, and document/epoch-bound grants closing the grant-then-navigate TOCTOU. The content_script.active_tab lifetime difference from Chromium (ends at cross-document navigation, not same-origin) is documented as a compat difference. The revocation behavior — state disabled not deleted, survives updates, extension notified — covers the operational questions.
6. tabs.metadata Split → RESOLVED

The v1 registry's tabs.metadata at "standard" was under-analyzed given it's essentially a live browsing history feed. The v0.2 registry splits it into tabs.snapshot (gesture-scoped read of current tab set, source: tab_urls, standard) and tabs.events (continuous navigation events = live history, source: tab_urls, loud). OneTab gets what it needs at standard; live monitoring requires loud. Correct tiering.
7. Header Safety → RESOLVED

The v1 registry had filtering.modify_headers as standard with no constraints. Section 15 now enumerates a protected-header list — Cookie, Authorization, Host, Origin, Sec-Fetch-*, Set-Cookie, Strict-Transport-Security, Content-Length, CORS headers — that rules cannot touch. The v0.2 registry splits headers into safe-listed remove/set operations. A compromised ruleset cannot rewrite a site's security policy. The protected list is aggressive but defensible; additions are a policy decision, not an architectural change.
8. SSRF Protection → NEW, BUT SOLID

Section 15 adds per-hop destination policy re-checking for extension-initiated fetches, with address-space splits: network.fetch_public (public only), network.fetch_private_network (loud), network.fetch_loopback (gated). Sonar enforces this at the connection point. This closes the "resolve publicly, redirect to localhost" vector. Well-scoped.
The New Architecture: Baleen

Section 14 introduces Baleen as the matching core. This is the most significant new technical material and deserves separate scrutiny.
What's Good

One core, many consumers is architecturally clean. Network filtering, content-script injection, cosmetic filtering, fetch scope checks, per-site grants, and stats attribution all dispatch through the same engine with different namespaced tables. This is a real design, not a sketch.

The artifact format is position-independent, mmap-able, and sealed. On Linux, memfd_create → write → validate → F_SEAL_* → map read-only. This reuses the tile-passing infrastructure from the multi-process architecture and eliminates TOCTOU between validation and use. The validation claim — "every artifact is validated on receipt against the assumption that the compiler was compromised" — is the right posture.

The frontend/core split correctly separates ABP/uBO semantics (frontend) from the matching data structure (core). Precedence resolution in the frontend with the core returning candidate sets is how real blockers work.
Concerns

The adblock-rust dependency is both phase-0 baseline and permanent oracle. The document commits to benchmarking before writing the own core, which is prudent. But if adblock-rust performs within targets (<10 µs p99, <50 MB resident), the case for replacing it becomes weak — the own core then exists primarily as a dependency-avoidance move, and the complexity budget for a custom matching engine with ABP/uBO semantics is large. The document should state the criteria for the build-vs-embed decision explicitly, not leave it as "wait for benchmark data." What threshold justifies writing Baleen?

The "linear-time regex bucket" commitment. RE2-class engines avoid catastrophic backtracking, but the worst-case linear-time constant on large rulesets with many regexes is still significant. The compile-time budget and memory cap do bound this, but the interaction between "large rule count" and "many regex rules" should be explicitly noted as a benchmark dimension. EasyList contains relatively few regexes; user-supplied rulesets might not.

Exception tables consulted only after a hit. This is standard (brave/adblock-rust works this way), but it means exception rules can't prevent a match from being found — they can only override the verdict after the fact. For $document and $elemhide exception semantics, this is fine. For URL-level exceptions that should prevent the engine from ever seeing a request as a candidate, the distinction matters. The frontend/core split should handle this, but it's worth a design note.
The Composition Model (Section 5)

This is the most important structural change from v1, and it's largely successful.

The source × sink labeling system replaces per-capability risk assessment with derived authority computed as closure over the granted set. This is correct: a content script is dangerous in combination with a network sink, and a rule-mutation capability is dangerous in combination with readable statistics. The model captures both.

The probe-sink treatment of filtering.dynamic_rules and filtering.remote_rulesets is particularly good. Labeling rule-mutation capabilities as sinks in the composition model means the system doesn't need a special-case rule for "dynamic rules + stats.read = bad" — it falls out of the closure.

The honesty property of the derived dialog — showing "Can send the contents of pages you visit to api.grammarclone.example" rather than separately itemizing "reads inputs" and "talks to its API" — is a genuine UX improvement. The capability list is technically accurate; the derived warning is what the user needs to know.

One gap: the composition model doesn't explicitly handle temporal composition. If an extension holds content_script and later gains network.fetch_public(new_host) via an update, the derived warning should appear at update time. Section 13 covers update diffs generally, but the interaction with the composition model — "recompute derived warnings for the new effective set, show the delta" — could be stated explicitly.
Revised Registry (Section 19) — Specific Scrutiny
filtering.block(main_frame) at standard tier

The v1 registry had filtering.block as silent. v2 splits it: subresource blocking is silent, main_frame blocking is standard. This is correct. Main-frame blocking can silently redirect navigation or suppress page loads; it's an availability power that users should see at install. Good correction.
filtering.redirect(main_frame) at loud tier

Redirecting main-frame navigation is both a confidentiality and integrity risk — it can send the user to an attacker-controlled page. Loud tier with the static-target constraint is appropriate.
forms.fill mediated flow

The v1 registry had forms.autofill as standard. v2 splits into forms.detect_credentials, forms.fill, and forms.read. The fill flow is browser-mediated: browser detects field, asks extension for candidates, user picks in browser UI, secret moves via privileged channel to exact origin. Extension code never holds the filled page's inputs. This is a strong design that addresses the password-manager security problem without requiring the extension to run a content script on every page. Bitwarden's core use case fits here.
input.commands vs input.raw_keys

The v1 input.global_keys is replaced by input.commands (mediated key chords, disabled in editable fields by default, always disabled in password fields, standard) and input.raw_keys (all keystrokes, loud). Vimium needs input.commands; a keylogger needs input.raw_keys. The distinction is meaningful and honest.
page.main_world_inject bidirectional risk note

The v1 registry listed this as loud without further comment. v2 adds: "bidirectional trust risk: the page can tamper with the injected API; requires its own hardening analysis." This is an improvement, but the document still doesn't specify what that hardening analysis entails. For MetaMask, the injected window.ethereum is a high-value target; page tampering is a real attack vector. The capability should either carry a gated tier or the document should commit to a hardening standard (e.g., "main-world injectors must pass a security review of their injected surface against page-tampering threats"). As written, "loud" puts it in the same tier as content_script, which has stronger isolation guarantees.
content_handler constraints

v2 adds important restrictions: top-level navigations only, never fetch/subresources, nosniff and Content-Disposition respected, origin boundary preserved. A JSON formatter registered for application/json can't intercept a fetch response or bypass X-Content-Type-Options: nosniff. These constraints make the capability narrow enough to be standard-tier. Good additions.
network.proxy_control persistent indicator

v2 adds "persistent indicator" to the gated tier. This aligns with the attribution principle in Section 17. Correct for a capability that reroutes all traffic.
Remaining Issues
1. page.main_world_inject Tiering

As noted above, this is at loud tier with a risk note but no hardening standard. Main-world injection is fundamentally different from content scripts: the page can intercept, modify, or replace the injected API. This is an inherent property, not a bug. The capability should either be gated (requiring developer-mode or explicit settings toggle) or the document should specify the hardening review that loud-tier injectors must pass. MetaMask is irreducibly powerful and will need this capability, but the tier should reflect the trust model.
2. Procedural DSL Operator Set (Open Question O3)

Section 8 bounds procedural filters as a "closed DSL" with a fixed, non-Turing operator set implemented natively. The open question acknowledges the operator set isn't determined. This is a genuine dependency: if the operator set is too small, uBO compatibility suffers; if it's too large, the native implementation surface is significant. The document should state the criteria: "include all operators that are both commonly used in major filter lists and have straightforward native implementations; defer operators requiring full DOM traversal or layout awareness to the content-script path."
3. stats.read Privacy Budget (Open Question O5)

The document commits to quantization, time windows, and decorrelation but defers the parameters. This is an empirical question, but the risk is that "we'll tune it later" becomes "the parameters are too coarse for useful statistics or too fine for privacy." A concrete proposal: "initial parameters set such that a targeted single-site probe rule requires O(weeks) to distinguish a single visit from noise, with parameters published and reviewable." Even if the numbers change, committing to the criterion makes the design testable.
4. Privacy Badger Incompatibility

v2 states the incompatibility explicitly: "Gosub does not support heuristic tracker learning at any silent or standard tier." This is the right honesty. However, the document should also state what Privacy Badger can do on Gosub: it can ship with a pre-trained blocklist (like Disconnect's list, which it already uses as a seed), it can display the badge via stats.display, and it can update its list via remote_rulesets. The learning mode requires loud observation. This isn't a criticism of the architecture — it's clarifying what the trade means in practice for a real extension.
5. Baleen Build-vs-Embed Criteria

As noted above, the document should state the thresholds that would justify writing the own core. Suggested: "If adblock-rust meets the <10 µs p99, <50 MB resident targets, and supports the required ABP/uBO operator set with acceptable compile times for standard filter lists, the own core is deferred. If it misses any target by >20% and profiling indicates the gap is intrinsic to the design rather than optimizable, the own core proceeds."
6. Temporal Composition in Update Diffs

Section 13 covers update diffs but doesn't explicitly mention recomputing derived composition warnings. The interaction is: if an extension gains network.fetch_public(new_host) in an update, and it already holds content_script, the derived "can send page contents to new_host" warning must appear in the update dialog. This likely falls out of "recompute the dialog for the new effective set," but stating it explicitly would close the gap.
7. content_handler and Service Workers

content_handler applies to top-level navigations. But what about navigations intercepted by a service worker? If a service worker returns a synthetic application/json response, does the content handler fire? The document should either specify that content handlers only apply to network-origin responses, or acknowledge the interaction.
Summary

v2 is a substantial improvement over v1. The eight structural issues from the first review are all addressed: redirect observation is closed at three points, resource limits are design commitments, the broker has a threat model, private browsing has a real design, grant lifecycle is defined, tabs.metadata is correctly split, headers are safe-listed, and SSRF is prevented.

The new material — Baleen architecture, composition model, revised registry — is well-scoped and concrete. The composition model is the right abstraction for the security analysis the document wants to perform. The registry tiering corrections (main-frame control, input.commands, forms.split, address-space fetches) show real engagement with the capability distinctions.

The remaining issues are tuning problems, not architectural flaws: main-world injection tiering, build-vs-embed criteria, procedural operator set scope, and privacy-budget parameterization. None of them threaten the core thesis.

The document has progressed from a design sketch to an implementable specification. The one-sentence test: could a team start building the broker, Baleen, and the translation layer from this document and make consistent security decisions? For v2, the answer is yes.
can we do a red-team analysis?
Red-Team Analysis: Gosub Extension Capability Model v2

I'll approach this as an adversary trying to break the model — either to exfiltrate user data, escalate privilege, or degrade browser integrity. I'll assume the attacker controls either (a) a malicious extension granted some capabilities, or (b) a compromised filter-list server, or (c) a compromised-but-capability-limited extension worker. The question in every case: what can they reach that the model says they can't?
Attack Surface 1: The Statistics Oracle
Target

Reconstruct browsing history from stats.read despite quantization, time windows, and decorrelation.
Attack: Frequency-Domain Probing

The model decorrelates reads from ruleset changes within a time window. But what if the extension doesn't change rules — it ships with 10,000 pre-registered rules, each matching exactly one domain of interest?
text

Rule 0001: ||alice-target.example^
Rule 0002: ||bob-target.example^
...
Rule 10000: ||zebra-target.example^

All rules are installed at install time. No dynamic rules, no remote rulesets. The extension holds stats.read (standard) without any probe sink. Quantization rounds counts; time windows batch updates.

The attack: Each quantization bucket reports "approximately N blocks." If the bucket size is, say, 50, and the extension ships 10,000 single-domain rules, a user visiting 30 tracked sites produces a bucket that rounds to 50. Visiting 80 produces rounding to 100. Over days, the accumulated deltas disambiguate: on Tuesday the count jumped by ~50; only three rules in the set could have contributed based on the user's timezone and typical browsing hours; correlation with known site popularity distributions narrows it further.

Why this might work despite decorrelation: The decorrelation constraint is that reads aren't orderable against the extension's own ruleset changes. But if the ruleset never changes, all reads are orderable against each other. The attacker observes the time series of aggregate counts and performs traffic analysis — the same techniques that deanonymize Tor users from flow metadata.

Countermeasure analysis: The model says stats.read provides "aggregates only" with "minimum aggregation no value scoped narrower than all-sites/all-rules." If this means one global counter per extension, updated on a coarse schedule, with no breakdown by rule, site, or time window smaller than hours, the attack fails — 10,000 single-site rules all increment the same counter. The attacker learns that someone somewhere triggered a rule, not which one. But the document's quantization language ("counts rounded; small deltas indistinguishable") implies per-rule or at least per-bucket counters exist, just rounded. The attack exploits the gap between "rounded" and "truly aggregated."

Recommendation: Specify that stats.read returns exactly one counter: total blocks across all rules across all sites, with no dimensionality. No per-rule, no per-site, no per-hour breakdown. Anything with more dimensions is stats.per_rule (loud). Alternatively, if per-rule counters exist internally (e.g., for list maintainer diagnostics), they must be in a separate namespace that no standard-tier extension can read, even rounded.
Attack Surface 2: The Timing Side Channel
Target

Infer blocked-vs-allowed request outcomes from timing, even without statistics capabilities.
Attack: Request-Initiated Timing Probe

The attacker holds filtering.block (silent), content_script on *.evil.example (loud, but granted), and network.fetch_public(api.evil.example) (standard). The extension wants to know if the user visited target-site.example.

Step 1: The content script on evil.example runs a loop:
javascript

const img = new Image();
const start = performance.now();
img.src = 'https://target-site.example/probe-' + Math.random();
img.onerror = () => {
const elapsed = performance.now() - start;
// Report elapsed to api.evil.example
};

Step 2: If Gosub blocks the request to target-site.example at the filter engine (before DNS), onerror fires quickly — no network round trip. If the filter engine allows it and DNS resolves, onerror takes longer (DNS + TCP + TLS + response). If the filter engine allows it and the remote server is up, timing differs further.

Step 3: The attacker trains a classifier on known-blocked vs known-allowed timing distributions from their own test browser and applies it to user timings.

Why this might work: The filter engine's verdict is a branch; branches have timing signatures. A block that returns immediately is distinguishable from an allow that initiates a network connection. The model assumes control primitives don't leak observation, but timing is a channel the model doesn't address.

Countermeasure analysis: The attack requires the attacker to control a page the user visits (evil.example) and to make requests to the target domain. The filtering.block capability doesn't prevent the extension from making its own requests to target domains — those requests originate from the extension's content script, not the page. The filter engine might or might not apply extension rules to extension-initiated requests.

Recommendation:

    Specify that extension content-script-initiated requests to third parties are either (a) always blocked in the filter engine regardless of rules, or (b) padded to constant time — all blocked requests incur a fixed synthetic delay matching typical DNS+TCP time. Option (b) is fragile; option (a) is simpler and aligns with the principle that content scripts shouldn't probe.

    Add a note that timing channels from filter-engine verdicts to same-extension content scripts are a recognized residual risk, and mitigation is constant-time behavior in the network stack where practical.

Attack Surface 3: The Procedural DSL Boundary
Target

Escape the closed-DSL constraint and execute arbitrary logic through procedural cosmetic filters.
Attack: Operator Composition as a Turing Tarpit

The procedural DSL is bounded as "fixed, non-Turing, cost-bounded." But composable operators on the DOM can achieve surprising expressiveness even without explicit loops.

Consider if the operator set includes:

    :has() — check descendant

    :has-text() — regex match on text content

    :upward() — walk ancestors

    :nth-ancestor() — parameterized walk

    :matches-css() — read computed style

    :xpath() — evaluate XPath expression (some ad blockers support this)

With :xpath(), Turing-completeness is immediate — XPath 1.0 is not Turing-complete, but XPath with arbitrary functions can simulate a counter machine. Even without :xpath(), :has() + :upward() + :has-text() lets the filter express "find a node whose ancestor N levels up has text matching pattern P, then check if its sibling matches pattern Q" — a constrained but real computation over the DOM tree.

The real attack isn't achieving Turing completeness — it's exfiltration. The procedural filter selects an element and hides it. But selection itself is information: does element X exist on the page? The stats.display counter increments when a cosmetic rule matches, and while extension code doesn't read the counter directly, it might be rendered on the badge. If the attacker can craft rules whose match or non-match changes visible browser state, they have a binary channel.

Attack sketch:
text

Rule: example.com##div:has-text("secret-token-") .indicator

If secret-token- appears on the page, .indicator is hidden. The extension's content script on the same page polls for .indicator visibility. One bit per rule, many rules = arbitrary data exfiltration from the page to the extension.

Why this might work: The cosmetic filter engine runs in the renderer, modifying the DOM. The extension's content script on the same page can observe DOM mutations. The model treats these as separate capabilities, but on the same page they compose into a channel.

Countermeasure analysis: This requires the extension to hold both filtering.cosmetic/filtering.procedural (silent) and content_script on the target domain (loud). The composition model should flag this pair — but currently it doesn't, because cosmetic filtering has source: none and content scripts have source: page_content. The channel is: cosmetic rule selection → DOM mutation → content script observation. The source label on cosmetic filtering is wrong if the content script can observe its effects.

Recommendation:

    Add a composition note: filtering.cosmetic + content_script on the same origin creates a DOM-mutation channel. Either (a) cosmetic mutations are unobservable to content scripts on the same page (the renderer applies them in a way invisible to JS observers, e.g., post-layout compositor-level hiding), or (b) the pair triggers a derived warning.

    For option (a): specify that cosmetic hiding operates at the compositor level (display: none injected via a mechanism that MutationObserver cannot see). This is technically challenging but definitional for the channel.

Attack Surface 4: The Compiler Compromise
Target

Escape the sandboxed compiler and achieve code execution in a privileged process.
Attack: Artifact Validation Bypass

Section 16 specifies a sandboxed, unprivileged compiler producing a sealed artifact. Consumers validate the artifact. The threat model acknowledges that a compromised compiler yields a hostile artifact, not a privileged process.

The question: What is the validation surface, and can it be attacked?

The artifact is described as "flat, offset-based, position-independent, mmap-able read-only." Validation means "bounds-checked offsets, verified table integrity." If the Baleen artifact contains:

    Offset tables pointing into string pools

    Trie structures with child pointers

    Regex compiled forms

    Exception tables

Then validation must verify every offset, every pointer, every size field before the consumer uses them. A single missed bounds check on a string-pool offset gives the compromised compiler control over what bytes the consumer reads, and potentially interprets as a length or jump target.

Attack sketch: The compromised compiler produces a structurally valid artifact header with one offset that points past the validated region but within the mmap'd pages (which might include adjacent kernel or allocator metadata on some platforms). The consumer validates the header structure, sees offsets within the file size, and accepts the artifact. At match time, the consumer follows the offset, reads uncontrolled bytes, and uses them as a table index or length, causing an out-of-bounds read or control-flow diversion.

Why this might work: The "validate on receipt" step occurs once; the "use at match time" occurs per request. If validation and use disagree on what constitutes a valid offset — e.g., validation checks offset < file_size but use interprets offset as an index into a sub-table with a different bound — the gap is exploitable.

Countermeasure analysis: The document says "never mmap-cast the blob into structs." This helps but doesn't prevent logic errors in the validation code. The consumer is the network process (Sonar); a compromised artifact that triggers an out-of-bounds read in Sonar is reading network-process memory, which contains request data for all tabs.

Recommendation:

    The artifact format should be self-describing with a single validation pass that produces a "safe handle" — a validated, bound-checked wrapper that all consumer code uses, with no raw offset arithmetic after validation.

    The validation code itself should be small enough for manual audit, with a statement of line count and cyclomatic complexity budget.

    Consider a second validation pass at match time (or sampled validation) as a defense-in-depth measure — "validate at install, re-validate checksums at use."

    The compiler sandbox should be a separate process with no network access, no filesystem access beyond its input/output pipes, and a strict seccomp filter — this is implied by "sandboxed, unprivileged" but should be explicit.

Attack Surface 5: The Redirect Target Race
Target

Serve attacker-controlled content despite static redirect targets.
Attack: Resource Substitution at Update

The model says redirect targets are static, enumerated in web_accessible_resources. The extension package is signed and verified at install. But extensions update.

Attack: The attacker publishes an extension with legitimate surrogates. It gains a user base and good reputation. After six months, they push an update where the package's web_accessible_resources replaces google-analytics_ga.js (a benign stub) with a payload that exfiltrates document.cookie from the page where it's injected. The surrogate still satisfies the page's API expectations (it provides the ga function), so no breakage. The extension's filtering.redirect capability still targets only declared packaged resources. The package is signed by the same developer key.

Why this works: The redirect constraint is structural (target must be in the package), not behavioral (target must be harmless). The model explicitly separates these: script surrogates "execute under a no-network CSP" — but document.cookie exfiltration doesn't require network. The surrogate can write to localStorage, postMessage to a same-origin iframe, or modify the DOM to include an image with the cookie in the URL (the CSP blocks the image load, but the URL construction itself might be observable via other means, or the cookie is embedded in DOM state that a cooperating content script reads).

Is this actually mitigated? Section 6 says surrogates execute under a no-network CSP: "they may satisfy the page's API expectations but may not initiate requests." This prevents fetch(), XMLHttpRequest, navigator.sendBeacon, <img> loads, etc. But it doesn't prevent:

    Writing to localStorage (which a cooperating first-party script on the same origin can read)

    postMessage to * (which a cooperating frame can receive)

    Modifying the DOM in ways observable to content scripts

    Side-channel exfiltration via SharedArrayBuffer timing

Countermeasure analysis: The no-network CSP prevents the most direct exfiltration but leaves DOM-local channels open. If the extension also holds content_script on the same origin (which uBO does for its element picker), the surrogate can communicate with the content script through DOM mutations, and the content script can exfiltrate via network.fetch_public.

Recommendation:

    Surrogates should execute in an isolated JavaScript realm with no access to the page's localStorage, sessionStorage, postMessage to page origins, or SharedArrayBuffer.

    The surrogate's realm should be perceptible to the page (it can call the ga function) but unable to mutate page-observable state beyond the surrogate API surface.

    At minimum, the composition of filtering.redirect (with script surrogates) + content_script on the same origin should trigger a derived warning: the combination can exfiltrate data from surrogate-injected pages.

    Alternatively: script surrogates require a separate, louder capability than resource surrogates (image/empty redirects). The v0.2 registry doesn't distinguish them; it should.

Attack Surface 6: The Remote Ruleset Server
Target

Serve per-user targeted rules through a compromised or coerced filter-list server.
Attack: User-Specific Rule Delivery

Section 9 says remote rulesets are browser-fetched with no extension cookies or headers. The browser fetches https://easylist.example/easylist.txt on a jittered schedule. The server sees the client IP and User-Agent.

Attack: The list server receives a request from IP 203.0.113.42 with Gosub's User-Agent. It serves the standard EasyList to everyone — except IPs matching a target list, which receive a modified EasyList that includes:
text

||target-user-only-tracker.example^$redirect=malicious-surrogate

The malicious surrogate is not in any extension's web_accessible_resources. Under Section 6, redirect targets must be static and packaged — so this rule would fail validation. But the attacker isn't trying to redirect; they're trying to detect whether the rule compiles or is rejected, or whether the rule's presence changes the filter engine's behavior in a way the extension can observe (e.g., via the timing channel of Attack Surface 2, or via stats.display if the badge count changes).

More subtly: The modified list could include rules that are valid but probe-specific:
text

||unique-probe-{target-uuid}.example^

If the extension holds stats.per_rule (loud) or stats.read with per-rule granularity (which the model should prevent but might not), the list server learns that the target user fetched the list — when the extension reports back to its own server (via network.fetch_public), the statistics include a hit on the unique probe rule.

Why this might work: The browser-fetching model prevents the extension from personalizing the request, but the server can still personalize the response. If the extension later reports statistics to its own backend, the probe rule bridges the gap.

Countermeasure analysis: The document partly addresses this with "optional: publisher signatures / content hashes." If the browser verifies that the fetched list matches a published hash (which is the same for all users), the server cannot serve per-user lists without detection. But the hash must be obtained out-of-band (e.g., in the extension package at install time), otherwise the server can serve a matching hash for the personalized list.

Recommendation:

    Make content hashes or signatures a requirement, not optional: remote rulesets declared in the manifest must specify a hash or signature, and the browser must reject lists that don't match.

    The hash should be embedded in the extension package, not fetched from the same server.

    Alternatively, require remote rulesets to be fetched through a browser-managed transparency mechanism (like Certificate Transparency but for filter lists) where the same list is served to all users and the browser can verify inclusion.

    At minimum, document that per-user targeting via list servers is a recognized threat, and the signature mechanism is the mitigation — not optional.

Attack Surface 7: The Broker's IPC Surface
Target

Exploit a parsing vulnerability in the broker to escalate from extension worker to broker privilege.
Attack: Malformed IPC Messages

Section 16 describes the broker as doing "deserialize small, typed IPC." This is the universal attack surface of capability-based systems. The broker is the only path from extension code to privileged operations; every message the broker accepts is a potential vulnerability.

Attack classes:

    Type confusion: A message that claims to be one type but contains data for another, exploiting union deserialization

    Length overflow: A size field that wraps around, causing a small allocation and large copy

    Capability forgery: A message that references a capability index the extension doesn't hold, exploiting a TOCTOU or confusion in the capability table

    State-machine confusion: A message sent in a state where it shouldn't be valid (e.g., a "fill credential" message when no credential request is pending)

Why this might work: The broker is specified as "boring" — deserialize, check channel, check capability, forward. This simplicity is a security virtue, but it means every branch in the deserializer and capability checker is a potential vulnerability. The document doesn't specify the serialization format, the capability representation, or the message schema.

Countermeasure analysis: The document doesn't need to specify these at the design level, but it should state the security requirements for the implementation.

Recommendation:

    Add a broker security requirement: the broker's message parser must be generated from a schema, not hand-written, with formally verified bounds checking.

    The broker's IPC protocol must be a fixed set of request-response pairs with no streaming or partial messages.

    Capability indices must be unforgeable — either kernel-mediated (Unix file descriptors passed via SCM_RIGHTS) or cryptographically randomized per-connection.

    The broker should be the subject of a dedicated security review and fuzzing campaign, acknowledged in the document as an implementation requirement.

Attack Surface 8: The private_browsing:isolated Boundary
Target

Correlate private and regular browsing despite isolation.
Attack: Time-Based Correlation

Section 12 specifies isolated as separate worker instances with memory-only storage and no channel between instances. But time is a channel.

Attack: The extension in the regular instance writes to storage.private at time T1: "user triggered action X." The extension in the private instance also holds storage.private (separate, memory-only) and network.fetch_public(api.example). Both instances have access to wall-clock time.

If the regular instance and private instance can agree on a time-based protocol — e.g., "at minute M, if condition C holds, make a request to api.example/beacon-M" — the server at api.example can correlate requests from the same client IP at the same minute. The private instance's request reveals private-browsing behavior, and the server correlates it with the regular instance's profile via IP + time window.

Why this might work: IP address is shared between instances (same machine). Wall-clock time is available to both. network.fetch_public is available to both. The only missing piece is a shared secret for coordination — but the coordination can be pre-arranged in the extension package: "at install time + random(0, 24h), start protocol; every 10 minutes, send aggregate."

Countermeasure analysis: This is an inherent limitation of any same-machine isolation without network-layer separation. The model can't prevent it without denying network.fetch_public to the private instance, which breaks legitimate private-browsing use cases.

Recommendation:

    Acknowledge the time+IP correlation channel as a residual risk in the isolated mode.

    Consider a stricter isolated_network mode where the private instance has no network access at all — network.fetch_public is denied. Legitimate private-browsing extensions (password managers that work offline) can use it; extensions that phone home in private mode need isolated with the acknowledged risk.

    For isolated mode, recommend that the private instance's network requests be proxied through a browser-managed anonymization layer (e.g., a fixed-delay batch proxy) to decorrelate timing — but this is likely out of scope for an initial release.

Attack Surface 9: The Document Identity TOCTOU
Target

Exploit a race between document identity validation and operation execution.
Attack: Navigate After Check

Section 13 specifies grants bind to (tab_id, frame_id, document_id, navigation_epoch, origin) and are "revalidated at the final privileged operation." This is the right design. But "revalidated at the final privileged operation" implies a check-then-use pattern if there are multiple steps.

Attack: The content script requests forms.fill on bank.example. The broker validates the document identity, then sends the fill request to the renderer. Between validation and fill, the page navigates to evil.example via location.href = 'https://evil.example'. If the fill operation completes on the new document, the credentials are injected into the wrong origin.

Why this might work: The broker validates, forwards to the renderer, the renderer executes. The validation-to-execution gap exists if these are separate IPC messages.

Countermeasure analysis: Section 13 says "revalidated at the final privileged operation." If the renderer re-checks the document identity at the moment of fill (comparing against the identity in the fill request), the attack fails — the document changed, the identities don't match, the fill aborts.

Recommendation:

    Specify that the document identity in the fill request is opaque to the broker and validated by the renderer at execution time against the current document — not just the broker validating and then forwarding.

    The same principle should apply to all document-bound operations: the final execution point (renderer) validates identity, not just the intermediary (broker).

    This is likely the intent of "revalidated at the final privileged operation" but should be made explicit: the renderer holds the ground truth for document identity.

Attack Surface 10: The forms.fill Mediated Flow
Target

Extract credentials from the browser-mediated fill flow.
Attack: Credential Confusion

Section 19 specifies: browser detects field, asks extension for candidates, user picks in browser UI, secret moves via privileged channel to exact origin. The extension never holds the filled page's inputs.

Attack: The browser detects a credential field on bank.example. It asks the extension for candidates. The extension returns a candidate. The user picks it. The secret moves to the field. But the extension can influence the candidate list. If the extension returns candidates for evil.example in response to a bank.example query, and the browser doesn't re-validate that the returned credentials match the origin, the user might pick the wrong credential.

More subtly: The extension controls the labeling of candidates. It can return:
json

{
"origin": "bank.example",
"username": "user@bank.example",
"display": "Bank of America — user@bank.example"
}

but the actual origin of the credential is evil.example. If the browser trusts the origin field from the extension, the credential is filled on bank.example but originated from evil.example — the extension just exfiltrated a credential across origins under the guise of autofill.

Why this might work: The browser-mediated flow puts the browser in control of the UI and the secret channel, but the extension still controls the candidate data. If the browser doesn't cryptographically bind credentials to origins in storage, the extension can lie.

Countermeasure analysis: The document says the secret moves "via privileged channel to exact origin." This implies the browser verifies the origin. But the specification of storage.private is silent on whether the browser can enforce origin binding on stored credentials.

Recommendation:

    Specify that forms.fill must use browser-managed credential storage with origin binding, not extension-managed storage.private. The extension registers credentials with the browser's credential store (similar to the Credential Management API), and the browser enforces origin matching.

    The extension's role is to supply credential candidates to the browser's store, not to answer fill queries directly.

    If the extension uses its own storage.private for credentials, the browser cannot enforce origin binding, and the capability should be loud with an explicit warning that the extension manages its own credential security.

Attack Surface 11: Composition Not Captured

The composition model (§5) identifies page_content × sink → exfiltration. But several dangerous compositions aren't labeled:
Missing Pair: filtering.cosmetic + content_script (same origin)

Covered in Attack Surface 3. DOM mutation by the cosmetic engine is observable by content scripts. Source label on cosmetic filtering should be reconsidered.
Missing Pair: filtering.redirect (script surrogate) + content_script (same origin)

Covered in Attack Surface 5. The surrogate can write to page-local storage; the content script can read it and exfiltrate.
Missing Pair: filtering.dynamic_rules + content_script (same origin)

The content script observes page behavior. Based on what it sees, it installs dynamic rules targeting other sites. Those rules affect other tabs. The content script has no direct observation of those other tabs, but it can probe — install a rule, wait for the aggregate counter to change (via timing of the badge update, even if it can't read the counter), and infer. This is slow but real.
Missing Pair: tabs.snapshot + network.fetch_public

tabs.snapshot is gesture-scoped and standard. But if the extension can trigger tabs.snapshot at will (the gesture is "user clicked the toolbar icon, which the extension can prompt"), and immediately send the result to api.example, it's a "dump all open tabs on demand" button. The gesture scoping means it's not continuous, but it's still a bulk history dump each time the user interacts with the extension.

Recommendation: Extend the composition labels. The missing pairs above are real channels. They should either be mitigated (e.g., cosmetic mutations unobservable) or flagged in derived warnings.
Summary of Findings
#	Attack Surface	Severity	Mitigation Status
1	Statistics oracle via frequency-domain probing	High	Needs stricter stats.read spec (single counter only)
2	Timing side channel from filter verdicts	Medium	Needs constant-time or request-padding commitment
3	Procedural DSL → DOM mutation → content script observation	High	Missing composition label; needs compositor-level hiding or derived warning
4	Compiler compromise → artifact validation bypass	Critical	Acknowledged; needs validation-code audit budget and double-validation
5	Surrogate update substitution → local exfiltration	High	No-network CSP prevents network exfil; DOM-local channels remain; missing composition label
6	Remote ruleset server per-user targeting	High	Needs mandatory content hashes/signatures
7	Broker IPC parsing vulnerabilities	Critical	Standard attack surface; needs schema-generated parser + fuzzing commitment
8	private_browsing isolated time+IP correlation	Medium	Acknowledged limitation; consider isolated_network mode
9	Document identity TOCTOU on fill	High	Design intent correct; needs explicit renderer-side revalidation
10	Credential origin confusion in mediated fill	Critical	Needs browser-managed credential store with origin binding
11	Missing composition labels	Medium	Extend the label system for cosmetic, surrogate, dynamic-rules channels
Overall Assessment

The model is well-designed and has closed the obvious first-order attacks. The red-team findings cluster in three areas:

    Side channels that the composition model misses — DOM mutation observation, surrogate-contentScript channels, dynamic-rules probing. The composition model is the right tool for catching these; it just needs to be applied more broadly.

    Implementation-critical security properties that are stated but not committed — content hashes for remote rulesets, schema-generated broker parsers, renderer-side document revalidation, browser-managed credential storage. These are all consistent with the model's intent but need to be design commitments, not implementation notes.

    Timing and statistical channels — the model's aggregation and decorrelation are necessary but not sufficient against a patient adversary with many probes. The mitigations (single-counter statistics, constant-time filter verdicts) are specific and implementable.

None of these findings invalidate the architecture. They're the difference between a model that's correct in its stated properties and one that's correct in its actual security boundary. The model is at the "stated properties" stage; the red-team findings point to where the boundary needs hardening to match the intent.
This response is AI-generated, for reference only.