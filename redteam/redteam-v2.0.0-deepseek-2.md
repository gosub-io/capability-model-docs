# Red-Team Analysis: Gosub Extension Capability Model v2

**Target Document:** Gosub Extension Capability Model v2.0 — August 2026  
**Analyst Stance:** Adversary controlling either (a) a malicious extension granted some capabilities, (b) a compromised filter-list server, or (c) a compromised-but-capability-limited extension worker.  
**Objective:** Exfiltrate user data, escalate privilege, or degrade browser integrity beyond what the model permits.

---

## Attack Surface 1: The Statistics Oracle

**Target:** Reconstruct browsing history from `stats.read` despite quantization, time windows, and decorrelation.

### Attack: Frequency-Domain Probing

The model decorrelates reads from ruleset changes within a time window. The attacker ships 10,000 pre-registered rules, each matching exactly one domain of interest:

Rule 0001: ||alice-target.example^
Rule 0002: ||bob-target.example^
...
Rule 10000: ||zebra-target.example^
text


All rules installed at install time. No dynamic rules, no remote rulesets. The extension holds `stats.read` (standard) without any probe sink.

**The attack:** Each quantization bucket reports "approximately N blocks." If the bucket size is 50, and the extension ships 10,000 single-domain rules, a user visiting 30 tracked sites produces a bucket that rounds to 50. Visiting 80 produces rounding to 100. Over days, accumulated deltas disambiguate: on Tuesday the count jumped by ~50; only three rules in the set could have contributed based on timezone and typical browsing hours; correlation with known site popularity distributions narrows it further.

**Why this works despite decorrelation:** The decorrelation constraint is that reads aren't orderable against the extension's own *ruleset changes*. If the ruleset never changes, all reads are orderable against each other. The attacker performs traffic analysis on the time series of aggregate counts.

**Severity:** High

**Recommendation:** Specify that `stats.read` returns *exactly one* counter: total blocks across all rules across all sites, with no dimensionality. No per-rule, no per-site, no per-hour breakdown. Anything with more dimensions is `stats.per_rule` (loud). If per-rule counters exist internally for diagnostics, they must be in a separate namespace that no standard-tier extension can read, even rounded.

---

## Attack Surface 2: The Timing Side Channel

**Target:** Infer blocked-vs-allowed request outcomes from timing, even without statistics capabilities.

### Attack: Request-Initiated Timing Probe

The attacker holds `filtering.block` (silent), `content_script` on `*.evil.example` (loud, but granted), and `network.fetch_public(api.evil.example)` (standard).

**Step 1:** The content script on `evil.example` runs:

```javascript
const img = new Image();
const start = performance.now();
img.src = 'https://target-site.example/probe-' + Math.random();
img.onerror = () => {
    const elapsed = performance.now() - start;
    // Report elapsed to api.evil.example
};

Step 2: If Gosub blocks the request at the filter engine (before DNS), onerror fires quickly. If allowed and DNS resolves, onerror takes longer. A classifier trained on known-blocked vs known-allowed timing distributions disambiguates.

Why this works: The filter engine's verdict is a branch; branches have timing signatures. The model doesn't address timing channels from filter-engine verdicts to same-extension content scripts.

Severity: Medium

Recommendation:

    Specify that extension content-script-initiated requests to third parties are always subject to filter-engine policy regardless of initiator, or padded to constant time.

    Add a note that timing channels from filter-engine verdicts to same-extension content scripts are a recognized residual risk, with constant-time behavior in the network stack as the mitigation.

Attack Surface 3: The Procedural DSL Boundary

Target: Escape the closed-DSL constraint and execute arbitrary logic through procedural cosmetic filters, or exfiltrate data via DOM-mutation observation.
Attack: Cosmetic Filter → Content Script Channel

If the procedural operator set includes :has(), :has-text(), :upward(), :matches-css(), and potentially :xpath(), the filter can select elements based on page content.

Attack sketch:
text

Rule: example.com##div:has-text("secret-token-") .indicator

If secret-token- appears on the page, .indicator is hidden. The extension's content script on the same page polls for .indicator visibility. One bit per rule, many rules = arbitrary data exfiltration from page to extension.

Why this works: The cosmetic filter engine runs in the renderer, modifying the DOM. The extension's content script on the same page can observe DOM mutations. The model treats these as separate capabilities (filtering.cosmetic source: none, content_script source: page_content), but on the same page they compose into a channel.

Severity: High

Recommendation:

    Add a composition label: filtering.cosmetic + content_script on the same origin creates a DOM-mutation channel.

    Specify that cosmetic hiding operates at the compositor level (post-layout, invisible to MutationObserver) or flag the pair in derived warnings.

    The procedural operator set should be explicitly enumerated and audited for expressiveness that enables probing.

Attack Surface 4: The Compiler Compromise

Target: Escape the sandboxed compiler and achieve code execution in a privileged process via artifact validation bypass.
Attack: Artifact Validation Bypass

Section 16 specifies a sandboxed, unprivileged compiler producing a sealed artifact. Consumers validate the artifact on receipt.

Attack sketch: The compromised compiler produces a structurally valid artifact header with one offset that points past the validated region but within the mmap'd pages (potentially containing adjacent kernel or allocator metadata). The consumer validates the header, sees offsets within file size, and accepts. At match time, the consumer follows the offset, reads uncontrolled bytes, and uses them as a table index or length — out-of-bounds read or control-flow diversion.

Why this works: Validation occurs once at install; use occurs per request. If validation and use disagree on offset bounds (e.g., validation checks offset < file_size but use interprets offset relative to a sub-table), the gap is exploitable.

Severity: Critical

Recommendation:

    The artifact format must be self-describing with a single validation pass producing a "safe handle" — bound-checked wrappers for all consumer code, with no raw offset arithmetic after validation.

    The validation code should be small enough for manual audit; specify line-count and cyclomatic-complexity budgets.

    Defense-in-depth: re-validate checksums at match time or perform sampled re-validation.

    The compiler sandbox must be a separate process with no network, no filesystem beyond pipes, and a strict seccomp filter — state this explicitly.

Attack Surface 5: The Redirect Target Race

Target: Serve attacker-controlled content despite static redirect targets.
Attack: Resource Substitution at Update

Attack: An extension publishes with legitimate surrogates. It gains reputation. After six months, an update replaces google-analytics_ga.js with a payload that reads document.cookie. The surrogate still satisfies the page's API expectations. The redirect target is still in web_accessible_resources. The package is signed by the same developer key.

Why this works: The redirect constraint is structural (target must be in the package), not behavioral. Section 6's no-network CSP prevents fetch() and XMLHttpRequest, but not:

    Writing to localStorage (a cooperating first-party script can read)

    postMessage to * (a cooperating frame can receive)

    DOM mutations observable by content scripts

    Side-channel exfiltration via SharedArrayBuffer timing

If the extension also holds content_script on the same origin, the surrogate can communicate with the content script through DOM mutations, and the content script can exfiltrate.

Severity: High

Recommendation:

    Surrogates should execute in an isolated JavaScript realm with no access to page localStorage, sessionStorage, or postMessage to page origins.

    The composition of filtering.redirect (script surrogates) + content_script on the same origin must trigger a derived warning.

    Consider splitting filtering.redirect into filtering.redirect_resource (images, empty responses — silent) and filtering.redirect_surrogate (scripts — loud).

Attack Surface 6: The Remote Ruleset Server

Target: Serve per-user targeted rules through a compromised or coerced filter-list server.
Attack: User-Specific Rule Delivery

Section 9 says remote rulesets are browser-fetched with no extension cookies or headers. The browser fetches on a jittered schedule. The server sees client IP and User-Agent.

Attack: The list server serves standard EasyList to everyone — except IPs matching a target list, which receive a modified list with probe rules:
text

||unique-probe-{target-uuid}.example^

If the extension later reports statistics to its own backend (via network.fetch_public), the probe rule bridges the gap: the server knows which user fetched the targeted list.

Why this works: The browser-fetching model prevents the extension from personalizing the request, but the server can still personalize the response. The optional "publisher signatures / content hashes" is not yet a requirement.

Severity: High

Recommendation:

    Make content hashes or signatures a requirement, not optional. The hash must be embedded in the extension package at install time, not fetched from the same server.

    Reject lists that don't match the declared hash.

    Alternatively: require remote rulesets through a browser-managed transparency mechanism where the same list is served to all users and the browser verifies inclusion.

    Document that per-user targeting via list servers is a recognized threat, and the signature mechanism is the mitigation.

Attack Surface 7: The Broker's IPC Surface

Target: Exploit a parsing vulnerability in the broker to escalate from extension worker to broker privilege.
Attack: Malformed IPC Messages

Section 16 describes the broker as doing "deserialize small, typed IPC." Every message the broker accepts is a potential vulnerability.

Attack classes:

    Type confusion: A message claiming one type but containing data for another

    Length overflow: A size field that wraps around, causing small allocation and large copy

    Capability forgery: A message referencing a capability index the extension doesn't hold

    State-machine confusion: A message sent when no valid state transition exists (e.g., "fill credential" with no pending request)

Why this works: The broker is the only path from extension code to privileged operations. The document doesn't specify the serialization format, capability representation, or message schema.

Severity: Critical

Recommendation:

    Add a broker security requirement: the message parser must be generated from a schema, not hand-written, with formally verified bounds checking.

    The IPC protocol must be a fixed set of request-response pairs with no streaming or partial messages.

    Capability indices must be unforgeable — either kernel-mediated (SCM_RIGHTS) or cryptographically randomized per-connection.

    The broker must be subject to a dedicated security review and fuzzing campaign, acknowledged as an implementation requirement.

Attack Surface 8: The private_browsing:isolated Boundary

Target: Correlate private and regular browsing despite isolation.
Attack: Time-Based Correlation

Attack: The extension in the regular instance writes to storage.private at time T1. The private instance also holds storage.private (separate, memory-only) and network.fetch_public(api.example). Both have wall-clock time.

Protocol: "at minute M, if condition C holds, make a request to api.example/beacon-M." The server correlates requests from the same client IP at the same minute. The private instance's request reveals private-browsing behavior, correlated with the regular instance's profile via IP + time window.

Why this works: IP address is shared. Wall-clock time is available. network.fetch_public is available. Coordination can be pre-arranged in the extension package.

Severity: Medium

Recommendation:

    Acknowledge the time+IP correlation channel as a residual risk.

    Consider a stricter isolated_network mode where the private instance has no network access. Password managers that work offline can use it; extensions that phone home need isolated with the acknowledged risk.

    For isolated mode, consider a browser-managed anonymization layer (fixed-delay batch proxy) — likely out of scope for initial release but noted.

Attack Surface 9: The Document Identity TOCTOU

Target: Exploit a race between document identity validation and operation execution.
Attack: Navigate After Check

Section 13 specifies grants bind to (tab_id, frame_id, document_id, navigation_epoch, origin) and are "revalidated at the final privileged operation."

Attack: The content script requests forms.fill on bank.example. The broker validates the document identity, then forwards the fill request to the renderer. Between validation and fill, the page navigates to evil.example via location.href. If the fill completes on the new document, credentials are injected into the wrong origin.

Why this works: The broker validates, forwards to the renderer, the renderer executes. The validation-to-execution gap exists if these are separate IPC messages.

Severity: High

Recommendation:

    Specify that the document identity in the fill request is opaque to the broker and validated by the renderer at execution time against the current document — not just the broker validating and then forwarding.

    The same principle applies to all document-bound operations: the final execution point validates identity.

    Make explicit: the renderer holds the ground truth for document identity.

Attack Surface 10: The forms.fill Mediated Flow

Target: Extract credentials from the browser-mediated fill flow via origin confusion.
Attack: Credential Confusion

Section 19 specifies: browser detects field, asks extension for candidates, user picks in browser UI, secret moves via privileged channel to exact origin. The extension never holds the filled page's inputs.

Attack: The browser detects a credential field on bank.example. It asks the extension for candidates. The extension returns:
json

{
  "origin": "bank.example",
  "username": "user@bank.example",
  "display": "Bank of America — user@bank.example"
}

But the actual origin of the credential is evil.example. If the browser trusts the origin field from the extension, the credential is filled on bank.example but originated from evil.example — the extension just exfiltrated a credential across origins.

Why this works: The browser-mediated flow puts the browser in control of UI and the secret channel, but the extension controls candidate data. If the browser doesn't cryptographically bind credentials to origins in storage, the extension can lie about origin.

Severity: Critical

Recommendation:

    forms.fill must use browser-managed credential storage with origin binding, not extension-managed storage.private.

    The extension registers credentials with the browser's credential store (similar to Credential Management API), and the browser enforces origin matching.

    If the extension uses its own storage.private for credentials, the capability must be loud with an explicit warning that the extension manages its own credential security.

Attack Surface 11: Composition Pairs Not Captured

Target: Exploit capability combinations that the composition model doesn't label.
Missing Pair A: filtering.cosmetic + content_script (same origin)

Covered in Attack Surface 3. DOM mutation by cosmetic engine is observable by content scripts. The source: none label on cosmetic filtering is incorrect when a content script can observe its effects.
Missing Pair B: filtering.redirect (script surrogate) + content_script (same origin)

Covered in Attack Surface 5. The surrogate writes to page-local storage; the content script reads it and exfiltrates.
Missing Pair C: filtering.dynamic_rules + content_script (same origin)

The content script observes page behavior, installs dynamic rules targeting other sites based on observations. Those rules affect other tabs. The content script has no direct observation of those tabs, but probes via rule installation and timing of aggregate counters.
Missing Pair D: tabs.snapshot + network.fetch_public

tabs.snapshot is gesture-scoped and standard. But if the extension can trigger it on user interaction and immediately send results to its server, it becomes a "dump all open tabs on demand" button — a bulk history dump each time the user interacts.

Severity: Medium

Recommendation: Extend the composition labels. The missing pairs above are real channels. They should either be mitigated (compositor-level cosmetic hiding, isolated surrogate realms, restricted snapshot scheduling) or flagged in derived warnings.
Summary of Findings
#	Attack Surface	Severity	Core Mitigation
1	Statistics oracle via frequency-domain probing	High	Single-counter stats.read only
2	Timing side channel from filter verdicts	Medium	Constant-time or padded verdicts
3	Procedural DSL → DOM mutation → content script	High	Compositor-level hiding or derived warning
4	Compiler compromise → artifact bypass	Critical	Self-describing artifacts, double validation, audited validator
5	Surrogate update substitution → local exfil	High	Isolated surrogate realms; split redirect_resource/redirect_surrogate
6	Remote ruleset server per-user targeting	High	Mandatory content hashes in extension package
7	Broker IPC parsing vulnerabilities	Critical	Schema-generated parser, fuzzing commitment
8	private_browsing isolated time+IP correlation	Medium	Acknowledge risk; isolated_network mode
9	Document identity TOCTOU on fill	High	Renderer-side revalidation at execution time
10	Credential origin confusion in mediated fill	Critical	Browser-managed credential store with origin binding
11	Missing composition labels	Medium	Extend label system for cosmetic, surrogate, dynamic-rules pairs
Overall Assessment

The Gosub Extension Capability Model v2 is well-designed and has closed the obvious first-order attacks. The red-team findings cluster in three areas:

    Side channels the composition model misses — DOM mutation observation, surrogate-contentScript channels, dynamic-rules probing. The composition model is the right tool; it needs broader application.

    Implementation-critical security properties that are stated but not committed — content hashes for remote rulesets, schema-generated broker parsers, renderer-side document revalidation, browser-managed credential storage. These are consistent with the model's intent but need to be design commitments.

    Timing and statistical channels — aggregation and decorrelation are necessary but not sufficient against a patient adversary with many probes. Specific mitigations (single-counter statistics, constant-time filter verdicts) are implementable and should be specified.

None of these findings invalidate the architecture. They identify where the security boundary needs hardening to match the stated intent — the difference between a model that's correct in its stated properties and one that's correct in its actual security boundary.

Analysis complete. All findings are presented for inclusion in the Gosub threat model and for prioritization in implementation planning.