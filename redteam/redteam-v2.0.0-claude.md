# Red-Team Analysis — Gosub Extension Capability Model v2

**Adversary:** a hostile extension author who submits a package to the Gosub store. Goal: exfiltrate browsing history, credentials, keystrokes, or page contents while requesting capabilities that are as *quiet* as possible — ideally nothing above `standard`, ideally no derived-authority warning at install.

**Method:** the v2 defense of record is the source×sink composition closure (§5). An attack succeeds if it (a) manufactures a source or sink the label system does not recognize, (b) moves information through a channel that is not a labeled sink at all, or (c) defeats the observe/control constraints (§6) directly. Findings are ranked by severity and annotated with whether v2 as written catches them.

---

## Findings

### R1 — `content_handler` is an unlabeled source (High)

**Setup.** Register `content_handler(["application/json"])`. Tier: `standard`. Also request `network.fetch_public(["collector.mine.example"])`. Tier: `standard`. Both individually innocuous — a JSON viewer that talks to its own service.

**Attack.** When the user navigates top-level to any endpoint that returns `application/json` — `https://bank.example/api/account/export`, `https://mail.example/api/messages`, a GraphQL gateway — the browser hands my handler the **authenticated response body**, because the navigation carries the user's cookies. I read it and POST it to `collector.mine.example`.

**Why v2 misses it.** §19 constrains `content_handler` navigationally (top-level only, nosniff, Content-Disposition) but **assigns it no source label**. It is therefore absent from the §5 closure: `content_handler + network.fetch_public` does not resolve to `page.exfiltration`, so no derived warning fires. The install dialog reads "displays JSON; talks to its own service" — technically true, materially a lie. This is the same class of hole the whole model exists to prevent, reintroduced through a capability that was reasoned about only for *rendering*, not for *reading*.

**Severity: High.** Authenticated cross-origin data, standard+standard, no honest warning.

**Fix.** Label `content_handler` `source: page_content` (elevating to `credentials` when the handled response is same-site authenticated). It then composes exactly like `content_script`: with any sink it becomes `page.exfiltration` and the dialog says so. Consider forcing handled documents into an isolated, sink-free rendering context unless the extension separately holds a network sink — making the exfiltration path explicit rather than ambient.

---

### R2 — Cross-extension / same-publisher collusion (High)

**Setup.** Ship **two** extensions. Extension A: "Reader Mode," requests `content_script(["<all_urls>"])` — `source: page_content`, **no sink**. Extension B: "Cloud Notes," requests `network.fetch_public(["sync.mine.example"])` — sink, **no page source**. Each extension's *own* closure is clean: A can read but not send; B can send but not read.

**Attack.** A and B collude through any shared browser-global channel — the obvious one being a covert channel neither declares: storage-quota timing, `filtering.dynamic_rules` state one can set and the other can infer, cache contention, IndexedDB under a shared eTLD if the store permits it, or simply a coordinating server that correlates the two by install-time nonce. A reads pages, encodes them into the covert channel; B drains it and exfiltrates.

**Why v2 misses it.** The composition closure is computed **per extension**. Nothing aggregates authority across two packages by the same publisher, and the covert channels are not modeled at all.

**Severity: High**, because it is low-effort and defeats the model's core claim by construction — split source and sink across the publisher boundary and each half passes review.

**Fix (layered).**
- Compute derived authority over the **union of a publisher's installed extensions**, not each in isolation. A publisher holding `page_content` in one extension and any sink in another is treated as holding `page.exfiltration`, warned accordingly.
- Deny extension-to-extension channels by default (v2 already forbids ambient cross-extension access and gates `externally_connectable` — extend the same posture to *implicit* channels: per-extension storage partitions, per-extension cache partitions per R6).
- Accept the residual: two *unrelated* publishers colluding via a server plus a covert channel cannot be prevented by manifest analysis. Name it as out-of-scope and lean on store-side signals (shared infrastructure, correlated behavior).

---

### R3 — `forms.detect_credentials` leaks fact-of-login as coarse history (Medium)

**Setup.** A password manager legitimately holds `forms.detect_credentials` (standard) **and** `network.fetch_public(["sync.myvault.example"])` (standard, for vault sync). This is the *expected, trusted* configuration — not an exotic grant.

**Attack.** `detect_credentials` fires with the page origin whenever the user lands on a login form. That stream is precisely "which sites the user logs into, and when" — a high-value, low-noise subset of browsing history. With the vault-sync sink already present, the manager can smuggle that stream out; even honestly, the *detection event itself* reveals it to extension code.

**Why v2 partially misses it.** The mediated fill flow (§19) protects the *secret* — extension code never holds the filled input. But detection is upstream of the flow and carries the origin. It has no source label, so `detect_credentials + fetch_public` does not raise `history.exfiltration`.

**Severity: Medium** — narrow channel (login pages only), but it lands on the single most sensitive extension class and the exact data users least expect to leak.

**Fix.** Make detection browser-mediated too: the browser observes the credential field and reveals *nothing* to the extension until the user actively invokes the manager on that field (gesture-scoped, like `content_script.active_tab`). Absent that, label `detect_credentials` `source: tab_urls` so its composition with any sink is warned.

---

### R4 — `remote_rulesets` differentiated by IP (Medium)

**Setup.** Declare `filtering.remote_rulesets(["https://lists.mine.example/easylist.txt"])`. The browser fetches it (§9): no extension cookies, no extension headers, jittered schedule. Looks airtight.

**Attack.** The browser fetch still originates from the **user's IP**. My server serves different rule bytes by IP/geo/ASN — coarse per-user policy that §9 was meant to preclude. More sharply, it undermines the §7 assumption that rules are uniform across users: I can hand a targeted cohort a ruleset whose single rule matches one site, then use aggregate `stats.read` against that cohort as an oracle the decorrelation logic didn't anticipate (because it assumed identical rules everywhere).

**Why v2 misses it.** §9 strips request-linkable identifiers but not the connection's source address, and treats "browser-fetched" as sufficient for uniformity.

**Severity: Medium** — coarse (IP-granular), but reintroduces the targeted-policy vector §9 claims to close.

**Fix.** Prefer **content-addressed rulesets**: publisher signs/hashes a canonical list; the browser fetches by hash through a shared cache/CDN so every user provably gets identical bytes, and mismatched bytes are rejected. Where that is impractical, state the IP-differentiation residual explicitly and keep the stats-degradation rule conservative regardless of apparent rule uniformity.

---

### R5 — Content-script revocation is not effective until reload (Medium)

**Setup.** Malicious `content_script(["<all_urls>"])` — openly loud, but the user grants it (some legitimately scary extensions get installed). Later the user revokes it on `bank.example`.

**Attack.** Revocation is a Baleen table broadcast (§13): it stops *new* injections and fails privileged broker operations closed. But JavaScript already injected into the currently-open `bank.example` document keeps executing — the model has no way to unload running script from a live document without a navigation. The extension keeps reading the page across the revocation until the user happens to reload.

**Why v2 misses it.** §13 defines revocation crisply for grant-gated *operations* and for *future* injection, but "the injected code is already running" is a document-lifetime fact the table update cannot reach.

**Severity: Medium** — bounded to already-open documents, but users reasonably read "revoke" as "stops now."

**Fix.** On revocation of `content_script` for an origin, force re-evaluation of affected live documents: tear down the isolated world where the runtime allows it, or prompt/auto-reload with attribution. At minimum, surface honestly in the revocation UI that open tabs remain affected until reload.

---

### R6 — Timing side channels for sink-only and redirect extensions (Low–Medium)

**Setup.** An extension with *no* page source — say only `network.fetch_public(["api.mine.example"])`, or only `filtering.redirect` with packaged static targets (both meant to be observation-free).

**Attack.** Two low-bandwidth channels survive v2's constraints:
- **Shared-cache / socket / DNS timing:** repeatedly fetch my own host and measure latency; connection-pool and DNS-cache contention leak coarse signals about the user's concurrent activity and, with effort, whether specific hosts were recently contacted.
- **Packaged-resource cache warmth (redirect case):** §6 makes packaged-resource *loads* event-unobservable, but not *cache-state*-unobservable. If a redirect warms packaged resource N and my own extension page can later time N's load, I learn rule N fired — i.e., the user hit tracker N — defeating "control without observe" through the cache rather than an event.

**Why v2 misses it.** §6 closes the event channel and the dynamic-target channel; it does not address cache/timing state shared between the request path and extension-accessible contexts.

**Severity: Low–Medium** — low bandwidth, noisy, but the cache-warmth path is a genuine crack in the headline property.

**Fix.** Partition HTTP cache, DNS cache, and connection pools per extension (and isolate packaged-resource cache state from any extension-readable context). This also strengthens R2. Note any residual timing channel as accepted.

---

### R7 — `input.commands` leaks keystroke dynamics (Low)

`input.commands` (standard) strips text and disables in editable/password fields, which kills content capture. It still exposes **chord timing** across all sites — dwell/flight intervals that are biometric (user fingerprinting, cross-site correlation) and, at the margin, cadence-inferential. Severity Low. Fix: coarsen/quantize event timing delivered to extensions, or note the residual biometric channel.

---

### R8 — `dom.declarative_actions` residual integrity/CSRF (Low)

v2 blocks user-activation minting and constrains navigation/form submission. Residual: declarative clicks on arbitrary *non-form* interactive elements (JS `onclick` handlers — "authorize," "delete," "buy," "send") on pages the extension cannot observe. No confidentiality loss, but real integrity/availability/user-intent impact (the I/A/U axes §4 exists to catch). Severity Low. Fix: restrict declarative targets to a conservative element class, or require the capability to declare its target selectors at install so the dialog can describe them.

---

### R9 — The Baleen artifact validator is attacker-influenced parsing inside Sonar (hardening mandate, not a design hole)

§14/§16 correctly treat the compiled artifact as untrusted and mandate validation before use. Consequence worth stating plainly: the validator is now **security-critical parsing of adversary-influenced bytes running inside the network process** — the exact surface the multi-process design otherwise works to minimize. This is not a hole (the design is right) but it concentrates risk. Mandate: the artifact format must be *totally and cheaply validatable* — forward-only offsets, length-prefixed sections, no internal pointers, no size fields that gate later reads without bound checks — and the validator must be continuously fuzzed against a hostile-compiler corpus. A validation bug here is a renderer→network-process escalation.

---

## What held up

Honest accounting — the model defeated several attacks I tried:

- **Direct request observation.** No configuration of filtering capabilities yields the concrete URL. §6 holds for the event channel; only the timing residual (R6) survives, and at low bandwidth.
- **Dynamic redirect encoding.** The static-target rule (§6) kills the "redirect to `extension://x/1x1.gif#{matched-url}`" exfiltration outright — the strongest single fix carried from the reviews.
- **The `fetch × user_scripts` remote-code bypass.** The §10 workflow rule (fetched content may not silently become a user script) closes it.
- **Naming yourself in the broker.** Channel-bound identity (§16) defeats the confused-deputy/spoofed-`extension_id` class cleanly.
- **Grant-then-navigate TOCTOU.** Document/epoch binding (§13) holds; navigation cannot smuggle a grant onto a new origin.
- **`stats.read` as a static oracle.** Quantization + windows + minimum aggregation defeat the *stable-rule* oracle; the probe-sink degradation rule handles the *mutable-rule* version — R4 is the remaining seam, and it comes through ruleset non-uniformity, not through stats directly.
- **The obvious update expansions.** Scope-widening and `gosub`-key removal both trip the §13 diff.

The pattern: v2's confidentiality-through-composition is strong where sources and sinks are correctly *labeled*. Every High/Medium finding is a **labeling gap** (R1, R3), a **scope-of-closure gap** (R2), a **uniformity assumption** (R4), a **lifetime gap** (R5), or an **unmodeled covert channel** (R2, R6) — not a flaw in the composition idea itself. That is the good news: the fixes extend the existing mechanism rather than replacing it.

---

## Recommended v2.1 deltas

| # | Finding | Severity | Delta |
|---|---------|----------|-------|
| R1 | `content_handler` unlabeled source | High | Assign `source: page_content`/`credentials`; force sink-free render context by default |
| R2 | Same-publisher source/sink split | High | Compute closure over a publisher's installed set; partition per-extension storage/cache; document unrelated-publisher residual |
| R3 | `detect_credentials` login-history | Medium | Browser-mediate detection (gesture-scoped), or label `source: tab_urls` |
| R4 | `remote_rulesets` IP differentiation | Medium | Content-addressed signed rulesets via shared cache; keep stats degradation conservative |
| R5 | Revocation vs. live documents | Medium | Tear down / reload affected documents on revoke; surface honestly in UI |
| R6 | Cache/DNS/socket timing | Low–Med | Per-extension cache/DNS/pool partitioning; isolate packaged-resource cache state |
| R7 | `input.commands` dynamics | Low | Quantize event timing; note residual |
| R8 | `declarative_actions` integrity | Low | Restrict to a safe element class; declare selectors at install |
| R9 | Validator attack surface | (mandate) | Totally-validatable format + continuous fuzzing; treat as renderer→Sonar boundary |

**Two structural principles to add to §5:**

1. **Every capability that touches page-, credential-, tab-, keystroke-, or pixel-derived data carries a source label — no exceptions, and "it only renders / only detects / only acts" is not an exemption.** R1 and R3 both came from capabilities reasoned about for their *action* while their *incidental read* went unlabeled.

2. **The closure is per *principal*, and the principal is the publisher, not the package.** R2 is only closed once authority aggregates across a publisher's extensions.

The next pass after v2.1 should be a dedicated **covert-channel review** (storage, cache, DNS, timing, quota) — R2 and R6 both live there, and it is the one area v2's confidentiality argument does not yet reach.
