# Red-team pass against Gosub Extension Capability Model v2.1.9 (Claude)

Scope: the whole document, with emphasis on (a) whether the v2.1.9 changes are sound and consistently applied, (b) places where one section has a stronger principle than the registry/translation has caught up with, and (c) fresh model-level holes. I did not re-raise anything already closed by the v2.1.8 passes. Severity reflects model impact, not prose size.

The short version: the v2.1.9 headline fix ("outbound mutation is a sink") is correct in direction but is **both over-scoped and under-applied**, and it misses the most important instance of itself — runtime-installed rules. Two other clusters stand out: the `remote_server` command-source is still defined egress-centrically and misses several channels (push, web-page→extension messaging, content scripts on publisher-controllable origins), and model C's "every user provably runs the same bytes" is asserted without a mechanism that actually provides it.

---

## HIGH

### 1. `filtering.dynamic_rules` is an outbound sink, and the §5 "unconditional mutation carries no predicate" exemption only holds for install-time / catalog rules

§5 (v2.1.9) reasons that a *static* header/rewrite mutation leaks nothing because it carries no predicate. That is true for rules fixed at install (package) or approved globally (catalog). It is false for **rules the worker installs at runtime**. With `dynamic_rules` + any mutation capability the worker can encode *worker-held state* into the rule it chooses:

- install header-rule variant *k* of *N* (`X-Client-Hint: <static-k>`) → a publisher-observed server sees *k* → log₂N bits per update;
- or, with only `filtering.block` (silent) + `dynamic_rules`: block/unblock `publisher-cdn.example/beacon.gif` → presence/absence is 1 bit per update on any page that loads a publisher-observable resource (or whenever the user visits a publisher page).

No `network.egress_*`, no `cookies.write`, no content script needed. Bandwidth is low but unbounded over time, and `dynamic_rules` is **standard**. The registry labels it `sink: probe` (inbound: turns another source into a targeted one) and `source: implicit_history`, but **not as an outbound sink** — so `tabs.events`/`context.*`/`forms.detect_credentials` + `dynamic_rules` derives nothing on Axis 1, while it is in fact `tab_urls × own_hosts → history.exfiltration`.

Fix: (a) `dynamic_rules` gains `sink: own_hosts` (rule-choice channel to any server the publisher can observe from page traffic); (b) restate the §5 exemption precisely — *a mutation is leak-free iff its predicate is over facts the observing server already holds AND the rule itself was installed through a non-worker-chosen channel (package, catalog, user text)*. Runtime-worker-chosen rules are a sink regardless of how "unconditional" each rule looks.

### 2. The conditional-mutation rule is mis-scoped: it bans predicates the destination already observes, breaks `$3p`/`$domain`/DNR `initiatorDomains` translation for no gain, and leaves `block`/`allow`/`upgrade_scheme` conditional at silent tier

§15 now says a standard-tier header/rewrite mutation "may not be predicated on initiator, party, or any page-derived state". But:

- **Party is already visible to the destination** (`Sec-Fetch-Site: cross-site`/`same-site`), and initiator origin usually is (`Referer`/`Origin` under the default referrer policy). Conditioning on them leaks nothing new to *that* server. Yet `$third-party`/`$3p`, `$domain=`, and DNR `initiatorDomains`/`excludedInitiatorDomains`/`domainType` are among the most common modifiers on `$removeparam`/`$removeheader`/`modifyHeaders` rules. Under the rule as written, every such list rule is untranslatable at standard tier (§18 does not mention this at all), for essentially zero privacy gain. The *genuinely* new leak is narrower: **top-frame identity for requests from nested cross-origin frames** (uBO's `$domain=` matches the top document, which a third-party iframe's server cannot see with partitioned state), and referrer-suppressed contexts. State that precisely instead of "no initiator/party predicate".
- **"Page-derived state" is undefined.** Every rule predicates on the request URL, which is page-produced. The criterion has to be "facts the observer already holds", not "page-derived".
- **Inconsistency:** `filtering.block`/`filtering.allow`/`upgrade_scheme` remain silent and freely conditional on `$domain=`. A `@@||publisher-cdn.example^$domain=clinic.example` exception on top of a general block is a **presence** channel — the publisher's server receives the request only from clinic.example — which is the same class as the conditional header the rule forbids (and a blocked-vs-allowed request is the most basic externally-observable outbound mutation). Either the rule covers block/allow too, or it should be explicit why presence is exempt (it mostly isn't).
- **Not carried into §19/§18.** The `filtering.headers.*` and `filtering.rewrite_url` registry entries still say `standard` / `source: none, sink: none` with no conditional caveat; §18's `$removeparam` → `rewrite_url` line does not say what happens to the initiator modifiers. This is exactly the "principle ahead of the registry" class the last pass hit.

### 3. Model C's "every user provably runs the same reviewed bytes" is asserted, not provided; catalog identity is unconstrained; the catalog is an unnamed command source

§9/§11 promise: "No server it talks to can choose different filtering for you than for anyone else". The mechanism described (catalog signs `(version, hash)`, monotonic revision, max-age, mirrors) does **not** deliver that:

- **Split view.** A catalog can serve client A revisions 1,2,3a and client B 1,2,3b — each signed, each "immutable", each monotonic *per client*. Only an append-only transparency log with inclusion + consistency proofs (or witness co-signing / gossip) makes "same for everyone" *verifiable*. The word "transparency" appears in the model-C row but nothing in the mechanism requires it.
- **Who may be a catalog?** The package "pins the catalog identity + signing key". If a publisher can pin a publisher-run catalog, model C collapses to model B-with-extra-steps and the dialog's ✗ line is false. The doc needs to say catalogs are UA/store-trusted anchors (and then face the centralization cost: every regional/custom list needs UA approval per revision, which pushes publishers toward `egress + dynamic_rules` — i.e. back into the loud pair).
- **Type gap.** The catalog is a command source into `filter_policy` that is neither `publisher_update` nor `remote_server`, and it is absent from the command-source enum. The model is silently declaring it trusted; it should be an explicit atom (`catalog_revision`) so the closure/dialog can name it and so catalog compromise (global, non-targeted filter control; O9 only names the *staleness* window) is a stated residual.

### 4. `remote_server` is still defined as "readable egress"; several readable remote channels carry no `network.egress_*` grant — including one whole missing capability (web-page → extension messaging)

§5: "any egress the worker can read a response from is a `remote_server` command-source". Channels that deliver publisher/remote-chosen bytes to extension code with **no egress in the set**:

- **Web-page → extension messaging** (`externally_connectable.matches` with web origins; `runtime.onMessageExternal`). Not in the registry at all — §10 mentions externally_connectable only for extension↔extension. This is a `command-source: webpage` capability with `actuator: extension_bridge`, and it is precisely the classic **web page → extension → native host** chain (`webpage × os` via `system.native_messaging`). MetaMask/Zotero/Bitwarden-class flows need it; its absence means the `webpage` atom and `extension_bridge` actuator are carried by no entry.
- **Push** (if Gosub workers get Web Push): remote bytes arrive with no egress grant; Axis 2 would not fire.
- **Content scripts on publisher-controllable origins.** `content_script(<all_urls>)` — or any scope containing a host the publisher controls — makes the page DOM a publisher-writable, extension-readable channel: the user visits `publisher.example` and the content script reads its instructions. Weaker (user-visit-gated) but real, and it composes with every actuator `content_script` already carries plus the rest of the set (`native_messaging`, `cookies.write`, `tabs.organize`…).
- **Remote iframes inside extension pages** (newtab override embedding `https://publisher.example/feed`): the iframe posts messages back — a command channel that is not a "fetch response".

Fix: define `remote_server` as *any channel through which remotely chosen bytes reach extension code* and enumerate the kinds; add the web-messaging capability and give `content_script`/`page.main_world_inject` a `command-source: webpage`.

---

## MEDIUM

### 5. `isolated_network`'s denial set is an ad-hoc denylist; it should be derived from the label algebra, and it currently misses obvious sinks

§12 lists "content_script main-world writes, scriptlet, styles.inject_raw" as what `isolated_network` also denies in private. That is the open-ended-denylist pattern §8/§15 reject elsewhere. Misses: `cookies.write` (`sink: session_state` — the cookie rides out on *page* traffic), `dynamic_rules` (finding 1, and page-observable block/unblock), `tabs.open/navigate`, `downloads.create`, `omnibox.navigate`, and **`content_script` wholesale** — an isolated-world script needs no main-world write to launder: DOM write + synthetic click on an existing page link/form, or simply the fact that §5 already labels `content_script` `sink: arbitrary_network` *by definition*. The consistent rule: under `isolated_network`, every capability with `sink ≠ none` (and every page-observable actuator) is denied in private, computed from the registry, not listed in prose.

### 6. `tabs.navigate` vs the egress policy is contradictory, and it makes the "minimal profile" flagship (OneTab) derive `history.exfiltration`

§15 says a navigation/tab-open "routes through the same `(extension_id, initiator, destination)` egress policy" — so `tabs.navigate` to an arbitrary URL needs `network.egress_public` covering it, and a tab manager restoring user URLs would need `egress_public(<all>)`. §19 instead labels `tabs.navigate` itself `sink: arbitrary_network` (no egress grant needed). One of these is wrong. And either way OneTab (`tabs.snapshot: tab_urls` + `tabs.navigate`) derives "Can send the addresses of your tabs to any server" — true in the algebra, but the doc calls OneTab the happy minimal profile without confronting this. The constructive fix, consistent with the `forms.fill` pattern: a **browser-managed tab/session store** with opaque handles (`tabs.restore(handle)`), gesture-bound, so restoring URLs never lets the extension choose destination bytes; plain `tabs.navigate(url)` stays a sink for extensions that genuinely need it.

### 7. The uBO appendix manifest omits `filtering.dynamic_rules`, which the flagship needs; with the current `source: implicit_history` label that yields a derived exfiltration warning on the happy path

The element picker, "My filters", and the per-site on/off switch all install rules at runtime — that is `dynamic_rules`, absent from the narrowed `gosub` grant in the appendix. Add it and, as labelled today (`source: implicit_history`), `dynamic_rules × content_script(.active_tab)` derives `history.exfiltration` — a scary derived line on the flagship dialog, contradicting "✗ It cannot see the addresses you visit". The `implicit_history` source label rests on one sentence ("a single-URL dynamic rule plus a timing loop turns the matcher into a navigation detector"); no worker-observable channel is actually described (packaged loads are unobservable, cache is isolated, no events, no counters). Either state the mechanism or drop the source label and keep `sink: probe` (which correctly captures "targets other sources"). Note finding 1 adds an *outbound* sink label instead, which for uBO only restates the `active_tab` "!" line.

### 8. The header safe-list needs an admission *criterion*; "static value" is not sufficient because a static header can make the UA fetch/navigate/trust, and the rule's URL predicate leaks to a *third* server

§15 v2.1.9 makes the writable set positively enumerated but gives no criterion. A static `Link: <https://collector.publisher.example/p>; rel=preload` set on responses from `clinic.example/*` makes every browser that loads clinic.example hit the collector — the predicate (the page URL) is known to clinic.example but *not* to the collector, so this is history exfiltration via a "static" header. Likewise `Refresh`, `Location`, `Report-To`/`NEL`, `Alt-Svc`, `Accept-CH`; and integrity-wise `Content-Type` (text/plain→text/html = stored XSS), `X-Content-Type-Options`, `Content-Disposition`, `Timing-Allow-Origin` (opens a cross-origin timing channel to page JS). Stated criterion: a writable header must have no UA-side fetch/navigate/store/trust/MIME/security semantics. (Also: "the writable set is the explicit complement the build validates" reads as complement-of-protected; if it is an allowlist, say allowlist.)

### 9. Axis 2's product table is not closed the way Axis 1 is, contradicting "no product is left undefined"

Axis 1 defines a product for every source atom. Axis 2 lists five products. Missing: `remote_server × os` (`downloads.create`, `proxy_control`, `native_messaging` are all `actuator: os`), `remote_server × session_state` (named only in prose), `remote_server × extension_bridge`, all of `native_process × *` ("etc." in the registry), `webpage × dom/navigation/os`, `enterprise_policy × *`, `publisher_update × *`. Atoms carried by no registry entry: `webpage`, `extension_bridge`, `publisher_update`, `packaged`. If the build validator enforces closure it would reject the document's own table.

### 10. Key rotation by continuity chain makes a *stolen key* sufficient to rotate the principal's key

§13: "a new key authenticated by a signed continuity chain from the old one is the same publisher … a stolen key cannot quietly ship expanded authority". A stolen key *can* sign a continuity chain to an attacker key — preserving the principal, locking out the victim, and surviving the victim's later revocation of the old key ("re-established only up the chain" — the chain the attacker extended). Since the principal is the store-bound organizational identity, rotation must be authorized by that identity (account auth), with the chain as a distribution artifact, not as the authority.

### 11. Executable surrogates in an "isolated realm" contradict what surrogates are for

§6/§8: surrogate entries "run in §6's isolated realm and cannot patch page globals". But `googletagservices_gpt.js`, `google-analytics_ga.js` (listed in the appendix) exist *to define page globals* (`window.googletag`, `window.ga`) that page code calls. An isolated-realm surrogate is functionally a noop script — fine for `noop.js`, useless for API stubs. Either API-stub surrogates run in the main world under the §8 closure (then the realm-partition argument is hollow and they inherit the loud-until-O3 tier), or there is a membrane exposing isolated-realm objects to the page (unspecified, and page callbacks crossing it reopen the sink question). Pick one and say it.

### 12. Filtering scope has two dimensions (initiator page vs destination host) and `capability(scope)` conflates them

`filtering.block(class, hosts)` — are `hosts` the request destinations or the pages the rules apply on? §14's envelope check is "against the effective destination"; §19's `dynamic_rules` entry mentions "host/initiator scope"; "per-site revocable" means initiator site. The grant envelope "a table entry outside the envelope is dropped" is ambiguous until both axes are named. Make filtering scopes explicitly `(initiator_scope, destination_scope)`.

### 13. Content-script IPC endpoints are renderer-trust; the doc should pin which capabilities are invocable from them

§16 assumes a compromised worker. A compromised *renderer* (hostile page) can act as any content script injected into it, with that content script's authority. §15 says content-script requests consume the extension's egress grants — so a page exploit buys egress to the publisher's hosts, and anything else callable from a content-script endpoint. State that content-script endpoints are page-compromisable and restrict them (document-scoped ops only; egress/cookies/etc. from the worker endpoint only, or explicitly accept the exposure).

### 14. "Expansion suspends the extension until approved" fails open, by the doc's own §9 argument

Suspending a blocker pending re-consent leaves the user unfiltered — exactly the fail-open outcome §9 refuses for stale lists. Run the *previous* version under the *old* grant until approval; suspend only if no prior version exists.

### 15. `redirect_resource` must be an in-place synthetic response with unchanged `response.url`

If a redirect is a 30x to an extension URL, `fetch().url` exposes the per-session randomized token to the page, so the per-session randomization (changelog 18) buys nothing and the page fingerprints the installed extension. The doc's "cache isolated" phrasing implies substitution; say so explicitly.

---

## LOW / consistency

16. **Stale prose.** Appendix "Interesting cases": "scriptlets in the browser library → `filtering.scriptlet` (standard)" — the tier is loud-until-O3. §11 says post-O3 it relaxes to a "silent-tier ✓ line"; §8/§19 say *standard*. §11's "Update its filter lists from lists.example" vs model C (catalog/mirrors). `content_script.active_tab` is standard but rendered with the loud "!" marker. Tier semantics are muddled: "silent (auto-granted)" capabilities (`filtering.block`, `stats.display`) still appear as ✓ lines, so silent ≠ unshown — define what silent/standard mean for the dialog.
17. **Cosmetic compositor-invisibility** is (a) incompatible with collapse semantics (`display:none` reflows; compositor hiding leaves holes) and (b) unnecessary: any extension context able to observe layout already holds `page_content`. Either accept `page_content` for cosmetic or drop the requirement.
18. **Pooled stats budget is a cross-publisher browser-provided channel** (A depletes, B observes degraded/denied reads) and a DoS on every legitimate `stats.read`. Assign to O5/O7.
19. **Registry completeness beyond O2** where new atoms or high-impact actuators appear: `clipboard` read (often credentials) / write (plant crypto addresses — MetaMask-relevant; ColorZilla in the appendix uses it), `management` (installed-extension list = a co-install oracle for the attacker), `browsingData`, `identity.launchWebAuthFlow` (navigation + read-back), `history`/`webNavigation`/`sessions`/`topSites`, `storage.sync` (cross-device channel; private-browsing relevance). Translation gaps: `$csp`/`$permissions` (protected headers — if admitted at all, additive-only and with `report-*` stripped, since violation reports are a sink), `$removeheader`, `$header=`, `$urlskip`, `$cname`.
20. **Extension-written cookies outlive the grant.** §13 calls a set cookie irreversible; it is deletable. Provenance-tag extension-written cookies and purge on revoke/uninstall (persistent tracking residual otherwise).
21. **DNS ordering.** The host-scope check must run *before* resolution — the DNS query itself leaks the hostname (`<secret>.evil.example`) even if the connect is later denied. §15 lists the checks but not the order.
22. **Registry relabeling vs existing grants.** v2.1.9 added `actuator: browser_ui` to `tabs.organize`; every installed `egress + tabs.organize` now derives `remote.ui_control`. Does a registry/model update re-display the derived delta? Unspecified.
23. **Same-publisher closure soundness depends on store identity proofing** (two accounts = two principals); name it as an O6 dependency. bfcache restore and prerender activation should revalidate grant epochs (§13).
24. **adblock-rust phase-0** does not implement §6 byte-splice `$removeparam`, §15 header semantics, or the envelope intersection; the oracle needs a wrapper or the claim "baseline" needs qualifying.

---

## What held

The cookie scope algebra (§3), grant-envelope placement (§14), the scriptlet closure's new timing/combination/Rice clauses (§8), the publisher-principal model apart from rotation (§13), the navigation scheme allowlist, and the private-browsing partition rule all survived this pass. The doc's recurring failure mode remains the one the v2.1.8 passes named: a section develops a stronger principle (here: mutation-as-sink) and the registry, translation table, and worked examples do not catch up — but this time the principle itself also needs a sharper statement (finding 2) and has a more dangerous instance the text does not see (finding 1).
