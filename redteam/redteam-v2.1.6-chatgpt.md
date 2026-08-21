This version is materially stronger. The v2.1.4 issues around artifact authority, cross-origin activeTab, publisher identity, raw-first URL rewriting, pooled stats, and redirect reauthorization are now substantively addressed rather than merely reworded. In particular, the “artifact carries no authority” rule is now at the right enforcement layer, including the writable-memfd TOCTOU issue.

I still found several new problems, though. One is serious enough that I think v2.1.6's command-flow closure is currently internally inconsistent.

CRITICAL — §5's command-flow model and §19's registry disagree, so the mechanical closure misses attacks that §5 explicitly says it catches. §5 now correctly says readable egress is a remote_server command source, and gives egress + tabs.navigate as the canonical direct-control example. It then explicitly promises that every capability that drives navigation, DOM, browser UI, etc. has an actuator label. But the registry does not do that. tabs.open / tabs.navigate has sink: arbitrary_network but no actuator: navigation. ui.notifications has no browser_ui actuator. dom.actions_arbitrary has no dom actuator. filtering.dynamic_rules has no filter_policy actuator. downloads.control has no actuator. More seriously, content_script and page.main_world_inject have no actuator labels even though they can obviously mutate the DOM and initiate navigation.

That means the exact example

network.egress_public(c2.example) + tabs.navigate

can fail to derive remote.navigation_control if §19 is what feeds the closure. This isn't editorial: it makes the derived permission warning false.

There's a related contradiction in the supposedly “closed” algebra. §5's source enum contains aggregate, selection, download_urls, user_text, and browser_traffic, but Axis 1 only defines products for six source classes. Meanwhile §19 still uses undeclared labels such as history, history/page, aggregate-history, page-derived, metadata, and credentials/session. Even webpage × extension_bridge refers to an extension_bridge actuator that isn't in the actuator enum. So the claim that the registry is mechanically validated against an authoritative algebra cannot currently be true as written.

Fix: make source/sink/command-source/actuator actual mandatory structured fields for every registry entry, including explicit none. Then mechanically require every source×sink and command-source×actuator product to have a defined outcome. No prose shorthand such as history/page.

HIGH — the scriptlet proof still doesn't account for transitive page gadgets. The new write-value restriction is a good fix: the extension can write only a vocabulary such as true, false, null, 0, etc., rather than https://evil.example. But this statement is too strong:

an attacker who cannot supply evil as the value cannot feed a page gadget, gadget or no gadget.

Consider a legitimate page containing conceptually:

if (cfg.telemetryEnabled) sendSensitivePageState();

A scriptlet sets the perfectly permitted plain property cfg.telemetryEnabled to the perfectly permitted constant true. The scriptlet did not move a page-derived byte. Its own control flow did not depend on page state. Yet it caused page code to produce a network effect that would not otherwise have occurred.

This matters because §5's foundational rule deliberately uses observable effect, not which API directly performed the operation. The current non-interference rule only considers page-derived state controlling the scriptlet's observable behaviour; it doesn't consider scriptlet state controlling downstream page behaviour.

I don't think a generic set-constant(path, fixed_value) can be proven sink:none merely from target shape and fixed-value vocabulary. You either need a transitive-effect proof, restrict standard-tier operators to much stronger monotonic/suppressive semantics, or admit that some operators remain dom power with a possible page-mediated sink. The current decision to keep scriptlets loud until O3 helps operationally, but it does not make the eventual sink:none proof sound.

HIGH — cookie permissions are still modeled like origins, but cookies aren't origin-scoped. §3 defines canonical grant identity as scheme + host + port and even uses cookies.read(http://localhost) as an example. But cookie authority behaves differently: cookies aren't port-scoped, a Domain=.example.com cookie may affect sibling subdomains, Secure affects scheme behaviour, and path/partition semantics matter. This becomes especially important now that cookies.write is correctly modeled as a delayed outbound sink and session-state actuator.

An extension granted narrowly to foo.example must not be able to write .example.com state that is subsequently emitted to bank.example. Likewise, a grant notion containing :8443 cannot pretend cookies are confined to that port.

Fix: define a cookie-specific scope algebra. A write should be permitted only if every request origin to which that cookie can be emitted is contained in the grant. An easier conservative rule is host-only cookies for narrow grants; Domain= requires a grant covering the resulting domain scope.

HIGH — private-browsing isolation isn't closed under the capability set. isolated promises separate workers, memory-only state and no browser-provided channel between regular and private instances. But stats.read now consumes a global per-profile privacy budget shared across all extensions. Unless private mode gets a separate pool, that itself is a browser-provided channel: private reads deplete a budget whose state a regular worker can observe through changed/noisy/denied reads, and vice versa. The underlying block counter must be partitioned too.

system.native_messaging is an even clearer bridge: two isolated workers talking to the same native process have a browser-provided communication path unless private mode forbids or partitions that capability. network.proxy_control, download state, badges/counters and other global-ish browser state deserve the same analysis.

I'd make private browsing a capability-intersection matrix, not just four worker modes: for each capability, say denied, separately partitioned, shared-but-read-only, or spanning.

HIGH — remote ruleset model C still contains model A as normative-looking text, and selective withholding still gives the list server policy control through availability. The section begins by defining filtering.remote_rulesets with a mandatory package-embedded hash, and §19 still says sources+hash, “hash-pinned in package”. Those are model A. A few paragraphs later the document says that wording is corrected and model C actually pins a catalog identity/key. An implementer can still reasonably choose either contract from the document.

There's also a deeper availability attack. The new max-age rule prevents a selected client from silently staying stale forever, but if the publisher's list server can withhold the current immutable object from Alice while serving Bob, after expiry Alice gets a fetch failure while Bob gets filtering. That's still targeted influence over filtering behaviour, just current rules versus failure/no rules rather than two valid hashes. Saying the catalog “mirrors where the threat model demands it” leaves the strong guarantee unsupported.

If the stated guarantee is really “the list server cannot choose per-user filtering”, catalog/store-controlled distribution or mandatory independent mirrors need to be part of model C, not optional.

There's also stale wording in §11: the UI still says “No remote server can change its filtering between updates” and the following prose again talks about no runtime changes between authenticated extension updates, even though §9 explicitly says catalog revisions are legitimate runtime filtering changes.

HIGH/MEDIUM — navigation authority has no explicit scheme boundary. tabs.open, tabs.navigate and omnibox.navigate are classified as navigation/network sinks, but the capability registry does not constrain which URL schemes they may target. This needs to be part of the security model, not left to incidental API implementation.

If javascript: ever reaches a page, tabs.navigate has become main-world execution rather than ordinary navigation. file:, browser-internal schemes, extension origins and similar targets have different authority from https:. I'd make this a positive scheme allowlist: ordinary standard navigation gets web schemes; javascript: is never accepted through navigation; local/internal/extension schemes require separately named authority.

HIGH/MEDIUM — the document doesn't close the “extension A filters extension B” boundary. §15 says what filtering can match and protects browser/extension update traffic, certificate validation, browser internals and gosub://. It doesn't say that ordinary network requests initiated by another extension are protected from another extension's filtering tables.

If blocker A can block or rewrite password-manager B's sync/API traffic, you have cross-extension integrity/availability and potentially feedback channels that aren't in the publisher closure. If the intent is already “filter page traffic, never another extension principal's traffic”, state and enforce that explicitly at Sonar.

MEDIUM — revocation currently promises more than physics permits. The new epoch recheck is good, but the text says an old request “does not get to finish under the withdrawn grant.” Once bytes have crossed the socket, a cookie has been committed, a file has been created, or a navigation has committed, revocation cannot undo the external effect.

Define a commit point per capability instead: no new privileged effect may begin/commit after revocation; in-flight cancellable work is aborted; already externally committed effects are irreversible. For networking you can close the connection and stop remaining bytes, but cannot “unsend” the prefix already received remotely.

MEDIUM — the compromised compiler can DoS the privileged assembler before artifact validation. The assembler now correctly owns the memfd, receives compiler output over a pipe, then validates and seals it. But because the compiler is explicitly assumed compromised, the assembler cannot wait for it to politely finish a bounded artifact. It can stream forever, emit gigabytes, or attempt pathological section counts before validation begins.

The compile/memory budgets therefore need to be enforced while ingesting the compiler stream by the trusted assembler, with a byte cap, section-count cap, wall/CPU limits and termination of the compiler process. Post-build validation is too late for this particular DoS.

MEDIUM — per-hop network authorization needs explicit connection-reuse/proxy semantics. The new host-scope + address-space redirect check is correct. But “check every DNS resolution/connect” is insufficient as the complete invariant once Sonar supports HTTP/2 or HTTP/3 connection coalescing, Alt-Svc, connection pooling, or proxies: a new logical request may reuse an existing socket and perform no new DNS resolution or connect() at all. With remote-DNS proxies, the socket peer isn't even the actual destination.

The invariant should be: every request/stream creation authorizes the logical destination and its route, independent of whether the underlying transport is new or reused. Connection reuse must never substitute for a capability check.

The biggest surprise in this pass is #1. v2.1.6 fixes the conceptual remote-command problem very well in §5, but the registry hasn't caught up with the model, so the concrete machine-readable thing that is supposed to make the fix real still loses the information.

The next two I'd focus on are cookie-specific scoping and private-mode closure across all browser-managed capabilities. And I would give the scriptlet sink:none proof another adversarial pass specifically around downstream page gadgets, rather than around direct scriptlet writes again. Those feel like the most likely sources of a genuine v2.1.7 model change rather than editorial cleanup.