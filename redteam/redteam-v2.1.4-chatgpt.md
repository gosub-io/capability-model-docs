Yes. I found several things I’d classify as genuine new red-team findings rather than just implementation details. I would not yet call the core composition model closed in v2.1.4. Three findings in particular affect the model itself.

CRITICAL — remote_server command authority is derived too narrowly.
§5 says command-source: remote_server emerges from “egress-to-own-host + a mutation capability,” with the canonical example being egress + dynamic_rules + filtering.block. But a mutation capability is not necessary for ordinary imperative APIs. An extension with only network.egress_public(["c2.example"]) + tabs.navigate can poll c2.example, receive {url: ...}, and call tabs.navigate() directly. That is plainly remote_server × navigation → remote.navigation_control, but the described derivation can miss it. The same applies to notifications, downloads, DOM actions, cookie writes, etc.

The rule should instead be: a readable egress channel is itself a command-source: remote_server. Then it composes with every direct actuator. dynamic_rules is only additionally required where the thing being remotely controlled is declarative policy rather than a directly callable API.

CRITICAL — a compromised compiler can apparently widen semantic authority while producing a perfectly valid artifact.
The threat model explicitly assumes the compiler is compromised, but the consumer validation described in §14 checks bounds, termination, safe handles, and scriptlet operator/argument validity. It does not say the consumer independently verifies that every compiled entry is within the extension's granted capability, host, class, initiator and extension identity.

Attack: grant filtering.scriptlet(["example.com"]); compromised compiler emits a structurally perfect bank.example -> set-constant(...) entry. The renderer revalidates that set-constant is a permitted operator with valid arguments, but that is not the same as revalidating the authority to inject it into bank.example. The same problem exists for header rules, redirects, content-script tables and anything else executed directly from an installed table rather than through a broker IPC call. The broker does capability×scope checks for IPC, but Sonar/render-side artifact execution bypasses that per-operation broker path.

I’d make this an explicit invariant: an artifact never carries authority. Every consumer intersects the artifact result with a trusted, separately-produced (extension_id, capability, granted_scope) envelope/table. The untrusted compiler must not be able to produce the grant/egress namespaces at all.

Related: the write → validate → seal memfd sequence is safe only if the compromised compiler never possesses the writable memfd. Otherwise there is a validate/seal TOCTOU. The actor ownership should be stated explicitly.

CRITICAL/HIGH — the scriptlet “byte provenance” rule does not close implicit information flows.
v2.1.4 says a rule-supplied constant is safe as long as no value derived from page state is written out. But information can be encoded in whether a constant gets written:

if secret_predicate(page_state) { x = false }

false contains no page-derived bytes, but observing whether x changed reveals one bit of secret_predicate. The listed operators are full of exactly this shape: prevent-fetch/xhr branches on a page-generated URL, json-prune branches on page data, and abort-on-property-read branches on page behavior. A co-resident extension context can observe consequences without a single page-derived byte ever being copied.

So the required property is not byte provenance; it is closer to non-interference including control-flow taint. If a page-derived predicate controls an extension-observable write, exception, timing change, response substitution, DOM change, etc., you have a channel. This directly attacks the reason filtering.scriptlet earns source:none.

There is also a second scriptlet problem: the allowlist as written appears incompatible with the advertised operators. It permits writing only an own data property containing a primitive on a plain non-DOM/non-navigation object, yet the motivating example writes window.adsEnabled; prevent-fetch needs to replace window.fetch; and abort-on-property-read/write normally installs accessors. Window isn't a plain object and a function/accessor isn't a primitive data property. So either the useful operator set is much smaller than claimed, or the allowlist will have to grow—and every exception reopens the security proof.

HIGH — activeTab appears to overgrant cross-origin frames.
The text says an active_tab grant “covers the current document and its frame tree.” If that literally includes cross-origin descendants, clicking an extension's toolbar button on news.example could grant access to embedded authenticated/payment/login frames from other origins.

It should say something like: top-level origin + same-origin/inherited-origin descendants. A cross-origin child needs a separately held host grant or a separately scoped browser gesture. The frame-tree-wide epoch teardown is good; frame-tree-wide authority is not.

HIGH — §10's “no remotely hosted executable code” guarantee cannot be enforced by CSP/runtime alone.
The document says remote data cannot introduce general-purpose executable logic, enforced through no remote scripts, no eval, packaged WASM only, etc. But packaged extension code can contain an interpreter:

fetch("c2.example/program.json") → interpret(program)

A JavaScript implementation of a bytecode interpreter, rules VM, expression language, Lua-like evaluator, or even a sufficiently capable JSON command dispatcher needs neither eval nor remote WASM. Remote data has now become arbitrary executable policy.

The engine can enforce no direct remote code loading/eval, but it cannot determine whether arbitrary fetched bytes are being treated as “data” or as a program by packaged Turing-complete code. This needs to be an honesty correction in §10, plus store/review policy if you want to forbid remote interpreters. The capability model still bounds what that interpreted program can do, which is where finding #1 becomes especially important.

HIGH — publisher identity can be sharded with signing keys, and key rotation is modeled incorrectly.
The model intentionally composes authority across a publisher, but then defines publisher as the signing-key identity rather than the actual controlling publisher. Two packages from one malicious controller can simply use two signing keys and stop being “same publisher” according to the model.

Also, ordinary key rotation should generally preserve publisher identity via a signed continuity chain, not change the principal. Otherwise approving a key rotation can cause two packages that previously composed to stop composing even though ownership never changed.

I think you want a stable publisher principal with signing keys attached/rotated beneath it. A genuine ownership transfer changes the principal; key rotation does not.

HIGH — rewrite_url still has a parser/provenance ambiguity capable of corrupting the wrong raw range.
The new algorithm says matching happens on a scratch copy that is percent-decoded and then treats & and ; as separators. Consider:

?a=%26fbclid=secret&b=1

If percent decoding happens before parameter tokenization, the scratch representation becomes conceptually a=&fbclid=secret&b=1. You have created a separator that did not exist in the raw URL. Now the matcher can identify a phantom fbclid parameter residing inside a's value, and the scratch→original span mapping becomes dangerous.

The safe ordering should be explicit: tokenize raw query components on raw separators first; retain exact byte spans; then decode each individual key/value solely for matching. Never let decoded %26 or %3B create structural separators.

There are also stale contradictory statements in the same section: the residual still talks about raw-byte matching with & as the only separator, while v2.1.4 says normalized matching with &/;; and the registry simultaneously says “no decoding” and “MATCH on a normalized copy.” This is exactly the kind of contradiction two different implementations will resolve differently.

HIGH — the remote-ruleset model still contains mutually incompatible security contracts.
§9 first normatively specifies a mandatory package-embedded hash, which necessarily freezes the list, then says Gosub adopts model C where the store/catalog can approve new hashes at runtime. The registry still says sources+hash, “hash-pinned in package.” Those are models A and C simultaneously.

There is also an anti-freeze problem with C: a compromised list server cannot supply different accepted bytes, but it can selectively withhold the newly approved revision from particular clients. If the browser continues using the old list, the distributor still obtains per-user policy influence through targeted staleness. Either the catalog/store needs to distribute the immutable object itself/mirror it, or there needs to be a freshness/minimum-revision rule.

And §11 now says no runtime channel can change filtering “between authenticated extension updates,” while model C intentionally updates filter lists without an extension-package update. The intended guarantee is probably: “Neither the extension publisher nor list server can choose a per-user ruleset; filtering changes only through authenticated package updates, browser updates, or globally approved catalog revisions.”

HIGH/MEDIUM — §5's formal label vocabulary is not actually the vocabulary used by the registry.
§5 gives apparently closed enums for sources, sinks, command sources and actuators. But §19 subsequently uses sink: probe, source: history, aggregate-history, page-derived, download_urls, user_text, browser_traffic, plus command-source: native_process and enterprise_policy; publisher_update appears elsewhere too.

That matters because the closure is the security mechanism. If download_urls isn't in the source lattice, what does download_urls × arbitrary_network become? The prose says new capabilities should compose automatically, but an open-ended set of undocumented atoms does not give you that property.

I’d make the label algebra an actual schema/type system and have the registry mechanically validated against it.

MEDIUM/HIGH — cookies.write is missing both a sink and a command actuator dimension.
It is currently only described as I:high / loud. But writing an arbitrary cookie for a scoped host creates bytes which the browser will subsequently emit to that host in a Cookie header. That's a delayed outbound channel. A source can therefore be encoded into cookie state and later transmitted without cookies.read.

More importantly for axis 2, network.egress_public(c2) + cookies.write(bank.example) lets a remote server instruct an extension to change login/session state at another site. You probably need a session_state/credentials_state actuator in addition to dom/navigation/browser_ui/os.

MEDIUM/HIGH — host scope must explicitly be rechecked at redirects, not merely address-space class.
§15 correctly says DNS/address-space policy is checked on every redirect hop and the connected SocketAddr is the checked address. But it doesn't explicitly say the capability's canonical host/origin scope is re-authorized at each redirect target. If network.egress_public(["api.allowed.example"]) follows api.allowed.example/redirect → collector.evil.example, then an “own host” grant has become arbitrary public egress.

I would state the redirect invariant explicitly: every hop repeats both capability_scope_allows(canonical_origin) and address_space_allows(resolved_socketaddr).

There are also a few documentation defects I would fix immediately because they can turn into implementation bugs. O3 still says “write-target denylist” even though v2.1.4 explicitly replaced it with an allowlist, and the registry itself contains both statements in adjacent lines. Also, the permission text has slipped back from effect into intent: “Remove tracking parameters” is not an honest description of a capability that can delete state, CSRF tokens, signatures, or any arbitrary query parameter—the document itself explicitly acknowledges that the browser cannot distinguish them. The same goes for “Block ads and trackers”: filtering.block grants the ability to block arbitrary matching resources, not an enforceable semantic category called “ads.”

The three things I would fix first for v2.1.5 are therefore: make readable egress a command-source in its own right; make every artifact consumer re-authorize semantic capability/scope independently of the compromised compiler; and replace the scriptlet byte-provenance claim with a real non-interference rule covering control dependencies. Those are the ones that can currently make the derived-authority dialog materially false.