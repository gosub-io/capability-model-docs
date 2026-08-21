Yes. This pass found a few things I’d consider genuine v2.1.9 candidates. The most interesting one is not another scriptlet problem—it is that the model still treats some **filter-controlled changes to existing network traffic as if they were not information sinks**.

1. **HIGH — Header filtering creates an unmodelled history-exfiltration channel.** The filtering engine may predicate on the initiator origin and request URL/header state, while standard-tier capabilities may modify safe request headers.   Consider a rule applying to requests to `collector.publisher.example`: if the initiator is `sensitive.example`, set or remove some permitted header. The publisher's server now learns whether the request came from `sensitive.example`. No `network.observe`, `stats.read`, worker-readable feedback, or extension egress response is required. The **filter itself acquired an initiator/history predicate and encoded it into externally visible traffic**.

   This exposes a weakness in the §5 definition. A sink is currently described primarily as something that can *cause a network-producing effect*.  But altering an already-existing outbound message is just as much an information sink. In fact, the document already half-recognizes this for `rewrite_url`: it says the destination server can observe stripping and that same-publisher destinations produce an implicit-history-flavored channel, while still assigning `source:none, sink:none`.

   I would change the abstraction rather than special-case headers. Something like **externally observable outbound mutation = sink**. Then filter predicates involving initiator/history-sensitive state are sources. Alternatively, standard-tier header mutations must not be conditional on initiator/page-derived predicates. This is the strongest new model-level issue I found.

2. **HIGH — `dom.declarative_actions` repeats the scriptlet transitive-effect mistake.** The registry makes `dom.declarative_actions` standard because it exposes a fixed semantic vocabulary such as `dismiss_consent`, `expand`, and `collapse`, rather than generic clicking.  But §8 just spent several revisions establishing that a restricted primitive is not safe merely because its *direct* action looks constrained: changing a harmless-looking property can cause page code to make a network request, set state, navigate, etc. That is why scriptlets now require a **transitive-effect proof**.

   The same argument applies here. A page can implement “dismiss consent” such that the state change causes `sendBeacon()`, enables trackers, submits something, or navigates. Naming the operation semantically does not establish its effect. I would either require the same per-operator transitive-effect proof as scriptlets, or split these into truly passive browser-owned UI transformations versus actions that participate in page behavior. The latter should remain loud unless their consequences can actually be bounded.

3. **HIGH — `tabs.organize` is missing an actuator, creating an Axis-2 false negative.** §5 explicitly says observable effect matters and "`only organizes`" is not an exemption. It also says every actuator-bearing capability must carry an actuator label.  Yet `tabs.organize` is simply listed as `close/move/group — no sink`, with no actuator.

   “No sink” is correct, but “no actuator” is not. A remotely commanded extension with egress plus `tabs.organize` can close the user's tabs, continually regroup them, move them, and generally alter browser state. That is precisely what Axis 2 was introduced to catch. At minimum this should be `actuator: browser_ui`; I might introduce a more precise `tab_state` or `browser_state` actuator because closing tabs is also availability power. Then `remote_server × tab_state` derives a remote browser-control warning.

4. **HIGH — `network.proxy_control` does not actually type-check against the supposedly closed algebra.** The authoritative sink enum contains `own_hosts`, `arbitrary_network`, `probe`, `native_host`, `user_scripts`, and `session_state`; the source enum contains `browser_traffic`.  But the proxy registry entry says `source: implicit_history + sink: arbitrary_network`, then derives:

   `browser_traffic × publisher_proxy -> traffic.exfiltration`

   `publisher_proxy` is not a sink atom in the declared algebra, and `browser_traffic` is not the source actually assigned to the entry.

   That's directly at odds with the claim that the structured registry is build-validated and that every product is defined. Either the machine-readable registry differs from this prose—in which case this isn't really its faithful rendering—or the build validator should reject it. I think proxying probably deserves an explicit effect type because it sends **all browser traffic through a publisher-selected observation point**, which is stronger than ordinary `arbitrary_network`.

5. **HIGH implementation-spec contradiction — §19 still tells implementors to fail open on stale remote rules.** v2.1.8 correctly says that after max-age the browser keeps the last accepted rules, visibly marks them stale, retries mirrors, and eventually flags the extension degraded. It explicitly explains that rejecting stale rules gives the withholding attacker exactly the fail-open behavior they want.

   But the authoritative registry still says:

   `freshness max-age, reject on hash mismatch or stale`



This one should be fixed immediately because the contradiction sits exactly where an implementor is likely to copy behavior from. It should say roughly: reject hash/signature mismatch; **retain last accepted revision on freshness failure**, surface stale state, retry independent distribution, then flag degraded after bounded grace.

6. **MEDIUM — `rewrite_url`'s registry accidentally reintroduces the encoded-tracker bug.** §6 is now precise: split on raw `&`, then decode each token **once for comparison**, while emission always splices the untouched original bytes. That's what makes `%66bclid` match `fbclid` without letting decoding alter the emitted URL.

   The registry, however, says “raw-byte or linear-time-regex matching, **no decoding** or re-serialization” and then a few lines later says matching occurs on a normalized copy.  An implementor following the first sentence recreates the exact evasion v2.1.4 fixed. I would replace it with an explicit compact formulation: **raw separator tokenization → exactly one decode for matching → splice original bytes for emission**.

7. **MEDIUM/HIGH — `forms.fill` has real integrity authority but no actuator.** The registry makes `forms.fill` standard and emphasizes the good confidentiality properties: browser-managed origin-bound credential store, opaque candidate handles, rate limiting, renderer document revalidation.  Those prevent the extension from *reading* the secret. They do not make filling inert.

   Filling a credential form modifies the DOM and can cause page code to react, authenticate, auto-submit, update session state, or issue network requests. Yet there is no `actuator` on `forms.fill`, despite the claim that every capability able to drive an effect has one.  If filling always requires a fresh browser-owned user gesture and the extension cannot choose the credential, that may block meaningful remote control—but that requirement needs to be stated on `forms.fill`, not inferred from the separate `forms.detect_credentials` entry. Otherwise `egress + forms.fill` currently escapes Axis 2.

8. **MEDIUM/HIGH — `isolated_network` can be bypassed through page-mediated egress unless the private capability matrix forbids the relevant page powers.** `isolated_network` promises isolation plus “no network egress in private.”  The new v2.1.8 initiator rule, however, explicitly says that if extension code changes the page and the **page's own code** subsequently makes a request, that request remains page traffic, not extension-principal traffic.

   So an isolated private content script can, for example, place extension-derived state somewhere a cooperating page reads; page JS then sends it to the publisher. Sonar sees a page request and does not apply the extension's no-egress restriction. This is the same causal-laundering problem the scriptlet section now understands very well. Content scripts inherently share the DOM and have network-capable effects.  Either `isolated_network` must deny page-write/main-world capabilities capable of such movement, or its guarantee needs to be narrowed to “no **extension-principal** network requests.” As written, “no network egress” is stronger than what §15 enforces.

One additional specification-hardening item: §15 explicitly exposes response-header/CSP hook points, but the actual **modifiable header allowlist is not enumerated here**; instead the text enumerates several engine-controlled headers.  Given how important CSP, Permissions-Policy, COOP/COEP/CORP, X-Frame-Options, cache/security headers, etc. can be, I would make the safe list positively enumerated and versioned. This document has repeatedly established that allowlists are safer than trying to maintain an open-ended denylist; headers deserve the same treatment.

Overall, **#1 is the finding I would consider the new load-bearing red-team result**. It suggests the information-flow model's definition of “sink” is still slightly too network-creation-centric. A filter does not have to create a request to exfiltrate information; it can encode information into a request the page was already going to make. #2, #3, and #4 are then closure/typing holes that fall naturally out of applying the document's own newer reasoning consistently. #5 and #6 look more like stale prose, but both are dangerous stale prose because they reverse security fixes.

The good news is that I did **not** find a comparable fresh break in the new cookie-scope algebra, publisher-principal definition, grant-envelope/artifact separation, or the v2.1.8 navigation-scheme correction during this pass. The remaining problems are now mostly cases where one section has developed a stronger security principle than the rest of the registry has caught up with.
