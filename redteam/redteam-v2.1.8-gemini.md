Here is a structural red-team analysis of the Gosub Extension Capability Model (v2.1.8), focusing on theoretical limits, unmitigated edge cases, and architectural friction points.

## Transitive Proof Undecidability

* The model admits that a vocabulary-safe write can still trigger a transitive page gadget, which qualifies as a sink.


* To resolve this, the model requires semantic non-interference proofs generated at library-build time, which are carried as machine-checkable artifacts.


* Proving transitive non-interference across arbitrary, dynamically typed page environments is theoretically impossible (Rice's Theorem). A safe scriptlet write could trigger a complex getter/setter chain dynamically defined by a modern SPA framework, creating unpredictable sinks that no static build-time proof can fully encompass.

## Egress Boundary Evasion

* Sonar applies the extension egress policy to network-producing operations attributable to an extension, explicitly including fetches, DOM-created nodes, websockets, beacons, and CSS URLs.


* Advanced network APIs handling UDP or peer-to-peer routing (like WebRTC ICE candidate gathering or WebTransport) often bypass standard HTTP-centric pipeline chokepoints. If Sonar misses these underlying native sockets, an extension could establish a covert side-channel.
* The model explicitly restricts response body matching from the network filter path, though capabilities like `devtools.network` or `content_handler` can access them. Highly privileged extensions could theoretically abuse timing discrepancies in body-parsing capabilities to leak filter-path states.



## The Staleness Grace Window

* Remote rulesets operate under Model C, where the browser checks a catalog-signed hash and freshness max-age.


* To prevent a "fail open" scenario, the browser retains stale rules past their max-age, surfaces a UI warning, and allows a bounded grace window before flagging the extension.


* An attacker compromising the catalog mechanism could weaponize this exact fail-safe. By intentionally withholding updates from specific clients, they can lock users into a known-vulnerable filter state for the entirety of the bounded grace window while the browser explicitly sanctions the downgrade.

## Revocation Race Conditions

* Revocation triggers control-plane messages that pre-empt the worker event loop.


* Operations are tagged with a grant epoch and re-checked at a defined commit point, but effects externally committed before the epoch changes are irreversible.


* A malicious worker anticipating revocation (e.g., via side-channels detecting user UI interaction) could intentionally queue massive, parallel exfiltration payloads. Any bytes committed to the wire milliseconds before the epoch boundary successfully bypass the revocation mechanism.

How does the Gosub engine plan to handle the undecidability of transitive gadget proofs in highly dynamic, framework-heavy page environments where static analysis breaks down?