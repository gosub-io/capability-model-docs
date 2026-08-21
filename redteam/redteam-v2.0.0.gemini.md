# Red-Team Assessment: Gosub Extension Capability Model (v2.0)

Version 2.0 addresses major v1 vulnerabilities by introducing a formal composition model ($\text{source} \times \text{sink}$), scope parameterization, sealed `memfd` rule handovers, and static-only redirect targets. However, shifting the security model to a state-based capability engine creates a new set of threat vectors.

Below is an adversarial red-team assessment of the v2 specification across five critical operational vectors.

---

### Threat Vector 1: Composition Bypass & Source/Sink Mislabeling

```text
               ┌─────────────────────────────────────────────────────────┐
               │              Compromised Extension Worker               │
               └──────────────┬───────────────────────────┬──────────────┘
                              │                           │
  [SOURCE: None]              │                           │             [SINK: Own Hosts]
  filtering.dynamic_rules ◄───┘                           └───► network.fetch_public
                              │                                 (api.attacker.example)
                              ▼
               ┌──────────────────────────────────────────┐
               │    Baleen Dynamic Engine (Sonar Core)    │
               └────────────────────┬─────────────────────┘
                                    │ Memory Contention / Cache Latency
                                    ▼
               ┌──────────────────────────────────────────┐
               │    Local Timing Observer (CPU Clock)     │
               └──────────────────────────────────────────┘

```

#### 1.1 `filtering.dynamic_rules` as an Unlabeled Implicit Source

* **Vulnerability:** In §5 and §19, `filtering.dynamic_rules` is labeled with `sink: probe`. However, it acts as an **implicit source** when combined with any outbound network channel.


* **Attack Path:**
1. An extension requests `filtering.dynamic_rules` (standard) and `network.fetch_public(["api.attacker.example"])` (standard). Under §5, the composition engine checks labels: `source: none` $\times$ `sink: own_hosts`, resulting in **no derived warning**.


2. The extension installs a dynamic rule matching a high-value URL segment (`||target-bank.example/authenticated/user^`).


3. Rather than reading `stats.read` (which is quantized/degraded), the worker executes a high-precision `performance.now()` loop while issuing requests to `api.attacker.example`.


4. When the user navigates to `target-bank.example`, Sonar's dynamic hash-table lock or matching step introduces microsecond-level thread contention on the CPU. The worker measures this latency delta and exfiltrates the hit over `network.fetch_public`.




* **Impact:** Browsing history exfiltration without triggering a `derived: history.exfiltration` warning.


* **Remediation:** Label `filtering.dynamic_rules` as `source: implicit_history` whenever dynamic rules can be registered post-installation.

#### 1.2 `forms.fill` Data-Leak via Speculative DOM State

* **Vulnerability:** §19 defines a mediated autofill flow where the extension never holds page inputs: credentials move directly from storage to the origin via a privileged channel.


* **Attack Path:**
1. A malicious extension holds `forms.fill` (standard) and `network.fetch_public`.


2. It generates hundreds of distinct fake credential candidate items via the browser's UI callback (e.g., `User_Variant_1`, `User_Variant_2`).
3. When the user selects a candidate from the native UI dropdown, the privileged channel fills the exact DOM node.
4. The host page (if compromised or controlled by an attacker via cross-site injection) reads the autofilled value and signals the extension worker via an external channel, or the extension monitors DOM layout shift side-effects via mid-tier CSS APIs (`styles.read`).




* **Remediation:** `forms.fill` must enforce a strict rate limit on candidate generation per tab, and candidate payloads must be opaque handles until user confirmation in the native UI.

---

### Threat Vector 2: IPC, Memory, and Baleen Artifact Attacks

#### 2.1 Deserialization Logic Bombs in the Baleen Validator

* **Vulnerability:** §14 mandates that Sonar and Renderer processes validate incoming read-only `memfd` artifacts for offset and bounds safety before mmapping.


* **Attack Path:**
1. A compromised compiler process crafts a valid `memfd` artifact containing extreme pointer arithmetic: a state graph where node transitions point to overlapping memory offsets within the valid mapped byte range.


2. The validator verifies that all pointers lie inside `[0, buffer_len]`, marking the artifact as safe.


3. When Sonar processes an incoming HTTP request, the Baleen matching loop enters an infinite pointer loop within the sealed buffer.




* **Impact:** Process-level Denial of Service (DoS) in Sonar (blocking all network traffic for the browser) without violating `memfd` seals or memory bounds.


* **Remediation:** The Baleen validator must enforce Directed Acyclic Graph (DAG) invariants or execution step caps during the validation pass before handing the table to Sonar.



#### 2.2 Re-entrancy & Epoch Mismatches in Cross-Document `activeTab` Binding

* **Vulnerability:** §13 binds `content_script.active_tab` to `(tab_id, frame_id, document_id, navigation_epoch, origin)`.


* **Attack Path:**
1. An attacker triggers an `activeTab` gesture on `attacker.example`.


2. The worker issues an asynchronous sequence of cross-document IPC execution commands to the Broker.


3. Simultaneously, `attacker.example` triggers an immediate top-level navigation to `victim-bank.example`.
4. If the Broker checks capability against `document_id_A` on thread 1, but the Renderer process context-switches to `document_id_B` before evaluating the incoming execution script payload on thread 2, a race condition occurs if `document_id` revocation messages arrive out of order via IPC.


* **Remediation:** Execution payloads must carry the target `document_id` directly inside the payload signature; the renderer context must drop the execution frame locally if its active `document_id` does not match the payload parameter.

---

### Threat Vector 3: Network Layer (Sonar) & Header Manipulation

```text
┌─────────────────────────────────────────────────────────────┐
│                       Sonar Engine                          │
│                                                             │
│  Incoming Response: Set-Cookie: session=xyz; SameSite=Strict│
│                                                             │
│  [ Bypasses Protected List ]                                │
│  filtering.headers.response.set_safe ───────────────────────┼──► Inject: "Custom-Header: \r\nSet-Cookie: session=evil"
└─────────────────────────────────────────────────────────────┘

```

#### 3.1 HTTP Header Splitting via "Safe-Listed" Header Injection

* **Vulnerability:** §15 restricts header modification by explicitly protecting `Cookie`, `Set-Cookie`, `Host`, and `Origin` from arbitrary rewrite. It exposes `filtering.headers.response.set_safe` for safe headers.


* **Attack Path:**
1. An extension with `filtering.headers.response.set_safe` targets a site.


2. It injects a string containing unescaped CRLF sequence characters into a benign header value:
   `X-Custom-Header: safe_value\r\nSet-Cookie: malicious_session=123; Domain=victim.example`
3. If Sonar's header parser converts structured rule representations into raw HTTP response bytes without enforcing strict ASCII token validation (`\r` / `\n` stripping), forbidden headers are injected indirectly.


* **Remediation:** Header values injected via `filtering.headers.*` must be validated against RFC 9110 field-value character sets before passing to Sonar's stream writer.



#### 3.2 DNS-Rebinding Race Condition in Per-Hop SSRF Checks

* **Vulnerability:** §15 specifies that Sonar re-checks IP destinations on every DNS resolution and redirect hop to prevent SSRF (`network.fetch_public` blocking `127.0.0.1` / RFC 1918).


* **Attack Path:**
1. Extension worker calls `fetch("[https://rebind.attacker.example](https://rebind.attacker.example)")`.


2. Sonar resolves `rebind.attacker.example` $\rightarrow$ `1.2.3.4` (Public IP) with `TTL=0`. Per-hop check succeeds.


3. Between the DNS check and the socket `connect()` call, local OS socket caching or a multi-threaded socket pool re-resolves `rebind.attacker.example`, obtaining `127.0.0.1` (TOCTOU).


* **Remediation:** Sonar must bind explicitly to the verified `SocketAddr` returned by its internal DNS lookup rather than re-resolving by hostname at socket creation.

---

### Threat Vector 4: Subversion of Translation & Manifest Semantics

#### 4.1 Scope Pollution via IPv6 / Canonical Host Patterns

* **Vulnerability:** §18 states that host permissions map to scopes (e.g., `content_script(hosts)`).


* **Attack Path:**
1. An extension manifest declares a host pattern in standard notation: `[https://[0:0:0:0:0:0:0:1]/](https://[0:0:0:0:0:0:0:1]/)`.
2. The Manifest Translator normalizes this as a string literal matching `[0:0:0:0:0:0:0:1]`.


3. At runtime, when checking scope for a fetch to `https://localhost/` or `[https://[::1]/](https://[::1]/)`, an inconsistency between the translator's canonicalizer and Sonar's URI parser allow requests to bypass private network checks or claim scope equivalence over ungranted origins.




* **Remediation:** All host pattern scopes must translate into canonical `eTLD+1` / IP representations using a single shared normalization crate (`url` / `addr`) before grant generation.



#### 4.2 `activeTab` Persistence via Embedded Subframes

* **Vulnerability:** `content_script.active_tab` persists across `pushState` on the top-level document until cross-document navigation.


* **Attack Path:**
1. User clicks the action button on `main-site.example`, granting `activeTab` to the top frame.


2. The extension injects a script that creates a hidden cross-origin `<iframe>` pointing to `attacker.example` or an `about:blank` frame.
3. Even if the top-level page navigates away, the injected subframe maintains its execution context or hooks `window.onbeforeunload` to delay frame destruction, executing background logic under the original active tab handle.



---

### Threat Vector 5: Engine/Embedder Trust Boundaries

#### 5.1 Asynchronous Revocation Window Race

* **Vulnerability:** §13 states that revocation is a table update broadcasted across processes.


* **Attack Path:**
1. A user revokes access for an extension on `sensitive-site.example` via the UA interface.


2. The UA sends `revoke(extension, scope)` to the Engine.


3. The Broker receives the command and queues a Baleen table update.


4. Concurrently, an extension worker process floods the Broker with thousands of rapid `content_script` injection commands.


5. If the IPC queue prioritizes worker requests over internal control messages, worker commands execute on `sensitive-site.example` during the propagation delay window.


* **Remediation:** Control plane messages (revocations, scope reductions) must use high-priority out-of-band channels in the Broker IPC, bypassing standard worker event loops.

---

### Assessment Matrix & Architectural Recommendations

| Threat Vector | Severity | Target System | Fundamental Vulnerability | Required Fix |
| --- | --- | --- | --- | --- |
| **1.1 Dynamic Rules** | **High** | Composition Engine | Side-channel timing oracle bypasses `source: none`<br> | Label `filtering.dynamic_rules` as an implicit history source.

|
| **2.1 Baleen Validator** | **High** | Baleen Core / Sonar | Cyclic pointer graph causes unbounded loop in parser | Enforce DAG validation pass on `memfd` artifacts before mmap.

|
| **3.1 Header Injection** | **Critical** | Sonar Network Engine | CRLF injection via safe-listed header primitives

| Strict ASCII field-value sanitization on header updates.

|
| **3.2 SSRF Re-binding** | **High** | Sonar Socket Manager | TOCTOU between DNS resolution and socket connection

| Bind sockets strictly to resolved `SocketAddr` structures.

|
| **5.1 Revocation Window** | **Medium** | Broker / IPC | Event-loop queuing delays table updates

| Prioritize control messages over standard worker IPC. |