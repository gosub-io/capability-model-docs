import json, os
# Portable paths. Reads the intermediate data.json produced by build_data.py
# (next to these scripts) and writes the viewer to OUT_DIR (default: the parent
# of this tooling folder, i.e. alongside the specs). Override with OUT_DIR.
HERE = os.path.dirname(os.path.realpath(__file__))
OUT_DIR = os.environ.get("OUT_DIR", os.path.dirname(HERE))
DATA = json.load(open(os.path.join(HERE, "data.json"), encoding="utf-8"))
payload = json.dumps(DATA, ensure_ascii=False)

CSS = r"""
:root{
  --ground:#fbfcfd; --surface:#ffffff; --surface-2:#f3f6f8;
  --ink:#1a2027; --muted:#586470; --faint:#8b98a4; --border:#e3e9ee; --border-2:#eef2f5;
  --accent:#0e7c86; --accent-strong:#0a5f68; --accent-ink:#ffffff;
  --tint:#e9f6f5; --tint-border:#bfe4e2; --tint-ink:#0b4a4f;
  --code-bg:#f2f5f7; --code-ink:#243039;
  --shadow:0 1px 2px rgba(20,30,40,.04),0 8px 24px rgba(20,30,40,.06);
}
@media (prefers-color-scheme:dark){ :root:not([data-theme="light"]){
  --ground:#0d1316; --surface:#131b20; --surface-2:#18242a;
  --ink:#e7eef2; --muted:#9fb0ba; --faint:#697a84; --border:#233139; --border-2:#1c272d;
  --accent:#40c1c7; --accent-strong:#63d4d9; --accent-ink:#06222a;
  --tint:#0f262a; --tint-border:#1d4045; --tint-ink:#9fe3e2;
  --code-bg:#0f1a1f; --code-ink:#cfe0e6;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
}}
:root[data-theme="dark"]{
  --ground:#0d1316; --surface:#131b20; --surface-2:#18242a;
  --ink:#e7eef2; --muted:#9fb0ba; --faint:#697a84; --border:#233139; --border-2:#1c272d;
  --accent:#40c1c7; --accent-strong:#63d4d9; --accent-ink:#06222a;
  --tint:#0f262a; --tint-border:#1d4045; --tint-ink:#9fe3e2;
  --code-bg:#0f1a1f; --code-ink:#cfe0e6;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto} *{transition:none!important;animation:none!important}}
body{margin:0;background:var(--ground);color:var(--ink);
  font:15.5px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
.mono{font-family:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}

.topbar{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--ground) 88%,transparent);
  backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--border)}
.topbar-in{max-width:1280px;margin:0 auto;display:flex;align-items:center;gap:18px;padding:12px 22px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;margin-right:auto}
.brand .logo{font-size:20px;line-height:1}
.brand h1{font-size:15px;font-weight:650;letter-spacing:-.01em;margin:0}
.brand .sub{font-size:11px;color:var(--faint);letter-spacing:.06em;text-transform:uppercase}
.ctl{display:flex;align-items:center;gap:8px}
.field{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border);
  border-radius:9px;padding:5px 10px;box-shadow:var(--shadow)}
.field label{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
select#ver{appearance:none;border:0;background:transparent;color:var(--ink);
  font:600 13px/1 ui-monospace,Menlo,monospace;padding-right:16px;cursor:pointer;outline:none}
.field.selwrap{position:relative}
.field.selwrap::after{content:"\25BE";position:absolute;right:10px;color:var(--faint);pointer-events:none;font-size:11px}
button.btn{border:1px solid var(--border);background:var(--surface);color:var(--muted);cursor:pointer;
  border-radius:9px;padding:7px 11px;font:600 12px/1 ui-sans-serif,system-ui,sans-serif;box-shadow:var(--shadow);
  display:inline-flex;align-items:center;gap:7px;transition:color .15s,border-color .15s,background .15s}
button.btn:hover{color:var(--ink);border-color:var(--accent)}
button.btn[aria-pressed="true"]{color:var(--accent-ink);background:var(--accent);border-color:var(--accent)}
button.btn:focus-visible,select:focus-visible,summary:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

.shell{max-width:1280px;margin:0 auto;display:grid;grid-template-columns:262px minmax(0,1fr);gap:34px;padding:0 22px}
@media (max-width:900px){.shell{grid-template-columns:1fr;gap:0}.rail{display:none}}
.rail{position:sticky;top:61px;align-self:start;height:calc(100vh - 61px);overflow:auto;padding:22px 4px 40px 0}
.rail::-webkit-scrollbar{width:8px}.rail::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}
.toc-group{font:600 10.5px/1 ui-monospace,Menlo,monospace;letter-spacing:.11em;text-transform:uppercase;
  color:var(--faint);margin:20px 0 8px 12px}
.toc-group:first-child{margin-top:2px}
.toc a{display:flex;gap:9px;align-items:baseline;padding:5px 12px;border-radius:8px;color:var(--muted);
  font-size:13px;line-height:1.35;border-left:2px solid transparent}
.toc a .n{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--faint);min-width:22px;text-align:right}
.toc a:hover{background:var(--surface-2);color:var(--ink);text-decoration:none}
.toc a.active{color:var(--accent);background:var(--tint);border-left-color:var(--accent);font-weight:600}
.toc a.active .n{color:var(--accent)}
.toc a.sub{padding:3px 12px 3px 30px;font-size:12px;color:var(--faint);line-height:1.3}
.toc a.sub::before{content:"";flex:0 0 auto;width:4px;height:4px;border-radius:50%;background:currentColor;opacity:.5;align-self:center}
.toc a.sub:hover{color:var(--ink)}
.toc a.sub.active{color:var(--accent);background:var(--tint);border-left-color:var(--accent);font-weight:600}

.content{padding:30px 0 120px;min-width:0}
.vhead{margin:0 0 8px}
.vhead .kick{font:600 11px/1 ui-monospace,Menlo,monospace;letter-spacing:.1em;text-transform:uppercase;color:var(--accent)}
.vhead h2{font-size:30px;letter-spacing:-.02em;margin:8px 0 4px;text-wrap:balance;font-weight:700}
.vhead .vlabel{color:var(--muted);font-size:14px}
.vhead .vlabel b{color:var(--ink);font-weight:600}
details.preface{margin:16px 0 8px;border:1px solid var(--border);border-radius:12px;background:var(--surface);overflow:hidden}
details.preface>summary{cursor:pointer;list-style:none;padding:12px 16px;display:flex;align-items:center;gap:10px;
  font:600 12px/1 ui-sans-serif,system-ui,sans-serif;color:var(--muted)}
details.preface>summary::-webkit-details-marker{display:none}
details.preface>summary .chev{color:var(--faint);transition:transform .2s;font-size:12px}
details.preface[open]>summary .chev{transform:rotate(90deg)}
details.preface .body{padding:2px 18px 16px;border-top:1px solid var(--border-2);color:var(--muted);font-size:13.5px;max-height:340px;overflow:auto}

hr.vrule{border:0;border-top:1px solid var(--border);margin:26px 0}

section.sec{scroll-margin-top:74px;padding:8px 0 4px}
.sec-eyebrow{font:600 11px/1 ui-monospace,Menlo,monospace;letter-spacing:.09em;text-transform:uppercase;color:var(--faint);
  display:flex;align-items:center;gap:9px;margin-bottom:7px}
.sec-eyebrow .part{color:var(--accent)}
h3.sec-title{font-size:22px;letter-spacing:-.015em;margin:0 0 2px;font-weight:680;text-wrap:balance;scroll-margin-top:74px}

details.plain{margin:12px 0 4px;border:1px solid var(--tint-border);background:var(--tint);border-radius:11px;overflow:hidden}
details.plain>summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:9px;padding:9px 14px;
  font:600 11px/1 ui-monospace,Menlo,monospace;letter-spacing:.07em;text-transform:uppercase;color:var(--tint-ink)}
details.plain>summary::-webkit-details-marker{display:none}
details.plain>summary .chev{transition:transform .2s;font-size:11px}
details.plain[open]>summary .chev{transform:rotate(90deg)}
details.plain>summary .tag{margin-left:auto;font-size:9.5px;letter-spacing:.1em;opacity:.7;font-weight:600}
details.plain .body{padding:4px 16px 14px;border-top:1px solid var(--tint-border)}
details.plain .body :is(p,li){font-size:14px;line-height:1.6;color:var(--tint-ink)}
:root[data-theme="dark"] details.plain .body :is(p,li){color:var(--ink)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) details.plain .body :is(p,li){color:var(--ink)}}

.prose{color:var(--ink)}
.prose>*:first-child{margin-top:8px}
.prose p{margin:.7em 0}
.prose :is(h2,h3,h4){font-weight:650;letter-spacing:-.01em;margin:1.4em 0 .5em;line-height:1.3}
.prose h2{font-size:19px} .prose h3{font-size:16.5px} .prose h4{font-size:14.5px;color:var(--muted)}
.prose strong{font-weight:670;color:var(--ink)}
.prose blockquote{margin:1em 0;padding:.5em 1em;border-left:3px solid var(--accent);background:var(--surface-2);
  border-radius:0 8px 8px 0;color:var(--ink)}
.prose blockquote p{margin:.3em 0}
.prose ul,.prose ol{padding-left:1.35em;margin:.7em 0}
.prose li{margin:.34em 0}
.prose li::marker{color:var(--faint)}
.prose code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.86em;background:var(--code-bg);
  color:var(--code-ink);padding:.12em .38em;border-radius:5px;border:1px solid var(--border-2)}
.prose pre{margin:1em 0;background:var(--code-bg);border:1px solid var(--border);border-radius:10px;
  padding:14px 16px;overflow-x:auto;color:var(--code-ink)}
.prose pre code{background:none;border:0;padding:0;font-size:12.6px;line-height:1.55;color:inherit}
/* mermaid: before render it's readable source; after render it's a centered diagram */
.prose pre.mermaid{white-space:pre;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted)}
.prose pre.mermaid:not([data-processed]){position:relative;padding-top:26px}
.prose pre.mermaid:not([data-processed])::before{content:"diagram (source)";position:absolute;top:7px;left:14px;
  font:600 9.5px/1 ui-monospace,monospace;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.prose pre.mermaid[data-processed]{background:none;border:0;padding:8px 0;overflow-x:auto;text-align:center;
  display:flex;justify-content:center}
.prose pre.mermaid[data-processed] svg{max-width:100%;height:auto}
.tablewrap{overflow-x:auto;margin:1em 0}
.prose table{border-collapse:collapse;width:100%;font-size:13px}
.prose th,.prose td{border:1px solid var(--border);padding:7px 11px;text-align:left;vertical-align:top}
.prose th{background:var(--surface-2);font-weight:650;font-size:11.5px}
.prose tr:nth-child(even) td{background:color-mix(in srgb,var(--surface-2) 45%,transparent)}
.prose hr{border:0;border-top:1px solid var(--border);margin:1.6em 0}
.prose.secbody>h3{margin-top:2em;padding-top:1.2em;border-top:1px solid var(--border-2);scroll-margin-top:78px;
  font-size:17px;color:var(--ink);display:flex;align-items:baseline;gap:9px}
.prose.secbody>h3::before{content:"\00B6";font:600 12px/1 ui-monospace,Menlo,monospace;color:var(--accent);opacity:.6}
.prose.secbody>h3:first-child{border-top:0;padding-top:0;margin-top:1em}
.prose.secbody>details.subplain{margin:10px 0 8px}
.prose a{border-bottom:1px solid transparent}.prose a:hover{border-bottom-color:var(--accent);text-decoration:none}

.footer{max-width:1280px;margin:0 auto;padding:26px 22px 50px;color:var(--faint);font-size:12px;
  border-top:1px solid var(--border);display:flex;gap:14px;flex-wrap:wrap;align-items:center}
.badge{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--muted);background:var(--surface);
  border:1px solid var(--border);border-radius:20px;padding:3px 11px}
"""

HTML = r"""<title>Gosub Capability Model</title>
<style>__CSS__</style>
<div class="topbar"><div class="topbar-in">
  <div class="brand"><span class="logo">\U0001F40B</span>
    <div><h1>Gosub Capability Model</h1><div class="sub">Extension capability specification</div></div>
  </div>
  <div class="ctl">
    <div class="field selwrap"><label for="ver">Version</label><select id="ver" title="Select documentation version"></select></div>
    <button class="btn" id="expand" aria-pressed="false" title="Expand every plain-language translation">
      <span id="expandLabel">Plain language</span></button>
    <button class="btn" id="theme" title="Toggle theme"><span id="themeIcon">◐</span></button>
  </div>
</div></div>

<div class="shell">
  <nav class="rail"><div class="toc" id="toc"></div></nav>
  <main class="content" id="content"></main>
</div>
<div class="footer">
  <span class="badge" id="fver">v-</span>
  <span>Official specification language, with plain-language translations from <span class="mono">guide-v2</span>.</span>
  <span style="margin-left:auto" id="fcount"></span>
</div>

<script>__MERMAID__</script>
<script id="data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById('data').textContent);
const $ = s => document.querySelector(s);
const el = (t,c,h)=>{const e=document.createElement(t); if(c)e.className=c; if(h!=null)e.innerHTML=h; return e;};
function enhance(node){node.querySelectorAll('table').forEach(t=>{
  if(t.parentElement.classList.contains('tablewrap'))return;
  const w=el('div','tablewrap'); t.parentNode.insertBefore(w,t); w.appendChild(t);}); return node;}

let CUR=null;
const verSel=$('#ver');
DATA.versions.forEach(v=>{const o=el('option'); o.value=v.ver; o.textContent=v.ver; verSel.appendChild(o);});
verSel.value=DATA.versions[DATA.versions.length-1].ver;

function slug(s){return s.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'')}
function sig(t){t=t.toLowerCase();
  for(const k of ["axis 1","axis 2","principal","derived","effect","namespace"]){
    if(t.includes(k)) return (k==="namespace"?"effect":k).replace(/ /g,"");}
  return t.replace(/[^a-z0-9]+/g,"").slice(0,16);}
function plainDetails(gh){const d=el('details','plain');
  d.innerHTML='<summary><span class="chev">›</span><span>Plain language</span><span class="tag">guide-v2</span></summary><div class="body prose">'+gh+'</div>';
  return enhance(d);}

function render(ver){
  const v=DATA.versions.find(x=>x.ver===ver); CUR=v;
  const c=$('#content'); c.innerHTML=''; const toc=$('#toc'); toc.innerHTML='';
  $('#fver').textContent=v.ver;
  $('#fcount').textContent=v.sections.length+' sections · '+v.sections.filter(s=>s.guide).length+' translated';

  const h=el('div','vhead');
  h.appendChild(el('div','kick','Specification'));
  h.appendChild(el('h2',null,v.title));
  h.appendChild(el('div','vlabel','Version <b>'+v.label+'</b>'));
  c.appendChild(h);
  if(v.preface){const d=el('details','preface');
    d.innerHTML='<summary><span class="chev">›</span> Preface &amp; release notes</summary><div class="body prose">'+v.preface+'</div>';
    enhance(d); c.appendChild(d);}
  c.appendChild(el('hr','vrule'));

  let lastGroup='__START__';
  v.sections.forEach(s=>{
    const id=s.num?('sec-'+s.num):slug(s.title);
    const grp=s.group||'';
    if(grp!==lastGroup){
      if(grp)toc.appendChild(el('div','toc-group',grp));
      else if(lastGroup!=='__START__')toc.appendChild(el('div','toc-group','More'));
      lastGroup=grp;
    }
    const label=s.num? s.title.replace(/^\d+\.\s*/,''):s.title;

    const sec=el('section','sec'); sec.id=id;
    const eye=el('div','sec-eyebrow');
    eye.innerHTML = s.num
      ? ('<span>§'+s.num+'</span>'+(s.group?'<span class="part">'+s.group+'</span>':''))
      : '<span class="part">'+(s.title.split(':')[0].split('—')[0].trim())+'</span>';
    sec.appendChild(eye);
    const titleEl=el('h3','sec-title',label); titleEl.dataset.target=id; sec.appendChild(titleEl);
    if(s.guide){sec.appendChild(plainDetails(s.guide));}
    const body=el('div','prose secbody'); body.innerHTML=s.html; enhance(body);
    const subs=[]; const sg=s.subGuides||{};
    body.querySelectorAll(':scope > h3').forEach(hh=>{
      const sid=id+'--'+slug(hh.textContent); hh.id=sid; subs.push({id:sid,title:hh.textContent});
      const g=sg[sig(hh.textContent)];
      if(g){const d=plainDetails(g); d.classList.add('subplain'); hh.insertAdjacentElement('afterend',d);}
    });
    sec.appendChild(body); c.appendChild(sec);

    const a=el('a',null,'<span class="n">'+(s.num||'§')+'</span><span>'+label+'</span>');
    a.href='#'+id; a.dataset.target=id; toc.appendChild(a);
    subs.forEach(sub=>{const sa=el('a','sub','<span>'+sub.title+'</span>');
      sa.href='#'+sub.id; sa.dataset.target=sub.id; toc.appendChild(sa);});
  });

  applyExpand(EXPANDED); wireObserver(); renderDiagrams(); window.scrollTo(0,0);
}

// render <pre class="mermaid"> blocks as diagrams, themed to match the viewer
let MERMAID_READY=false;
function isDark(){const t=document.documentElement.getAttribute('data-theme');
  return t==='dark' || (!t && matchMedia('(prefers-color-scheme:dark)').matches);}
function renderDiagrams(){
  if(typeof mermaid==='undefined') return;
  const nodes=[...document.querySelectorAll('pre.mermaid')];
  if(!nodes.length) return;
  nodes.forEach(n=>{ n.removeAttribute('data-processed');
    const src=n.getAttribute('data-diagram'); if(src!=null) n.textContent=src; });
  try{
    mermaid.initialize({startOnLoad:false, securityLevel:'strict', theme:isDark()?'dark':'neutral',
      flowchart:{htmlLabels:false,useMaxWidth:true}, themeVariables:{fontFamily:'ui-sans-serif,system-ui,sans-serif'}});
    mermaid.run({nodes});
  }catch(e){ /* leave source visible on failure */ }
}

let EXPANDED=false;
function applyExpand(on){document.querySelectorAll('details.plain').forEach(d=>d.open=on);
  const b=$('#expand'); b.setAttribute('aria-pressed',on?'true':'false');
  $('#expandLabel').textContent=on?'Plain language · on':'Plain language';}
$('#expand').addEventListener('click',()=>{EXPANDED=!EXPANDED; applyExpand(EXPANDED);});

let OBS=null;
function wireObserver(){
  if(OBS)OBS.disconnect();
  const links=new Map([...document.querySelectorAll('.toc a')].map(a=>[a.dataset.target,a]));
  OBS=new IntersectionObserver((ents)=>{ents.forEach(e=>{if(e.isIntersecting){
    const key=e.target.dataset.target||e.target.id;
    const a=links.get(key); if(!a)return;
    document.querySelectorAll('.toc a.active').forEach(x=>x.classList.remove('active'));
    a.classList.add('active'); a.scrollIntoView({block:'nearest'});
  }});},{rootMargin:'-70px 0px -72% 0px',threshold:0});
  document.querySelectorAll('h3.sec-title, .prose.secbody > h3[id]').forEach(s=>OBS.observe(s));
}
$('#toc').addEventListener('click',e=>{const a=e.target.closest('a'); if(!a)return;
  e.preventDefault(); const t=document.getElementById(a.dataset.target);
  if(t){history.replaceState(null,'','#'+a.dataset.target); t.scrollIntoView({behavior:'smooth',block:'start'});}});

const THEMES=['auto','light','dark']; let ti=0;
try{const s=localStorage.getItem('gcm-theme'); if(s&&THEMES.indexOf(s)>=0)ti=THEMES.indexOf(s);}catch(e){}
function applyTheme(){const t=THEMES[ti];
  if(t==='auto')document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme',t);
  $('#themeIcon').textContent = t==='light'?'◑':t==='dark'?'◐':'◒';
  $('#theme').title='Theme: '+t;
  try{localStorage.setItem('gcm-theme',t);}catch(e){}
  renderDiagrams();}
$('#theme').addEventListener('click',()=>{ti=(ti+1)%THEMES.length; applyTheme();});
matchMedia('(prefers-color-scheme:dark)').addEventListener('change',()=>{if(THEMES[ti]==='auto')renderDiagrams();});
applyTheme();

verSel.addEventListener('change',()=>render(verSel.value));
render(verSel.value);
</script>
"""

# Inline the vendored mermaid library so diagrams render (GitHub Pages, local file).
# The Claude Artifact's CSP rejects the bundled library, so build with
# EMBED_MERMAID=0 for that target — diagrams then show as labelled source.
MERMAID = ""
_mpath = os.path.join(HERE, "vendor", "mermaid.min.js")
if os.path.exists(_mpath) and os.environ.get("EMBED_MERMAID", "1") != "0":
    MERMAID = open(_mpath, encoding="utf-8").read()

out = (HTML.replace("__CSS__", CSS)
           .replace("__MERMAID__", MERMAID)
           .replace("__DATA__", payload))
# decode the two python-style escapes I embedded as literal text in the HTML template
out = out.replace(r"\U0001F40B", "\U0001F40B")
outp = os.path.join(OUT_DIR, "capability-model-viewer.html")
open(outp, "w", encoding="utf-8").write(out)
print("wrote", outp, len(out), "bytes")
