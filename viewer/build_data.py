import re, json, glob, os, html as htmlmod
import markdown

# Portable paths. Spec .md files are read from SPECS_DIR (default: the parent
# of this tooling folder). Override with the SPECS_DIR env var if the specs
# live elsewhere. The intermediate data.json is written next to these scripts.
HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.environ.get("SPECS_DIR", os.path.join(os.path.dirname(HERE), "spec"))
md = markdown.Markdown(extensions=["tables","fenced_code","sane_lists"])

def render_md(text):
    # extract mermaid blocks -> placeholders
    mer = []
    def grab(m):
        mer.append(m.group(1))
        return f"\n\nMERMAIDPLACEHOLDER{len(mer)-1}\n\n"
    text = re.sub(r"```mermaid\n(.*?)```", grab, text, flags=re.S)
    md.reset()
    out = md.convert(text)
    for i, src in enumerate(mer):
        esc = htmlmod.escape(src)
        attr = htmlmod.escape(src, quote=True)
        tag = f'<pre class="mermaid" data-diagram="{attr}">{esc}</pre>'
        out = out.replace(f"<p>MERMAIDPLACEHOLDER{i}</p>", tag)
        out = out.replace(f"MERMAIDPLACEHOLDER{i}", tag)
    return out

def _registry_desc_col(block_lines):
    """The description column, detected globally: the most common start position
    of the second field across entry-start lines (position after the first run
    of 2+ spaces). Robust against shallow parenthetical notes."""
    from collections import Counter
    positions = Counter()
    for l in block_lines:
        if l[:1] not in (" ", "", "-"):        # entry-start line (not indented, not a -- divider)
            m = re.search(r"\s{2,}", l)
            if m:
                positions[m.end()] += 1
    return positions.most_common(1)[0][0] if positions else 38

def _reg_cell(s):
    """Format a registry cell as raw HTML: `code` spans -> <code>, everything
    else HTML-escaped (so text like __proto__ or *x* stays literal, not markdown)."""
    parts = s.split("`")
    out = []
    for i, p in enumerate(parts):
        e = htmlmod.escape(p)
        out.append(f"<code>{e}</code>" if i % 2 == 1 else e)
    return "".join(out)

def _registry_group_to_table(seg, col):
    """Parse a registry group's entry lines into a raw-HTML table using the given
    description column. A capability name that overflows the column is kept whole
    (split at the next space); continuation lines extend the previous cell."""
    lines = [l for l in seg if l.strip() != ""]
    if not lines:
        return None
    entries = []
    for l in lines:
        if l[:1] != " ":                        # entry start
            sp = col
            if len(l) > col and l[col-1] != " " and l[col] != " ":   # col lands inside the name
                nx = l.find(" ", col)
                sp = nx if nx != -1 else len(l)
            cap, desc = l[:sp].rstrip(), l[sp:].strip()
            entries.append([cap, desc])
        else:                                   # continuation
            add = l[col:].strip() if l[:col].strip() == "" else l.strip()
            if entries:
                entries[-1][1] = (entries[-1][1] + " " + add).strip()
            else:
                entries.append(["", add])
    rows = ['<table><thead><tr><th>Capability</th><th>Notes</th></tr></thead><tbody>']
    for cap, desc in entries:
        capcell = f"<code>{htmlmod.escape(cap)}</code>" if cap else ""
        rows.append(f"<tr><td>{capcell}</td><td>{_reg_cell(desc)}</td></tr>")
    rows.append("</tbody></table>")
    return "\n".join(rows)

def split_registry_md(body):
    """Render the §19 registry: each `-- Group --` becomes a `### Group`
    heading + a Markdown table (auto-aligned), instead of one ASCII code block."""
    def repl(block):
        lines = block.split("\n")
        col = _registry_desc_col(lines)
        lead=[]; segs=[]; cur_label=None; cur=[]
        for ln in lines:
            dm=re.match(r'^-- (.+?) --\s*$', ln)
            if dm:
                if cur_label is None: lead=cur
                else: segs.append((cur_label,cur))
                cur_label=dm.group(1); cur=[]
            else:
                cur.append(ln)
        if cur_label is not None: segs.append((cur_label,cur))
        parts=[]
        if any(x.strip() for x in lead):
            parts.append("```text\n"+"\n".join(lead).rstrip()+"\n```")
        for label,seg in segs:
            tbl=_registry_group_to_table(seg, col)
            if tbl:
                parts.append("### "+label+"\n\n"+tbl)
            else:
                parts.append("### "+label+"\n\n```text\n"+"\n".join(seg).rstrip("\n")+"\n```")
        return "\n\n".join(parts)
    return re.sub(r"```text\n(.*?)\n```",
                  lambda m: repl(m.group(1)) if re.search(r'^-- .+ --\s*$', m.group(1), re.M) else m.group(0),
                  body, flags=re.S)

def split_preface_md(pf):
    """Break the wall-of-text version preface into one paragraph per version note."""
    pf = re.sub(r'(?<!\A)((?:The \.\d patch |v2\.1\.\d+ (?:integrates|is a|integrated|is a self))\b)',
                r'\n\n\1', pf.strip())
    return pf

def split_sections(txt):
    """Return (frontmatter_md, [ (kind, num, title, body_md) ]).
    kind in {'part','section'}. Splits on ^## and ^# (part) headers."""
    lines = txt.split("\n")
    front = []
    blocks = []
    cur = None  # (kind,num,title,[lines])
    started = False
    for ln in lines:
        m2 = re.match(r"^## (.+)$", ln)
        m1 = re.match(r"^# (.+)$", ln)
        if m2:
            started = True
            if cur: blocks.append(cur)
            title = m2.group(1).strip()
            nm = re.match(r"^(\d+)\.\s+(.*)$", title)
            num = nm.group(1) if nm else None
            cur = ["section", num, title, []]
        elif m1 and started is False and not front:
            # H1 title line at very top -> frontmatter
            front.append(ln)
        elif m1:
            # a Part divider (# Part ...) — treat as part block
            started = True
            if cur: blocks.append(cur); cur=None
            blocks.append(["part", None, m1.group(1).strip(), []])
        else:
            if cur: cur[3].append(ln)
            elif not started: front.append(ln)
    if cur: blocks.append(cur)
    return "\n".join(front), blocks

def sig(title):
    """Stable subsection signature for matching official <-> guide subsections."""
    t=title.lower()
    for k in ["axis 1","axis 2","principal","derived","effect","namespace"]:
        if k in t: return ("effect" if k=="namespace" else k).replace(" ","")
    return re.sub(r"[^a-z0-9]+","",t)[:16]

def guide_sections():
    txt = open(os.path.join(REPO,"guide-v2.md"),encoding="utf-8").read()
    raw = {}
    lines = txt.split("\n"); cur=None; key=None
    for ln in lines:
        m2 = re.match(r"^## (.+)$", ln)
        m1 = re.match(r"^# (.+)$", ln)
        if m2:
            if key is not None: raw[key]="\n".join(cur)
            title=m2.group(1).strip()
            nm=re.match(r"^(\d+)\.",title)
            key = nm.group(1) if nm else title.lower()
            cur=[]
        elif m1:
            if key is not None: raw[key]="\n".join(cur); key=None; cur=None
            t=m1.group(1).strip().lower()
            if t.startswith("overview"): key="overview"; cur=[]
            elif t.startswith("open questions"): key="open"; cur=[]
        else:
            if cur is not None: cur.append(ln)
    if key is not None: raw[key]="\n".join(cur)
    out={}
    for k,body in raw.items():
        if not body.strip(): continue
        parts=re.split(r"(?m)^### (.+)$", body)
        lead=parts[0]
        subs={}
        for i in range(1,len(parts),2):
            subs[sig(parts[i].strip())] = render_md(parts[i+1].strip())
        out[k]={"lead": render_md(lead.strip()) if lead.strip() else "",
                "subs": subs,
                "full": render_md(body.strip())}
    return out

def guide_key_for(title, num):
    if num: return num
    t=title.lower()
    if t.startswith("overview"): return "overview"
    if t.startswith("open questions"): return "open"
    return None

def vkey(fn):
    m=re.search(r"v(\d+)\.(\d+)\.(\d+)\.md$", fn)
    return tuple(int(x) for x in m.groups())

guides = guide_sections()

files = sorted(glob.glob(os.path.join(REPO,"gosub-extension-capability-model-v*.md")), key=vkey)
versions=[]
for fn in files:
    txt=open(fn,encoding="utf-8").read()
    vm=re.search(r"v(\d+\.\d+\.\d+)\.md$",fn); ver="v"+vm.group(1)
    front, blocks = split_sections(txt)
    # title + version label from front
    title_m = re.search(r"^# (.+)$", front, re.M)
    title = title_m.group(1).strip() if title_m else "Gosub Extension Capability Model"
    verlabel_m = re.search(r"^\*\*Version (.+?)\*\*", front, re.M)
    verlabel = verlabel_m.group(1).strip() if verlabel_m else ver
    # preface = front minus H1 and version line
    pf = re.sub(r"^# .+$","",front,flags=re.M)
    pf = re.sub(r"^\*\*Version.+?\*\*","",pf,flags=re.M)
    preface_html = render_md(split_preface_md(pf)) if pf.strip() else ""
    secs=[]
    group=None
    for kind,num,btitle,blns in blocks:
        if kind=="part":
            group=btitle
            continue
        body="\n".join(blns).strip()
        if num=="19":
            body=split_registry_md(body)
            body=re.sub(r'(?m)^(Deltas from v0\.2:)', r'### Registry deltas\n\n\1', body, count=1)
            # break the wall-of-text deltas paragraph into one paragraph per registry version
            body=re.sub(r'(?<!\n\n)(v0\.2\.\d+ deltas:)', r'\n\n\1', body)
        gk=guide_key_for(btitle,num)
        gobj=guides.get(gk) if gk else None
        off_subs=[m.group(1).strip() for m in re.finditer(r"(?m)^### (.+)$", body)]
        guide_html=""; sub_guides={}
        if gobj:
            if gobj["subs"] and off_subs:
                guide_html = gobj["lead"] or gobj["full"]
                for ot in off_subs:
                    g = gobj["subs"].get(sig(ot))
                    if g: sub_guides[sig(ot)] = g
            else:
                guide_html = gobj["full"]
        secs.append({
            "num":num, "title":btitle, "group":group,
            "html":render_md(body),
            "guide":guide_html,
            "subGuides":sub_guides,
        })
    versions.append({"ver":ver,"label":verlabel,"title":title,"preface":preface_html,"sections":secs})

data={"versions":versions}
outp=os.path.join(HERE, "data.json")
json.dump(data,open(outp,"w"),ensure_ascii=False)
print("versions:", [v["ver"] for v in versions])
print("guide keys:", sorted(guides.keys()))
print("sections in latest:", len(versions[-1]["sections"]), "| with guide:", sum(1 for s in versions[-1]["sections"] if s["guide"]))
print("data bytes:", os.path.getsize(outp))
