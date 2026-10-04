"""Render docs/guides/*.md to HTML (stdlib only) and write sitemap.xml. Run: python docs/build_site.py

Guide format: `title:` and `description:` header lines, `---`, then a Markdown subset (headings, paragraphs, - lists,
fenced code, pipe tables, `code`, **bold**, [links](url)).
"""

import html
import json
import re
from pathlib import Path

DOCS = Path(__file__).parent
BASE = "https://thedarkartist.github.io/tda-dsc-signer/"
LASTMOD = "2026-10-04"
SITE = "DSC Signer"


def inline(s: str) -> str:
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', s)


def cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def render(md: str) -> str:
    out, lines, i = [], md.splitlines(), 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            j = i + 1
            while not lines[j].startswith("```"):
                j += 1
            out.append("<pre><code>" + html.escape("\n".join(lines[i + 1 : j]), quote=False) + "</code></pre>")
            i = j + 1
        elif m := re.match(r"(#{1,3}) (.*)", ln):
            n = len(m[1])
            out.append(f"<h{n}>{inline(m[2])}</h{n}>")
            i += 1
        elif ln.startswith("|"):
            j = i
            while j < len(lines) and lines[j].startswith("|"):
                j += 1
            head, rows = cells(lines[i]), [cells(r) for r in lines[i + 2 : j]]
            t = "<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr></thead><tbody>"
            t += "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in rows)
            out.append(t + "</tbody></table>")
            i = j
        elif re.match(r"(- |\d+\. )", ln):
            tag = "ul" if ln.startswith("- ") else "ol"
            j = i
            while j < len(lines) and re.match(r"(- |\d+\. )", lines[j]):
                j += 1
            items = "".join("<li>" + inline(re.sub(r"^(- |\d+\. )", "", x)) + "</li>" for x in lines[i:j])
            out.append(f"<{tag}>{items}</{tag}>")
            i = j
        elif ln.strip():
            j = i
            while j < len(lines) and lines[j].strip() and not re.match(r"(#|```|\||- |\d+\. )", lines[j]):
                j += 1
            out.append("<p>" + inline(" ".join(lines[i:j])) + "</p>")
            i = j
        else:
            i += 1
    return "\n".join(out)


def page(title: str, desc: str, slug: str, body: str) -> str:
    url = f"{BASE}guides/{slug}.html"
    crumbs = {
        "@context": "https://schema.org",
        "@type": "BreadcrumbList",
        "itemListElement": [
            {"@type": "ListItem", "position": 1, "name": SITE, "item": BASE},
            {"@type": "ListItem", "position": 2, "name": title, "item": url},
        ],
    }
    t, d = html.escape(f"{title} | {SITE}"), html.escape(desc)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{t}</title>
<meta name="description" content="{d}">
<link rel="canonical" href="{url}">
<meta name="theme-color" content="#0f0f13">
<link rel="icon" type="image/svg+xml" href="../assets/favicon.svg">
<link rel="stylesheet" href="../assets/style.css">
<meta property="og:type" content="article">
<meta property="og:site_name" content="{SITE}">
<meta property="og:title" content="{t}">
<meta property="og:description" content="{d}">
<meta property="og:url" content="{url}">
<meta property="og:image" content="{BASE}assets/social-preview.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{t}">
<meta name="twitter:description" content="{d}">
<meta name="twitter:image" content="{BASE}assets/social-preview.png">
<script type="application/ld+json">{json.dumps(crumbs)}</script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top"><div class="wrap"><a class="brand" href="../index.html"><img src="../assets/favicon.svg" alt="" width="32" height="32">{SITE}</a>
<nav aria-label="Main"><a href="../index.html#install">Install</a><a href="sign-mca-forms-linux.html">MCA forms</a>
<a href="troubleshooting.html">Troubleshooting</a><a href="https://github.com/TheDarkArtist/tda-dsc-signer">GitHub</a></nav></div></header>
<main id="main" class="wrap">
<p class="crumbs"><a href="../index.html">{SITE}</a> / {html.escape(title)}</p>
<article>
{body}
</article>
</main>
<footer><div class="wrap"><p>GPL-3.0-or-later. Not affiliated with the Ministry of Corporate Affairs, the CCA or any certifying authority.
The TDACorp logo is a brand mark and is not covered by the GPL.</p></div></footer>
</body>
</html>
"""


def main() -> None:
    slugs = []
    for src in sorted((DOCS / "guides").glob("*.md")):
        head, body = src.read_text().split("\n---\n", 1)
        meta = dict(ln.split(": ", 1) for ln in head.splitlines())
        (DOCS / "guides" / f"{src.stem}.html").write_text(page(meta["title"], meta["description"], src.stem, render(body)))
        slugs.append(src.stem)
    urls = [BASE, *(f"{BASE}guides/{s}.html" for s in slugs)]
    entries = "".join(f"  <url><loc>{u}</loc><lastmod>{LASTMOD}</lastmod></url>\n" for u in urls)
    (DOCS / "sitemap.xml").write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n{entries}</urlset>\n'
    )
    print(f"built {len(slugs)} guides + sitemap.xml")


if __name__ == "__main__":
    main()
