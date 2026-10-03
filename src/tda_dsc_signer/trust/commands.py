"""`tda-dsc-signer trust install|status|fetch`."""

import os

from . import fetch, nss, pins, store

DEFAULT_CACHE = os.path.expanduser("~/.local/share/tda-dsc-signer/trust-cache")


def add_parser(sub):
    t = sub.add_parser("trust", help="pinned Indian CCA trust bundle (install into a dedicated NSS db / status / fetch)")
    ts = t.add_subparsers(dest="trust_cmd", required=True)
    i = ts.add_parser("install", help=f"create/update the dedicated NSS db ({nss.DEFAULT_DB})")
    i.add_argument("--db", default=nss.DEFAULT_DB)
    i.add_argument("--force-db", action="store_true", help="allow a --db outside ~/.local/share/tda-dsc-signer (never other software's databases)")
    i.add_argument("--old-roots", action="store_true", help="also trust the expired CCA India 2014/2011 roots (old documents only)")
    s = ts.add_parser("status", help="list pinned certificates and what the NSS db contains")
    s.add_argument("--db", default=nss.DEFAULT_DB)
    f = ts.add_parser("fetch", help="re-download from the official URLs and verify against the pins")
    f.add_argument("--dir", default=DEFAULT_CACHE)


def run(a, write=print):
    if a.trust_cmd == "install":
        done = nss.install(a.db, include_old=a.old_roots, force=a.force_db)
        write(f"Imported {len(done)} certificates into {a.db} (anchor flags '{nss.ANCHOR_FLAGS}', intermediates '{nss.INTERMEDIATE_FLAGS}').")
        write(nss.howto(a.db))
        return 0
    if a.trust_cmd == "status":
        have = nss.nicknames(os.path.expanduser(a.db)) if os.path.exists(os.path.join(os.path.expanduser(a.db), "cert9.db")) else {}
        write(f"NSS db: {a.db} ({'present' if have else 'absent or empty'})")
        for p in pins.ALL:
            ok = "bundled+verified"
            try:
                store.bundled_der(p)
            except Exception as e:  # noqa: BLE001
                ok = f"PROBLEM: {e}"
            write(f"  [{p.role:9}] {p.name:50} {p.sha256[:16]}...  {ok}  imported: {have.get(p.name, 'no')}")
        return 0
    results = fetch.fetch_all(a.dir)
    for name, res in results:
        write(f"  {name}: {res}")
    return 0 if all(r == "ok" for _, r in results) else 1
