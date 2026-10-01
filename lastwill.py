#!/usr/bin/env python3
"""lastwill — a dead-man's registry and handoff system for scheduled automations.

Every long-running agent declares its scheduled jobs: what they do, what
silence means, how long a grace period lasts, and who decides. When the
owner's heartbeat dies past the grace, nothing auto-restarts and nothing
silently rots — the job enters a visible orphanage, and the registry emits a
signed "last will" inventory so a named successor can adopt or lay each job
to rest with recorded evidence.

Core rule: absence from the scheduler is not consent to stop, and an old note
is not authority to restart. A job retired with evidence stays RETIRED forever.

Tamper-evidence: append-only JSONL, each entry hash-chained to the previous
line and HMAC-SHA256 authenticated with a local key (0600). This proves LOCAL
tamper-evidence, not third-party trust.

Standard library only. No daemons, no servers, no network. Never prints the key.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

HOME = os.environ.get("LASTWILL_HOME") or os.path.join(os.path.expanduser("~"), ".lastwill")
KEY_FILE = os.path.join(HOME, "key")
REGISTRY = os.path.join(HOME, "registry.jsonl")
EVIDENCE_DIR = os.path.join(HOME, "evidence")
GENESIS = "GENESIS"

SILENCE_POLICIES = ("continue", "stop", "alert")
BEAT_STATUSES = ("ok", "fail")

_GRACE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdwSMHDW])?\s*$")
_GRACE_MULT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def now_utc():
    return datetime.now(timezone.utc)


def parse_grace(spec):
    """'30d', '12h', '90m', '1w', '3600' -> seconds (float)."""
    m = _GRACE_RE.match(spec or "")
    if not m:
        raise ValueError(f"bad grace period {spec!r}: use e.g. 30d, 12h, 90m, 1w, 3600")
    mult = _GRACE_MULT[(m.group(2) or "s").lower()]
    return float(m.group(1)) * mult


def fmt_age(seconds):
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def parse_ts(s):
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def canon(obj):
    """Canonical JSON: sorted keys, no whitespace variance."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def ensure_home():
    os.makedirs(HOME, exist_ok=True)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def load_key():
    """Load (creating if needed) the local HMAC key. Never printed."""
    ensure_home()
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "w") as f:
            f.write(os.urandom(32).hex() + "\n")
        os.chmod(KEY_FILE, 0o600)
    else:
        st = os.stat(KEY_FILE)
        if st.st_mode & 0o777 != 0o600:
            os.chmod(KEY_FILE, 0o600)
    with open(KEY_FILE) as f:
        return bytes.fromhex(f.read().strip())


def chain_head():
    """sha256 hex of the last registry line's raw text, or GENESIS."""
    if not os.path.exists(REGISTRY):
        return GENESIS
    last = None
    with open(REGISTRY, "rb") as f:
        for line in f:
            if line.strip():
                last = line
    if last is None:
        return GENESIS
    return hashlib.sha256(last.rstrip(b"\n")).hexdigest()


def append_entry(key, entry):
    """Sign and append one entry. Returns the 1-based line number."""
    ensure_home()
    entry = dict(entry)
    entry["ts"] = iso(now_utc() if entry.get("ts") is None else entry["ts"])
    prev = chain_head()
    body = {"prev": prev, "entry": entry}
    mac = hmac.new(key, canon(body).encode(), hashlib.sha256).hexdigest()
    record = {"prev": prev, "entry": entry, "mac": mac}
    line = canon(record)
    n = 0
    with open(REGISTRY, "a") as f:
        if os.path.exists(REGISTRY):
            with open(REGISTRY) as rf:
                n = sum(1 for _ in rf)
        f.write(line + "\n")
    return n + 1


def read_records():
    """Raw (line_no, text, record) triples; skips blanks."""
    out = []
    if not os.path.exists(REGISTRY):
        return out
    with open(REGISTRY) as f:
        for i, line in enumerate(f, 1):
            if line.strip():
                out.append((i, line.rstrip("\n"), json.loads(line)))
    return out


def cmd_verify(args):
    key = load_key()
    records = read_records()
    prev_expected = GENESIS
    for lineno, text, rec in records:
        body = {"prev": rec.get("prev"), "entry": rec.get("entry")}
        if rec.get("prev") != prev_expected:
            print(f"VERIFY FAILED at line {lineno}: hash chain broken "
                  f"(prev mismatch)", file=sys.stderr)
            return 1
        mac = hmac.new(key, canon(body).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, rec.get("mac") or ""):
            print(f"VERIFY FAILED at line {lineno}: HMAC mismatch "
                  f"(entry tampered or wrong key)", file=sys.stderr)
            return 1
        prev_expected = hashlib.sha256(text.encode()).hexdigest()
    print(f"OK: {len(records)} entr{'y' if len(records) == 1 else 'ies'} verified, "
          f"chain intact")
    return 0


def job_state():
    """Replay the registry into per-job state. Returns (jobs, order)."""
    jobs, order = {}, []
    for _, _, rec in read_records():
        e = rec["entry"]
        t, name = e.get("type"), e.get("name")
        if t == "register":
            if name not in jobs:
                order.append(name)
            jobs[name] = {
                "def": e, "last_beat": None, "last_ok": None,
                "retired": None, "adopted": None, "beats": 0, "fails": 0,
            }
        elif name in jobs:
            j = jobs[name]
            if t == "beat":
                j["beats"] += 1
                j["last_beat"] = e["ts"]
                if e.get("status") == "ok":
                    j["last_ok"] = e["ts"]
                else:
                    j["fails"] += 1
            elif t == "retire":
                j["retired"] = e
            elif t == "adopt":
                j["adopted"] = e
    return jobs, order


def job_status(j, at=None):
    """ACTIVE / ORPHANED / RETIRED. Retired-with-evidence is terminal."""
    at = at or now_utc()
    if j["retired"] is not None:
        return "RETIRED"
    grace = float(j["def"].get("grace_sec", 0))
    # The owner is "alive" as of the newest owner action: heartbeat or
    # adoption (a successor taking over restarts the dead-man's timer).
    # Registration only sets the baseline when no action exists yet.
    stamps = [s for s in (j["last_beat"],
                          (j["adopted"] or {}).get("ts")) if s]
    last = max(parse_ts(s) for s in stamps) if stamps \
        else parse_ts(j["def"]["ts"])
    if (at - last).total_seconds() > grace:
        return "ORPHANED"
    return "ACTIVE"


def snapshot():
    jobs, order = job_state()
    at = now_utc()
    return {n: {"job": jobs[n], "status": job_status(jobs[n], at)} for n in order}, at


def evidence_info(path):
    """Record an evidence path (+ sha256 if the file exists)."""
    info = {"path": path, "sha256": None}
    if path and os.path.isfile(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        info["sha256"] = h.hexdigest()
    return info


def cmd_register(args):
    key = load_key()
    jobs, _ = job_state()
    try:
        grace_sec = parse_grace(args.grace)
    except ValueError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    if args.name in jobs and not args.force:
        print(f"error: job {args.name!r} already registered "
              f"(use --force to update its definition)", file=sys.stderr)
        return 2
    entry = {
        "type": "register", "name": args.name, "schedule": args.schedule,
        "what": args.what, "silence_means": args.silence_means,
        "successor": args.successor, "grace": args.grace, "grace_sec": grace_sec,
        "evidence": evidence_info(args.evidence) if args.evidence else None,
    }
    n = append_entry(key, entry)
    print(f"registered {args.name!r} (grace {args.grace}, "
          f"silence-means {args.silence_means}, successor {args.successor}) "
          f"[line {n}]")
    return 0


def cmd_beat(args):
    key = load_key()
    jobs, _ = job_state()
    if args.name not in jobs:
        print(f"error: no such job {args.name!r}", file=sys.stderr)
        return 2
    j = jobs[args.name]
    if j["retired"] is not None:
        print(f"error: job {args.name!r} is RETIRED — beats are not accepted "
              f"(absence is not consent to stop; only an explicit re-register "
              f"by the successor revives it)", file=sys.stderr)
        return 2
    ts = parse_ts(args.at) if args.at else None
    n = append_entry(key, {"type": "beat", "name": args.name,
                           "status": args.status, "note": args.note, "ts": ts})
    print(f"beat {args.name!r}: {args.status} [line {n}]")
    return 0


def cmd_audit(args):
    snap, at = snapshot()
    if args.json:
        print(json.dumps(
            {"at": iso(at),
             "jobs": [{"name": n,
                        "status": s["status"],
                        "schedule": s["job"]["def"]["schedule"],
                        "silence_means": s["job"]["def"]["silence_means"],
                        "successor": s["job"]["def"]["successor"],
                        "grace": s["job"]["def"]["grace"],
                        "last_beat": s["job"]["last_beat"],
                        "beats": s["job"]["beats"],
                        "fails": s["job"]["fails"]} for n, s in snap.items()]},
            indent=2))
        return 0
    rows = []
    for name, s in snap.items():
        j = s["job"]
        last = j["last_beat"] or "(never)"
        age = fmt_age((at - parse_ts(j["last_beat"])).total_seconds()) \
            if j["last_beat"] else "—"
        rows.append((name, j["def"]["schedule"], last, age, s["status"],
                     j["def"]["silence_means"], j["def"]["successor"]))
    hdr = ("NAME", "SCHEDULE", "LAST BEAT", "AGE", "STATUS", "SILENCE", "SUCCESSOR")
    widths = [max(len(str(r[i])) for r in [hdr] + rows) for i in range(len(hdr))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*hdr))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*r).rstrip())
    counts = {}
    for _, s in snap.items():
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    print(f"\n{len(snap)} jobs: " + ", ".join(
        f"{v} {k}" for k, v in sorted(counts.items())))
    return 0


def cmd_will(args):
    snap, at = snapshot()
    records = read_records()
    doc = {
        "emitted_at": iso(at),
        "registry_lines": len(records),
        "chain_head": chain_head(),
        "jobs": [],
    }
    md = ["# Last will — scheduled-automation inventory", "",
          f"_Emitted {iso(at)}. Registry: {len(records)} signed entries._", ""]
    for name, s in snap.items():
        j, d = s["job"], s["job"]["def"]
        last = j["last_beat"] or "(never)"
        entry = {
            "name": name, "status": s["status"],
            "description": d["what"], "schedule": d["schedule"],
            "silence_means": d["silence_means"], "successor": d["successor"],
            "grace": d["grace"], "last_beat": last, "last_ok": j["last_ok"],
            "beats": j["beats"], "fails": j["fails"],
            "retired": j["retired"], "adopted": j["adopted"],
        }
        doc["jobs"].append(entry)
        md += [f"## {name} — {s['status']}", "",
               f"- **What:** {d['what']}",
               f"- **Schedule:** `{d['schedule']}`",
               f"- **If silent, this means:** {d['silence_means']}",
               f"- **Successor:** {d['successor']}",
               f"- **Grace period:** {d['grace']}",
               f"- **Last heartbeat:** {last}",
               f"- **Last success:** {j['last_ok'] or '(never)'}",
               f"- **Heartbeats:** {j['beats']} ({j['fails']} failed)"]
        if j["retired"]:
            r = j["retired"]
            md += [f"- **Retired:** {r['ts']} by {r.get('by') or 'owner'} — "
                   f"{r['reason']}"]
            if r.get("evidence", {}).get("path"):
                md += [f"- **Evidence:** `{r['evidence']['path']}`"]
        if j["adopted"]:
            a = j["adopted"]
            md += [f"- **Adopted:** {a['ts']} by {a['by']}"
                   + (f" — {a['note']}" if a.get("note") else "")]
        md += [""]
    md += ["---",
           "_Absence from the scheduler is not consent to stop; "
           "an old note is not authority to restart._", ""]
    markdown = "\n".join(md)
    json_doc = json.dumps(doc, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(markdown)
        jpath = args.json_out or (os.path.splitext(args.out)[0] + ".json")
        with open(jpath, "w") as f:
            f.write(json_doc)
        print(f"wrote {args.out} and {jpath}")
    else:
        print(markdown)
        if args.json_out:
            with open(args.json_out, "w") as f:
                f.write(json_doc)
            print(f"(also wrote {args.json_out})", file=sys.stderr)
    return 0


def cmd_adopt(args):
    key = load_key()
    jobs, _ = job_state()
    if args.name not in jobs:
        print(f"error: no such job {args.name!r}", file=sys.stderr)
        return 2
    j = jobs[args.name]
    if j["retired"] is not None:
        print(f"error: job {args.name!r} is RETIRED — adoption is not possible "
              f"(retirement is terminal)", file=sys.stderr)
        return 2
    n = append_entry(key, {"type": "adopt", "name": args.name,
                           "by": args.by, "note": args.note})
    print(f"transfer receipt: {args.name!r} adopted by {args.by} [line {n}]")
    return 0


def cmd_lay_to_rest(args):
    key = load_key()
    jobs, _ = job_state()
    if args.name not in jobs:
        print(f"error: no such job {args.name!r}", file=sys.stderr)
        return 2
    j = jobs[args.name]
    if j["retired"] is not None:
        print(f"error: job {args.name!r} is already RETIRED", file=sys.stderr)
        return 2
    n = append_entry(key, {
        "type": "retire", "name": args.name, "reason": args.reason,
        "by": args.by or j["def"]["successor"],
        "evidence": evidence_info(args.evidence) if args.evidence else None})
    print(f"{args.name!r} laid to rest (RETIRED, terminal) [line {n}]")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="lastwill",
        description="Dead-man's registry and handoff for scheduled automations.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("register", help="declare a scheduled job")
    r.add_argument("--name", required=True)
    r.add_argument("--schedule", required=True, help="cron expression or prose")
    r.add_argument("--what", required=True, help="what the job does")
    r.add_argument("--silence-means", required=True, choices=SILENCE_POLICIES,
                   help="what the job's silence means: keep running, stop, or alert")
    r.add_argument("--successor", required=True, help="who decides on handoff")
    r.add_argument("--grace", required=True,
                   help="grace period, e.g. 30d, 12h, 90m")
    r.add_argument("--evidence", help="path to supporting evidence file")
    r.add_argument("--force", action="store_true",
                   help="update the definition of an existing job")
    r.set_defaults(func=cmd_register)

    b = sub.add_parser("beat", help="record a heartbeat for a job")
    b.add_argument("name")
    b.add_argument("--status", required=True, choices=BEAT_STATUSES)
    b.add_argument("--note")
    b.add_argument("--at", help="ISO-8601 timestamp (testing/backfill only)")
    b.set_defaults(func=cmd_beat)

    a = sub.add_parser("audit", help="ACTIVE / ORPHANED / RETIRED table")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_audit)

    w = sub.add_parser("will", help="emit the signed last-will inventory")
    w.add_argument("--out", help="write Markdown to PATH (+ JSON beside it)")
    w.add_argument("--json-out", help="write the JSON inventory to PATH")
    w.set_defaults(func=cmd_will)

    ad = sub.add_parser("adopt", help="successor adopts a job (transfer receipt)")
    ad.add_argument("name")
    ad.add_argument("--by", required=True)
    ad.add_argument("--note")
    ad.set_defaults(func=cmd_adopt)

    l = sub.add_parser("lay-to-rest", help="retire a job with evidence (terminal)")
    l.add_argument("name")
    l.add_argument("--reason", required=True)
    l.add_argument("--evidence", help="path to supporting evidence file")
    l.add_argument("--by", help="who retires it (default: the successor)")
    l.set_defaults(func=cmd_lay_to_rest)

    v = sub.add_parser("verify", help="verify hash chain + HMACs")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
