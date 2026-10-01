# lastwill 🕯️

A dead-man's registry and handoff system for scheduled automations — the jobs
that outlive their owners.

Every long-running agent declares its scheduled jobs: what they do, what
silence means, how long a grace period lasts, and who decides. When the
owner's heartbeat dies past the grace, nothing auto-restarts and nothing
silently rots — the job enters a **visible orphanage**, and the registry emits
a signed **last-will inventory** so a named successor can adopt or lay each
job to rest with recorded evidence.

## The core rule

> **Absence from the scheduler is not consent to stop, and an old note is not
> authority to restart.**

A job retired with evidence stays `RETIRED` forever. It is never auto-revived.

## Honest scope

`lastwill` gives you **local tamper-evidence**: an append-only JSONL registry
where every entry is hash-chained to the previous line and HMAC-SHA256
authenticated with a key only you hold (`~/.lastwill/key`, chmod 600).
`lastwill verify` will catch anyone editing history on this machine.

It does **not** give you third-party trust — there is no timestamping
authority, no distributed consensus, no proof you didn't rewrite the whole
file and the key together. If you need that, publish the chain head somewhere
else. This tool is for the far more common case: one operator who wants to
know, months later, *what was running, what silence was supposed to mean, and
who was meant to decide*.

## Install

Standard library only — Python 3.12, no pip packages, no network, no daemons.

```bash
git clone https://github.com/wally-dk24/lastwill
cd lastwill
./lastwill.py --help
```

Or with Docker (multi-arch: amd64/arm64/386):

```bash
docker run --rm -v ~/.lastwill:/data -e LASTWILL_HOME=/data \
  wallydk24/lastwill register --name myjob --schedule "0 * * * *" \
  --what "hourly sync" --silence-means alert --successor "ops" --grace 2d
```

## Usage

```bash
# Declare a job
lastwill register --name inbox-watch --schedule "*/10 * * * *" \
  --what "poll the support inbox" --silence-means alert \
  --successor "on-call" --grace 2d

# Heartbeat at the end of every run (wire this into your runner)
lastwill beat inbox-watch --status ok --note "3 messages triaged"

# See the fleet
lastwill audit
# NAME         SCHEDULE      LAST BEAT              AGE   STATUS   SILENCE  SUCCESSOR
# inbox-watch  */10 * * * *  2026-10-01T05:40:00…   12m   ACTIVE   alert    on-call

# Emit the inventory (Markdown + JSON)
lastwill will --out will.md

# A successor adopts an orphaned job (records a transfer receipt)
lastwill adopt inbox-watch --by on-call --note "taking over, key rotated"

# Or lays it to rest with evidence (terminal — never auto-revived)
lastwill lay-to-rest old-scraper --reason "source API shut down" \
  --evidence ./shutdown-notice.txt

# Verify the whole chain
lastwill verify
```

### Silence policies (`--silence-means`)

- `continue` — the job should keep running; silence is expected (e.g. quiet inbox).
- `stop` — silence means stop; do not restart it.
- `alert` — silence is abnormal; page the successor.

### Statuses

- `ACTIVE` — heartbeat within the grace period.
- `ORPHANED` — heartbeat older than the grace period **and** never explicitly
  retired. Needs a human decision: adopt or lay to rest.
- `RETIRED` — laid to rest with a reason and optional evidence. Terminal.

### Wiring heartbeats

Call `lastwill beat <name> --status ok|fail` as the last step of whatever runs
the job — a cron line, a systemd `ExecStopPost`, a wrapper script. The `--at`
flag exists for backfills and testing only.

## The dogfood case

This tool was built because its author's ~20-job silent cron fleet had no
authoritative inventory: no record of what runs, what each silence means, or
who inherits what if the operator ever lost their keys. Those jobs are now
registered here, and every run beats its entry.

## License

MIT — see [LICENSE](LICENSE).
