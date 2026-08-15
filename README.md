# nginx / Apache log analysis

Single piece that produces the report from the same logs:

| | |
|---|---|
| `analysis.html` | the report — reads **either** `logs.csv` **or** the raw `.log` files directly |

Both are self-contained. The HTML has no CDN, no external fonts, no charting library
(charts are drawn on `<canvas>`), so it opens from `file://` with nothing running.

`logs/` should be gitignored — raw logs contain visitor IP addresses.

---

## Quick start

**Just want the report:** open `logs/analysis.html` in a browser and drag your `.log`
files onto it. No conversion step. Drop several at once — an Apache log and an nginx
log merge in true timestamp order.

**Large corpus (millions of lines):** convert first, then load the CSV. The Go tool
streams and never holds rows; the page keeps everything in memory (~550 MB for 900k rows).

```bash
go run ./scripts/logs -in logs/raw -out logs
```

`-in` accepts a directory, a glob, or a comma-separated list.

---

## How it works

### 1. Format detection — by content, not filename

A file called `access.log` might be nginx or Apache. Neither tool is told which; both
sniff the shape of the line:

| format | shape |
|---|---|
| `nginx-main` | this box's custom format — `"$host"` **before** `"$request"`, `"$http_x_forwarded_for"` appended |
| `combined` | `"$request" $status $bytes "$referer" "$agent"` |
| `common` / CLF | `"$request" $status $bytes` |
| `nginx-error` | `2026/08/14 22:52:45 [error] 450#450: …` |
| `apache-error` | `[Thu Aug 14 22:52:45.123456 2026] [core:error] [pid 1] [client 1.2.3.4:5]` |

The file-level guess is a **vote, not a contract** — every line re-derives its own shape
from the quoting pattern of the first three tokens. A `combined` line sitting in a
`main` file still parses correctly.

> The custom `main` format is why off-the-shelf parsers mis-column these logs: they
> read `$host` as the request. Defined at `nginx.conf:51`.

### 2. Merging

The N streams are already time-ordered internally, so they merge by timestamp with an
N-way merge — O(1) memory regardless of corpus size. Two timestamp formats are
reconciled to UTC RFC3339 on the way out: `[15/Aug/2026:00:49:34 +0000]` (access) and
`2026/08/14 22:52:45` (error).

Every row is tagged with the file it came from (`file` column) so multi-source
corpora stay attributable.

### 3. Bad rows

Lines that cannot be parsed are **skipped with a reason**, never turned into a row of
empty fields. The converter writes `file:line<TAB>reason<TAB>content` to
`rejects.log`; the page lists them under **Data & method**.

Tuning this matters more than it sounds. `"" 400 0` looks like garbage but is exactly
what a 400 Bad Request logs — rejecting it threw away 376 real rows. On the production
corpus the reject count is now **48 lines, all `Starting periodic command scheduler: cron.`**

### 4. Client identity behind Cloudflare

`$remote_addr` is a Cloudflare edge PoP, not a visitor. `client_ip` is the XFF value
when present, falling back to `edge_ip` (kept separately so edge-vs-origin traffic can
still be told apart). Keying visitors off `$remote_addr` would report ~200 PoPs as the
entire internet.

Loopback and RFC1918 addresses are excluded from visitor counts and attacker ranking —
otherwise `127.0.0.1` ranks as the top offender on health-check traffic, and a deny
list generated from that takes the site down.

### 5. Classification

Method + path + query + UA + status are matched against a rule table. Each match yields
an OWASP 2021 category (`A01`–`A10`) and a specific `signal` (`sqli`, `log4shell`,
`wp-plugin-probe`, `secret-file`, …), so every count in the report drills down to
evidence.

Rules are **first-match-wins and order-sensitive**: `template-injection` sits last
because it is the broadest and would otherwise swallow `${jndi:` before `log4shell`
sees it.

Both directions are recorded — a `403` on `/wp-login.php` is an attack that was
stopped; a `200` on the same path is an incident.

**Soft-404 detection.** 22,178 attacks appeared to return `2xx`, including `/.env` and
`/.git/config` — a false CRITICAL. All returned *exactly* 60,056 bytes across 6,406
distinct paths: a WordPress catch-all serving the homepage under every URL. The page
runs a per-host body-size census and treats a size shared by ≥25 distinct paths as a
soft 404. Real exposure: 4,127.

`/.well-known/` is deliberately **not** an attack signal — those 1,609 hits are certbot
renewal. Static assets are exempt from the admin-panel rule unless they carry a query
string, otherwise SnappyMail's own `openpgp.min.js` fires it 2,084 times. Flagging
routine operations as attacks is the fastest way to make the whole report untrustworthy.

### 6. In-browser row store

Rows are held columnar: typed arrays for numbers, dictionary-encoded ids for strings.
Filtering is an integer-only scan over those arrays with unknown values bailing out up
front, so drill-downs stay interactive at ~900k rows.

Parsing runs chunked on the main thread with yields — **not** a Web Worker, because
Chrome blocks blob-URL workers on `file://` pages and the report has to work by
double-clicking it.

Absent byte counts are stored as `-1`, not `0`. A missing measurement is not a
measurement of zero.

---

## The report

| section | what it answers |
|---|---|
| **Executive summary** | requests, unique visitors, bandwidth, availability %, attacks blocked vs served, plain-English verdict |
| **Availability & reliability** | 5xx over time by vhost and hour, 499 aborts, `[emerg]` events |
| **Traffic & audience** | requests/day, peak hour, top vhosts and paths, human-vs-machine mix |
| **SEO & crawl health** | crawl budget by day and status, top 404s crawlers waste it on, AI-crawler arrivals by agent |
| **OWASP Top 10 (2021)** | ten tabs — count, trend, top source IPs, targeted paths, blocked-vs-served, raw sample lines |
| **Threat actors** | repeat offenders with attempts, distinct techniques, first/last seen; exports nginx `deny` lines and a Cloudflare IP CSV |
| **Risk register** | findings ranked by severity, each with a concrete action |
| **Data & method** | files loaded, rows kept, lines rejected and why, time range |

**Everything is clickable.** Every KPI, table row, chart bar and OWASP tab opens a
drawer with the underlying rows — paginated, sortable by timestamp, exportable to CSV
(the full selection, not the visible page).

Inside the drawer, 13 column filters compose with the drill-down and each other:
Host · Client IP · Path · Query · Status · Method · Client type · User agent ·
OWASP · Signal · Log · Source file · Day.

---

## Why there are two implementations, and how they are kept honest

The Go converter and the page carry the same parser and the same rule table. That is a
duplication, and duplicated rules drift.

`rawparity.mjs` guards it: it extracts the page's **own** JavaScript (slicing `<script>`
up to `function render()`), runs it over the raw logs in Node, runs the Go converter
over the same logs, and compares 23 aggregates — requests, bytes, every status code,
host counts, UA classes, OWASP totals, signals, attackers, soft-404 split.

Current result: **every metric identical**, both skipping exactly the same 48 lines.
Same log, same report, whichever way you load it.

`go test ./scripts/logs/` covers format sniffing, Apache combined and error parsing,
rejection behaviour, URLs containing spaces, and IPv6 hosts. One test earns its keep
specifically:

```go
func TestRulePatternsAreLowercase(t *testing.T) { … }
```

`classify()` lowercases its subject, so a rule written `/HNAP1` can never match — while
looking perfectly correct in the source. Four rules were written that way
(`/HNAP1`, `/GponForm`, `/.DS_Store`, `/+CSCOE+`) and **271 real attacks were silently
classified as harmless**. If you add a rule with a capital letter, this test fails.

---

## Gotchas worth knowing

- **Two-parser rule.** Changing a classification rule means changing it in *both*
  `logparse.go` and `analysis.html`. `rawparity.mjs` will catch you if you don't.
- **Aggregates were reconciled against `awk` on the raw logs**, independently of either
  parser — requests 864,386, bytes 27,178,831,088, `200`=411,691, `404`=136,542,
  `403`=128,295, `502`=7,036, `[emerg]`=60. If a change moves these, it needs a reason.
- **Counter caps.** Pruning the body-size census too aggressively silently discards
  soft-404 evidence and produces phantom "reached real content" rows.
- The size census counts **all 2xx**, not just `200` — 216 rows of `206 Partial Content`
  were scoring as genuine exposure.
