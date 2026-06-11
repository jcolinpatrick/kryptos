# kryptosbot.com Traffic Analysis

Date: 2026-04-17

Scope:
- GoAccess summary provided by user for `2026-02-23` through `2026-04-17`
- Live nginx access log at `/var/log/nginx/access.log`
- Current site assets and nginx config in repo

## Executive read

The site is getting real human traffic, but the raw request totals are heavily inflated by probes, crawlers, and at least one dominant automated/internal source.

Operationally, the site looks healthy:
- very low `5xx`
- high `2xx`
- no sign of a broad availability problem

Security-wise, the site is under constant routine scanning:
- WordPress/PHP probes
- dotfile/git/config probes
- backup/archive fishing
- non-browser methods like `CONNECT` and `PROPFIND`

The `/static/fonts/fonts.css` 404s appear to be a historical rollout/deploy gap, not a current missing-file bug. The file exists now and is currently serving successfully.

## Raw totals

From the live access log:
- total requests: `317,277`
- `200`: `215,173`
- `404`: `55,132`
- `301`: `34,938`
- `400`: `4,311`
- `429`: `3,628`
- `405`: `976`

From the GoAccess snapshot:
- unique visitors: `8,935`
- valid requests: `297,727`
- not found: `10,314` distinct URL rows in report table context
- transferred: `5.2 GiB`

Important caveat:
- GoAccess "unique visitors" here means same IP + same date + same user-agent.
- That is not the same thing as unique humans.

## Human vs bot/probe estimate

Two local heuristics were run on the live nginx log:

1. UA-based classifier in `ops/tools/analyze_traffic.sh`
- likely bot: `94,419` requests (`29%`)
- likely human: `222,858` requests (`70%`)

2. Broader probe-like classifier on the live log
- known bot UA: `92,722`
- probe-like path/method requests: `75,750`
- probe-like 404s: `44,359`

Interpretation:
- `29%` is a floor for obvious bot traffic, not a full count.
- Many scanners spoof normal browser UAs, so true automated/probe traffic is higher than the UA-only estimate.
- A realistic read is:
  - at least about `30%` of requests are plainly automated
  - total non-human / hostile / synthetic traffic is likely in the `35%` to `50%+` band
  - the raw hit totals should not be interpreted as mostly human browsing

One especially distorting source:
- top host in the GoAccess report: `100.18.4.0`
- hits: `172,318`
- share of all hits: `57.88%`
- transferred: `2.4 GiB`

That single source dominates the traffic picture. It is not representative of organic public use.

## Evidence of real human traffic

Despite the noise, the site clearly has genuine users:

- browser families with meaningful visitor counts:
  - Chrome
  - Safari
  - Firefox
  - Edge
- OS mix includes:
  - Windows
  - iOS
  - macOS
  - Android
- heavily visited real pages:
  - `/`
  - `/archive/`
  - `/browse/`
  - `/workbench/`
- static assets like fonts/CSS/images are being fetched in browser-like patterns

Conclusion:
- the site has real human readership
- but the aggregate request volume is not a good proxy for human attention

## 404 / probe analysis

Live log classifier:
- total 404s: `55,132`
- probe-like 404s: `44,359`

That means roughly `80%` of 404s are routine exploit or scan noise.

Representative hostile paths from the user-provided report:
- `/ioxi-o.php`
- `/wp-content/plugins/hellopress/wp_filemanager.php`
- `/about.php`
- `/admin.php`
- `/.git/config`
- `/wp.php`
- `/init.php`
- `/bs1.php`
- `/wp-michan.php`

Non-browser methods also appear:
- `CONNECT`
- `PROPFIND`

Bottom line:
- the 404 volume is mostly expected internet background radiation, not user confusion

## `/static/fonts/fonts.css` diagnosis

Current repo state:
- file exists at `ops/site_builder/static/fonts/fonts.css`
- generated file exists at `site/static/fonts/fonts.css`
- generated HTML links to `/static/fonts/fonts.css`
- nginx static rule should serve `.css` under the site root

Live log counts for `/static/fonts/fonts.css`:
- `200`: `956`
- `404`: `297`
- `304`: `19`
- `429`: `2`

Timeline from live log:
- first `404`: `2026-03-09 08:33:35 -0400`
- last `404`: `2026-03-12 21:14:33 -0400`
- first `200`: `2026-03-12 21:21:51 -0400`

Interpretation:
- this was almost certainly a historical deployment mismatch around the font rollout
- likely sequence:
  - HTML began referencing `/static/fonts/fonts.css`
  - live `site/` did not yet have the file, or nginx/root served an older build
  - after `2026-03-12 21:21`, the file began serving successfully
- this does **not** look like an ongoing current bug

Current risk:
- low
- the path is mostly healthy now

## Odd/static probe requests

From the live log:
- `/html.tgz`: only `301` responses seen
- `/backups/backup.zip`: only `301` responses seen

Interpretation:
- scanners are fishing for accidental archives/backups
- they are not successfully retrieving such files based on the observed log slice

## Reliability / operations read

This is the strongest operational result from the whole snapshot:
- only `7` `5xx` server errors in the GoAccess report

That suggests:
- the site is stable
- nginx and the static serving model are holding up well
- hostile traffic is not causing broad app failure

The `429` count is also useful:
- rate limiting is actively doing work
- this is good and should probably stay in place

## Recommendations

1. Treat raw hits as an infrastructure metric, not an audience metric.
   Use browser/OS/referrer slices for audience discussions.

2. Track a "likely human" dashboard separately.
   Suggested definition:
   - `200` status
   - `GET/HEAD`
   - no obvious bot/scanner UA
   - non-probe path
   - excludes known dominant internal/automation IPs like `100.18.4.0` once identified

3. Keep current rate limiting.
   The `429` volume suggests it is absorbing real scan pressure.

4. Consider adding explicit nginx deny/drop patterns for common junk paths that still consume log volume.
   Candidates:
   - `/.env`
   - backup/archive extensions under obvious names
   - common WordPress/plugin probe prefixes
   - `.git/` already covered, keep it

5. Consider a dedicated short-circuit location for obvious exploit families.
   This is mostly a log hygiene / CPU hygiene improvement, not a correctness issue.

6. Preserve the current static-site model.
   The near-zero `5xx` rate is strong evidence that serving from `site/` directly is operationally sound.

7. No urgent fix is needed for `fonts.css`.
   If desired, add a small note to ops docs:
   - there was a historical `2026-03-09` to `2026-03-12` rollout gap
   - current state is healthy

## Suggested audience-facing summary

If you need a short public/internal summary:

> kryptosbot.com is receiving meaningful real-user traffic, but the raw request totals are heavily mixed with normal internet scanning and automated fetches. The site itself appears stable and healthy, with almost no server-side failures. Most 404 volume is hostile probe noise rather than user navigation problems.

