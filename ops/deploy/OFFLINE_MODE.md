# Offline mode: taking kryptosbot.com down and bringing it back

Procedure for a planned outage, such as physically relocating the server. Covers
pointing visitors at the GitHub repository while the machine is off, silencing the
monitors so the outage does not page you continuously, and restoring service on a new
network.

Companion to [`docs/operations.md`](../../docs/operations.md), which covers normal
day-to-day operation.

---

## Why the server cannot redirect itself

kryptosbot.com is self-hosted. [`kryptosbot.nginx`](kryptosbot.nginx) serves the static
site from `/home/cpatrick/kryptos/site` on one machine, and the GoDaddy A record for the
apex domain points at that machine's Verizon Fios WAN IP.

The consequence: once the machine is off, there is nothing left to serve a redirect.
The domain still resolves, so browsers dial the old IP and hang until they time out.
Visitors see a connection error, not a message.

Any working pointer therefore has to live somewhere that stays up. The registrar is the
simplest such place, which is what this procedure uses.

---

## Two constraints that bite if ignored

**1. HSTS means returning visitors demand a valid certificate.** nginx sends
`Strict-Transport-Security: max-age=63072000; includeSubDomains`, so every browser that
has loaded kryptosbot.com in the last two years has recorded a promise that the domain
is HTTPS-only. Those browsers will refuse a plain-HTTP redirect outright, and they will
refuse an untrusted certificate with no click-through. Whatever answers the domain
during the outage must present a valid certificate for `kryptosbot.com`. GoDaddy's
forwarding can do this, but only with SSL forwarding enabled, and provisioning is not
instant. Verify it rather than assuming it (see the check below).

The domain is not on the HSTS preload list, so first-time visitors are unaffected.
Only people who have been to the site before are exposed to this.

**2. Use a 302, never a 301.** Browsers cache permanent redirects, some of them
indefinitely. A 301 to github.com would keep sending returning visitors to GitHub for
weeks after the site is back, and there is no way to reach into their caches to fix it.
A 302 is re-checked each time and stops mattering the moment DNS points home again.

---

## Before you unplug

Do these in order. The order matters: pausing the monitors first means they never see
the transition and never fire.

### 1. Pause the monitors and the deploy loop

Two cron jobs will page you via ntfy the instant anything changes, and neither has any
concept of planned downtime:

- `check_dns.sh` (every 15 min) compares the A record against the WAN IP. Enabling
  forwarding replaces the A record with a GoDaddy address, which reads as a mismatch,
  and it sends an **urgent** "Verizon likely changed your public IP" alert.
- `uptime-monitor.sh` (every 5 min) fetches the public site and sends a "DOWN" alert
  when it stops answering.

Both windows matter: the gap between enabling forwarding and shutting down, and the gap
between powering back on and reverting DNS. Pause before the first and restore after the
second.

```bash
crontab -l > ~/crontab.backup.$(date +%F)   # keep a copy to restore from
crontab -e
```

Comment out these four lines with a leading `#`:

```
0 7 * * *    /home/cpatrick/kryptos/ops/scheduled/health-check.sh
*/30 * * * * /usr/bin/flock -n /tmp/kryptosbot-cron.lock /home/cpatrick/kryptos/ops/deploy/cron_update.sh
*/15 * * * * /home/cpatrick/kryptos/ops/deploy/check_dns.sh
*/5 * * * *  /home/cpatrick/kryptos/ops/scheduled/uptime-monitor.sh
```

Consider also pausing `0 2 * * * ops/scheduled/run-prompt.sh nightly-review.txt`, which
spends API tokens reviewing a site that is not serving.

Leave `poll_github_traffic.sh` alone. It is harmless and simply will not run while the
machine is off.

### 2. Turn on GoDaddy forwarding

In the GoDaddy DNS panel for kryptosbot.com, under **Forwarding**, add a domain forward:

| Field | Value |
|---|---|
| Forward to | `https://github.com/jcolinpatrick/kryptos` |
| Redirect type | **Temporary (302)**, not permanent |
| Forward settings | Forward only (no masking) |
| SSL | Enabled |

Record the current A record value before you change anything, so you have a known-good
reference:

```bash
dig +short kryptosbot.com A     # note this down
curl -4 -s https://api.ipify.org   # the WAN IP it should currently match
```

GoDaddy replaces the A record with its own forwarding address. Propagation is usually
minutes, but allow up to an hour, and certificate provisioning can lag behind DNS.

### 3. Verify the forward actually works

Do this **while the server is still running**, so you can back out if the forward
misbehaves.

**Two traps make the naive test lie.** Both were hit on 2026-07-26.

*Trap 1: a stale DNS cache means you test your own server.* Plain
`curl https://kryptosbot.com` from this machine, or from anywhere with the old A record
cached, resolves to your WAN IP and gets answered by local nginx. It returns `200` with
the real site and a `server: nginx` header, which looks like a pass and proves nothing
about the forward. Query a resolver that has no cached copy, then pin curl to the
addresses you get back:

```bash
# Authoritative answer, bypassing any local cache
curl -s "https://dns.google/resolve?name=kryptosbot.com&type=A" \
  | python3 -c "import json,sys; [print(a['data']) for a in json.load(sys.stdin).get('Answer',[])]"
```

A forward is in effect when those addresses are GoDaddy's, not your WAN IP. On
2026-07-26 they were `3.33.152.147` and `15.197.142.173`. Treat the values as
changeable and read them from the query rather than hardcoding them.

*Trap 2: `curl -I` sends HEAD, and GoDaddy's load balancer rejects it with `405 Not
Allowed`.* That looks like a broken forward when the forward is fine. Use GET.

```bash
IP=3.33.152.147     # substitute what the query above returned

# HTTPS: the path that matters, because HSTS forces returning visitors onto it
curl -sS --max-time 20 --resolve "kryptosbot.com:443:$IP" -o /dev/null \
  -w 'https code=%{http_code} location=%{redirect_url}\n' https://kryptosbot.com

# HTTP: GET, not HEAD
curl -sS --max-time 20 --resolve "kryptosbot.com:80:$IP" -o /dev/null \
  -w 'http  code=%{http_code} location=%{redirect_url}\n' http://kryptosbot.com

# Is 443 even listening? Distinguishes a bad cert from no listener at all.
timeout 8 bash -c "cat < /dev/null > /dev/tcp/$IP/443" && echo "443 open" || echo "443 closed"

# The certificate HSTS browsers require
echo | timeout 15 openssl s_client -connect "$IP:443" -servername kryptosbot.com 2>&1 \
  | grep -E "Verify return code|subject="
```

Look for: `302` (not 301), a `Location` on github.com, 443 open, and
`Verify return code: 0 (ok)`.

**What actually happened on 2026-07-26.** HTTP worked correctly and returned
`302 -> http://github.com/jcolinpatrick/kryptos`, chaining to
`https://github.com/jcolinpatrick/kryptos` in two hops. HTTPS was completely dead: port
443 was not listening on either endpoint, so there was no certificate to inspect and no
handshake to fail. GoDaddy had not provisioned a forwarding certificate.

That combination is the bad case, because HSTS makes HTTPS the *only* path returning
visitors can take. Their browser rewrites to `https://` before sending a request, hits a
closed port, and times out. Inbound links from search results are also overwhelmingly
`https://`. Plain-HTTP forwarding reaches only visitors typing the bare hostname whose
browser falls back after the HTTPS attempt fails, and reaches nobody with HTTPS-Only
mode enabled.

If 443 does not open:

1. Confirm SSL forwarding is actually **enabled** in the GoDaddy panel, not just
   "forward only." If the toggle is off, waiting changes nothing.
2. If it is on, give it time. GoDaddy provisions the certificate asynchronously, and it
   can take hours. Poll for the listener rather than guessing:
   ```bash
   while ! timeout 8 bash -c "cat < /dev/null > /dev/tcp/3.33.152.147/443" 2>/dev/null; do
     echo "$(date '+%H:%M:%S') still closed"; sleep 180
   done; echo "443 open"
   ```
3. If it never comes up, switch to the GitHub Pages fallback below. That path gets a
   real Let's Encrypt certificate automatically and satisfies HSTS for every visitor.

### 4. Stop services and shut down

```bash
sudo systemctl stop kryptosbot-api.service
sudo systemctl disable kryptosbot-api.service    # so it does not start on boot mid-move
sudo systemctl stop nginx
sudo shutdown -h now
```

Disabling the API service matters if the machine gets powered on at the new location
before the network is ready. It avoids a half-live service answering on an address DNS
does not point to.

---

## Fallback: GitHub Pages on the apex domain

Use this when registrar forwarding cannot serve HTTPS. GitHub Pages issues a real
Let's Encrypt certificate for a custom apex domain, so HSTS is satisfied and returning
visitors get through. It also puts the explanation on kryptosbot.com itself rather than
bouncing people to a repository they did not ask for.

**Prepared and standing by, not live.** Branch `site-holding-page` (pushed 2026-07-26)
is an orphan branch containing only four files:

```
.nojekyll         suppresses Jekyll processing
CNAME             kryptosbot.com
index.html        self-contained holding page, inline CSS, no external requests
kryptosbot.png    logo, doubles as favicon
```

It is an orphan branch on purpose: no repo history or source is reachable from it, so
serving it exposes nothing beyond the page. It is deliberately **not** named `gh-pages`,
because that name can trigger automatic publication. Nothing happens until Pages is
explicitly pointed at it.

### Activating

1. **GitHub:** repo Settings, Pages. Source: Deploy from a branch. Branch:
   `site-holding-page`, folder `/ (root)`. Save. The `CNAME` file in the branch sets the
   custom domain to kryptosbot.com automatically.
2. **GoDaddy:** delete the domain forward. Leaving it in place overrides the A record and
   the Pages site will never be reached.
3. **GoDaddy:** add A records for the apex pointing at GitHub Pages:
   ```
   185.199.108.153
   185.199.109.153
   185.199.110.153
   185.199.111.153
   ```
   Optionally add a `www` CNAME to `jcolinpatrick.github.io`.
4. **Wait for the certificate.** GitHub provisions it only after DNS resolves to Pages.
   Usually minutes, occasionally up to a few hours. In Settings, Pages, the "Enforce
   HTTPS" checkbox becomes available once the certificate exists. Tick it.

### Verifying

```bash
curl -s "https://dns.google/resolve?name=kryptosbot.com&type=A" \
  | python3 -c "import json,sys; [print(a['data']) for a in json.load(sys.stdin).get('Answer',[])]"

curl -sS --max-time 20 -o /dev/null \
  -w 'code=%{http_code} bytes=%{size_download}\n' https://kryptosbot.com

echo | timeout 15 openssl s_client -connect kryptosbot.com:443 -servername kryptosbot.com 2>&1 \
  | grep -E "Verify return code|subject="
```

Success is `200`, a certificate issued by Let's Encrypt with subject covering
kryptosbot.com, and `Verify return code: 0 (ok)`. At that point HSTS is satisfied and
every visitor, returning or not, sees the holding page.

### Deactivating on return

Order matters. Repointing DNS while Pages still claims the domain is harmless, but
leaving the custom domain set on Pages after the site returns can interfere with
certificate renewal.

1. GitHub Settings, Pages: set Source to None, and clear the custom domain.
2. GoDaddy: replace the four Pages A records with a single A record for the new WAN IP.
3. Continue with "Coming back online" below.

The `site-holding-page` branch can stay in the repo indefinitely. It costs nothing and is
ready for the next planned outage.

---

## Coming back online

The README notice and the forward both stay in place until service is confirmed working.
Do not revert them first.

### 1. Confirm the network can host at all

This is the step most likely to fail after a move, and none of the rest matters until it
passes.

```bash
curl -4 -s https://api.ipify.org       # the new WAN IP
ip -4 addr show | grep inet            # the machine's LAN address
```

Check three things at the new location:

1. **Ports 80 and 443 forwarded** from the router to this machine's LAN address. Without
   this, DNS can be perfect and nothing will answer. Port 80 is also required for
   Let's Encrypt renewal, not just for the site.
2. **A routable WAN IP.** If `api.ipify.org` reports one address but the router's WAN
   interface shows a `100.64.x.x` address, the ISP is using carrier-grade NAT and
   inbound hosting is not possible on that connection. Self-hosting then needs a tunnel
   (for example Cloudflare Tunnel) or a different plan, and this procedure will not be
   enough on its own.
3. **Inbound 80/443 not blocked by the ISP.** Some residential plans block them.

### 2. Restore DNS

Delete the GoDaddy forward, then re-add the A record pointing at the new WAN IP. Both
steps are required: leaving the forward in place will override the A record.

```bash
dig +short kryptosbot.com A            # confirm it matches the new WAN IP
```

Wait for propagation before continuing. `check_dns.sh` is still paused at this point, so
nothing will alert on the intermediate state.

### 3. Restore services and the certificate

```bash
sudo systemctl enable --now kryptosbot-api.service
sudo systemctl start nginx
sudo systemctl status kryptosbot-api.service nginx

# Certificates expire after 90 days. A long move can outlast one.
sudo certbot certificates                # check expiry
sudo certbot renew --dry-run             # verify the challenge path works on the new network
sudo certbot renew                       # only if actually near or past expiry
```

If the certificate expired while the machine was off, renewal needs port 80 reachable
from the internet, which is why the port-forwarding check comes first.

### 4. Rebuild and verify the site

```bash
cd /home/cpatrick/kryptos
source venv/bin/activate && python3 ops/site_builder/build.py
ops/deploy/cron_update.sh --force

curl -sSI https://kryptosbot.com | head -20      # expect 200, no redirect
curl -sS https://kryptosbot.com/browse/ -o /dev/null -w '%{http_code}\n'
```

### 5. Restore the monitors

```bash
crontab -e        # uncomment the lines paused earlier
crontab -l        # confirm, and compare against ~/crontab.backup.<date>
```

`check_dns.sh` keeps state in `logs/.dns_check_state`. On its first run after the
outage it compares against a stale entry and will send a one-time "recovered" notice.
That is expected. To suppress it, delete the state file before re-enabling:

```bash
rm -f /home/cpatrick/kryptos/logs/.dns_check_state
```

### 6. Revert the README notice

Only after the site is confirmed serving. Remove from `README.md`:

- the `Site status` section and the offline line in the centered header block
- the six inline "offline while the server relocates" annotations
- restore the original four-link navigation row

The original wording is in git history:

```bash
git log --oneline -- README.md          # find the commit that added the notice
git show <commit>^:README.md            # the pre-notice version, for reference
```

Then push to `main` as usual, subject to whatever push constraints are current.

---

## What breaks during the outage, at a glance

| Surface | State while offline |
|---|---|
| kryptosbot.com over HTTP | Forwarded to the GitHub repository (302), verified working |
| kryptosbot.com over HTTPS | Dead until GoDaddy provisions a forwarding certificate or the Pages fallback is activated. HSTS forces returning visitors down this path, so this is the case that matters. |
| Workbench, VIC workbench, cylinder viewer | Unavailable. Browser apps served by the site. |
| Theory submission API (`127.0.0.1:8321`) | Stopped. Submissions arrive as GitHub issues instead. |
| Search index, browse pages, elimination pages | Unavailable on the web. Source data still in the repo. |
| ntfy alerting | Paused deliberately. Nothing is watching, by design. |
| Nightly review and site rebuild crons | Paused. No data is lost; they rebuild from the repo on return. |
| The research repo itself | Fully available. Unaffected by the outage. |

---

## Reverting early

If the move finishes faster than expected, or the forward causes trouble, the whole
change backs out in two steps and needs no code change:

1. Delete the GoDaddy forward and restore the A record to the current WAN IP.
2. Uncomment the cron lines.

The README notice can stay up harmlessly for a while after the site returns. It is
inaccurate at that point rather than damaging, so it does not need to be part of the
emergency path.
