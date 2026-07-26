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
misbehaves. Check from a machine that is not on your LAN, or the local nginx will answer
instead of the forward.

```bash
# Should show a 3xx with a Location header pointing at github.com
curl -sSI https://kryptosbot.com | head -20

# Certificate must be valid for kryptosbot.com, or HSTS blocks returning visitors
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' https://kryptosbot.com
echo | openssl s_client -connect kryptosbot.com:443 -servername kryptosbot.com 2>/dev/null \
  | openssl x509 -noout -subject -dates
```

Look for: a 302 (not 301), a `Location` on github.com, and a certificate whose subject
covers kryptosbot.com and has not expired.

If the certificate is missing or invalid, returning visitors get a hard TLS error rather
than a redirect. That is worse than a plain timeout, because it looks like the domain has
been hijacked. In that case remove the forward and fall back to leaving DNS alone: the
README notice on GitHub still explains the outage to anyone who arrives from search or a
link.

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
| kryptosbot.com and all subpages | Forwarded to the GitHub repository (302) |
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
