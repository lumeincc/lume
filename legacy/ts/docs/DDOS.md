# Abuse and denial of service

What LUME already does, what it cannot do, and the one change that has to happen
at the same moment as putting a CDN in front of the relay.

---

## The honest split

There are two different problems and only one of them is solvable in this
repository.

**Application-layer abuse** — someone using the API faster or more often than a
real client would. This is code, and it is largely done: see the inventory
below.

**Volumetric attack** — someone saturating the network link. The packets are
dropped before Node is reached; no amount of Express middleware helps, because
the process never sees them. This needs capacity in front of the origin, which
means a CDN. Writing our own would be building a smaller version of something
that has to be bigger than the attacker, which is not a thing a small team wins.

So: keep hardening the first, buy the second.

---

## What is already in place

| Control | Where | Value |
|---|---|---|
| Per-endpoint rate limits | 16 limiters across the routes | varies per route |
| Public endpoint limit | `index.ts` | 60/min per address |
| WebSocket handshakes | `websocket/handler.ts` | 10/min per address |
| WebSocket sockets per address | `websocket/handler.ts` | 128 concurrent |
| WebSocket sockets per process | `websocket/handler.ts` | 5000 concurrent |
| WebSocket sockets per user | `websocket/handler.ts` | 5, oldest evicted |
| Inbound frame budget | `withinFrameBudget` | flooding closes the socket (1008) |
| WebSocket frame size | `WS_MAX_PAYLOAD_BYTES` | 64 KB |
| JSON body size | `JSON_LIMIT` | 8 MB |
| Header deadline | `HEADERS_TIMEOUT_MS` | 20s — the slow-loris control |
| Request deadline | `REQUEST_TIMEOUT_MS` | 120s |
| Table growth | TTL or cap on all nine tables | see below |

Every table is bounded, verified rather than assumed: `pending_messages` 30 days
plus a per-user cap, `files` a TTL with blobs deleted alongside the rows,
`request_signatures` 180 seconds, `invite_tokens` a TTL, one-time prekeys are
consumed on use, and the rest only grow through a user's own actions.

---

## Putting Cloudflare in front of Render

Free tier covers the volumetric case: L3/L4 absorption, a WAF, and challenges on
suspicious bursts. The client is already behind Vercel, which has its own edge —
the relay is the exposed one.

### The change that must not be forgotten

**Adding Cloudflare adds a proxy hop.** The chain becomes

```
client → Cloudflare → Render → app
```

Today `TRUST_PROXY=1` is correct, because Render alone is one hop. The moment
Cloudflare is in front, `X-Forwarded-For` carries one more entry and the server
reading "one hop in" lands on Cloudflare's address rather than the caller's.

Every one of the 16 rate limiters then buckets **all traffic on earth into one
key**. It will not error. It will not log anything unusual. It will look exactly
like a working limiter right up to the moment it rate-limits every user
simultaneously, which is a self-inflicted outage that looks like the attack it
was installed to stop.

So the two steps are one step:

```
TRUST_PROXY=2
```

set on Render **in the same change** as pointing DNS at Cloudflare. Do not do
one and then the other.

`server/src/utils/trustProxy.ts` refuses to boot on a value it cannot parse, so
a typo is a failed deploy rather than a silent fallback to zero.

### Verifying it afterwards

The check is that the server sees real client addresses, not Cloudflare's. With
`LOG_SECURITY=1`, make a request from a known address and confirm the limiter
key matches it. Two addresses hitting a limited endpoint should get independent
budgets; if one exhausts the other's, the hop count is too low.

### Order of work

1. Cloudflare account, add the domain, DNS moved (nameserver change, ~an hour to
   propagate).
2. Proxy mode on for the relay hostname (orange cloud), not DNS-only — DNS-only
   leaves the origin address published and the whole exercise pointless.
3. `TRUST_PROXY=2` on Render, same change.
4. Verify as above.
5. Only then consider WAF rules, which are tuning and can wait.

### Do not skip

Cloudflare hides the origin only if the origin is not reachable directly.
Render's `*.onrender.com` hostname stays public, so an attacker who finds it can
go around the CDN entirely. Restricting the origin to Cloudflare's published IP
ranges is what makes the protection real rather than decorative.

---

## Known gaps

**Backups — narrower than it first looks.** Render's free plan has an *ephemeral*
filesystem, so the database is already reset on every deploy. That is by design,
not an oversight: LUME is client-authoritative, and a client re-binds its
existing identity silently on the next unlock, keeping its safety numbers and
sessions. Backing up a disk that does not survive a restart would be theatre.

What is actually lost on a reset is undelivered messages (at most 30 days old)
and uploaded files (their own TTL). Both bounded, neither reconstructible.

The real question is therefore not "add backups" but "should server state be
durable at all" — a paid plan with a mounted disk, at which point backups start
to matter. That is a cost decision, not an engineering one.

**Metadata.** The relay cannot read messages and does not try to. It does
necessarily see who talks to whom and when. That is the honest limit of the
design and worth stating publicly rather than being caught claiming otherwise.

**Account cost, and the one table without a real bound.** Registration creates a
`users` row plus twenty one-time prekeys, and nothing prunes them. Every other
table has a TTL or a cap; this one was counted as "grows only through a user's
own actions", which is true and beside the point — mass registration is a user
action too.

The window was tightened from ten minutes to an hour for the same allowance of
thirty, cutting one address from 4,320 accounts a day to 720. Still generous
enough for a campus or café behind one NAT.

Inactive accounts now expire. Decided by the owner on 2026-08-06: an account
untouched for `INACTIVE_USER_MAX_AGE_DAYS` is deleted and its username released
for anyone to claim.

The delete is safe mechanically — the row is a cache and a client re-binds its
existing identity silently on the next unlock, keeping its safety numbers and
sessions — and every child table cascades, so prekeys, pending messages, file
rows, group memberships and blocks go with it. File blobs do not cascade, so
their ids are collected first and unlinked.

Two deliberate choices in the shape of it:

- **The default is 365 days.** This is irreversible, so the default must not be
  able to surprise anyone. A year of total silence is unambiguous; a tighter
  number chosen before there is usage data would be a guess enforced by
  deletion. The server refuses to boot with a threshold under 30 days.
- **Each pass is bounded** (`INACTIVE_USER_BATCH`, default 200, every six
  hours). Deleting an unbounded set would hold a write transaction over the
  whole table while the server serves live traffic. There is no deadline here.

`last_seen` is null until a first authenticated action, so the query falls back
to `created_at` — otherwise an account registered in bulk and never touched,
exactly the kind worth reclaiming, would never qualify.

### Reissuing a released username

**A freed username may be claimed by anyone.** Owner decision, 2026-08-06, and it
covers both ways a name comes free: the owner deleted the account, or it was
reclaimed for inactivity.

The obvious worry is impersonation — someone takes a name you had verified and
inherits the trust attached to it. That does not happen here, and the reason is
structural rather than a matter of care:

- **Contacts are pinned to an identity key, not to a username**
  (`client/src/lib/identityPinning.ts`, enforced on the outbound bundle in the
  chat and group send paths and on the inbound X3DH header in
  `useMessengerSync`). A new holder of the name has different keys, so their
  prekey bundle is *refused* — not merely displayed with a different safety
  number.
- **Safety numbers are computed from both parties' identity keys**
  (`crypto/safetyNumber.ts`), and the username is not an input. A verified number
  cannot silently come to mean a different person.
- Trust-on-first-use applies only where nothing is known yet, so it cannot be
  used to overwrite an existing anchor.

What a correspondent *does* see is their existing contact ceasing to work: the
pin refuses the new bundle rather than quietly re-pointing at whoever holds the
name now. Failing visibly is the intended behaviour — the alternative is the
impersonation this section is about.
