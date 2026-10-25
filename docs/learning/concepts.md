# Concepts primer

Read this before the code, and come back to it when a milestone touches a concept. Each entry answers four questions:

- **What** it is, in plain words.
- **Why** ThreatLock needs it.
- **When** you meet it (which milestone).
- **Watch out** for the common mistake.

Field Guide section numbers are in brackets, e.g. [FG 8.6].

---

## Part 1. Identity and sessions

### 1.1 Authentication vs authorisation [FG 8.1]

- **What:** authentication answers "who are you?" (password check). Authorisation answers "are you allowed to do this?" (can this user read that note?).
- **Why:** ThreatLock attacks are about *stolen authentication*. The attacker passes authentication with someone else's credential, so every authorisation check still says yes. That's why we need detection at all.
- **When:** M2.
- **Watch out:** checking "is logged in" and forgetting "owns this resource" (broken object-level authorisation, the #1 API vulnerability in OWASP's list).

### 1.2 Sessions vs tokens [FG 8.2, 8.3]

- **What:** a *session* is state the server keeps ("session 42 belongs to Asha, created at 10:01"); the client holds only an id. A *token* carries its own claims, signed so the server can trust it without looking anything up.
- **Why:** sessions are easy to revoke (delete the row) but cost a lookup. Tokens are cheap to check but hard to revoke. ThreatLock combines them. See [ADR-0002](../adr/0002-short-lived-jwt-plus-server-side-session-check.md).
- **When:** M2 (tokens only), M3 (both).
- **Watch out:** "stateless" sounds like an advantage until you need to sign someone out *now*.

### 1.3 JWT anatomy and validation [FG 8.6]

- **What:** a JSON Web Token is `base64url(header).base64url(payload).signature`. Anyone can *read* the payload; only the key holder can *produce* a valid signature.
- **Why:** our access token. Validation must check signature, issuer, audience and expiry. Decoding is not validating.
- **When:** M2.
- **Watch out:** accepting `alg: none`, not checking `aud`, putting secrets in the payload (it's not encrypted), huge clock skew.

### 1.4 Why stateless JWT revocation is hard (Break B1)

- **What:** if the server never stores anything about issued tokens, it has nothing to update when you "revoke". The token stays valid until `exp`.
- **Why:** this is Break B1. With a 60-minute token, a "revoked" user keeps access for up to 60 minutes.
- **When:** M2 (break), M3 (fix).
- **Fixes, ranked by how often you'll see them:** short expiry + refresh tokens; a server-side check of a session id (our choice); a deny-list of token ids; a per-user "tokens issued before T are invalid" timestamp.

### 1.5 Refresh tokens, rotation and reuse detection [FG 8.14]

- **What:** a long-lived secret used *only* to get new short-lived access tokens. *Rotation* means every use returns a new refresh token and invalidates the old one. *Reuse detection*: if an already-used refresh token shows up again, two parties have it, so one of them is a thief. Kill the session.
- **Why:** keeps users signed in for days while the token that travels on every request lives for 5 minutes. Reuse detection turns cookie theft into a near-certain signal (detector D5).
- **When:** M3.
- **Watch out:** race conditions. Two browser tabs refreshing at the same moment look exactly like reuse. ThreatLock's answer (M3): a second use within 5 seconds gets `409` and changes nothing, so the client retries with the newer cookie; after 5 seconds it's treated as theft and the session dies. The SPA also shares one in-flight refresh between all its requests.

### 1.6 Cookies: HttpOnly, Secure, SameSite, CSRF [FG 25.8]

- **What:** `HttpOnly` hides a cookie from JavaScript (limits XSS theft). `Secure` sends it only over HTTPS. `SameSite=Strict` stops the browser sending it on requests started by other sites, which is the core of CSRF defence.
- **Why:** our refresh token is a cookie. Every endpoint that reads a cookie for authentication is a CSRF target; that's one reason only `/api/auth/refresh` uses the cookie.
- **When:** M3.
- **Watch out:** `SameSite=Lax` still sends cookies on top-level GET navigations; never let a GET change state.

### 1.7 Tenant isolation [FG 8.13, 25.37]

- **What:** one customer's data must be invisible to another, even though they share tables.
- **Why:** ThreatLock is multi-tenant; policies, anomalies and audit chains are all per org.
- **When:** M2, then forever.
- **Watch out:** taking `orgId` from the request body or URL. Always take it from the authenticated principal.

### 1.8 Password storage and lockout [FG 25]

- **What:** never store passwords, store a *slow* salted hash. ASP.NET Core Identity uses PBKDF2 (HMAC-SHA512, 100,000 iterations): checking one guess costs tens of milliseconds, which is nothing for a user and ruinous for someone trying billions of guesses against a stolen database. *Lockout* stops online guessing: 5 wrong passwords in a row lock the account for 15 minutes.
- **Why:** M2's login. Length beats complexity rules (NIST SP 800-63B), so we require 12+ characters and nothing else.
- **When:** M2.
- **Watch out:** lockout is itself a denial-of-service lever (anyone can lock *your* account by typing your email wrong 5 times). Real systems add per-IP rate limits and CAPTCHAs; we note it and move on.

### 1.9 User enumeration

- **What:** any difference in how the server answers "wrong password" versus "no such user" (message, status code, *or response time*) tells an attacker which emails have accounts, giving them a target list for phishing and password guessing.
- **Why:** ThreatLock answers both with the same 401 and the same text, and for unknown or locked accounts it still verifies a dummy hash, so both paths take about the same time.
- **When:** M2 (`DummyPasswordHash`).
- **Watch out:** sign-up necessarily reveals "that email is taken". That's an accepted trade-off here; high-security systems email the address instead of answering inline.

### 1.10 Object-level authorization and mass assignment [FG 25.10, 25.11]

- **What:** *Object-level authorization* means checking, for every single record, that this caller may touch it, not just that they're logged in. *Mass assignment* is when an API copies request fields straight onto a database object, so a client can set fields it shouldn't (`"orgId": "<someone else's>"`).
- **Why:** notes are filtered by org (EF Core query filter) *and* by owner-or-shared; org and owner are always taken from the token. Tests send other orgs' ids and smuggled `orgId` fields to prove both.
- **When:** M2.
- **Watch out:** returning 403 for "exists but not yours" leaks existence. We return 404 unless the caller could already see the item.

### 1.11 Fail closed vs fail open [FG 17, 25.3]

- **What:** when a security check *can't run* (its database is down), the system must pick: *fail open* (let the request through) or *fail closed* (refuse it). Fail open keeps the app up and lets attackers through; fail closed blocks attackers and also legitimate users.
- **Why:** the session check fails closed with `503` when both Redis and PostgreSQL are unreachable. `503` (not `401`) tells the client "try again", so the SPA doesn't throw the user out. When only Redis is down the check falls back to PostgreSQL, so most outages cost latency, not availability.
- **When:** M3.
- **Watch out:** fail-open bugs hide in `catch` blocks. `catch { return true; }` around a permission check is the classic.

---

## Part 2. Moving events reliably

### 2.1 Activity events vs audit logs [FG 25.18]

- **What:** activity events are high-volume behavioural telemetry ("read note 17"), kept for 30 days, used by detectors. Audit entries are low-volume, security-relevant facts ("sessions revoked because of anomaly X"), kept for a long time as evidence.
- **Why:** mixing them gives you either a useless audit log (millions of note reads) or detectors starved of data.
- **When:** M4 (events), M7 (audit).

### 2.2 At-least-once delivery and idempotency [FG 18]

- **What:** across a network you can choose *at-most-once* (may lose messages) or *at-least-once* (may duplicate them). "Exactly once" is achieved in *effect* by at-least-once delivery plus consumers that produce the same result when they see a message twice: that's *idempotency*.
- **Why:** events, anomalies, response jobs and notifications can all be retried. Each needs a natural key that makes the second attempt a no-op: event id, anomaly dedupe key, `anomaly_id` on the job, `(anomaly_id, recipient)` on notifications, `idempotency_key` on audit entries.
- **When:** M4 onwards; the centrepiece of M6 (Break B4).
- **Watch out:** side effects outside your database (sending an email, calling a webhook) can't be rolled back. Record intent first, and accept that the external receiver may see a duplicate.

### 2.3 Transactional outbox and the dual-write problem [FG 18]

- **What:** "write to the DB, then publish to the queue" can crash in between, leaving the two out of sync. The *outbox* pattern writes the message into a table **in the same transaction** as the business change; a relay publishes it later.
- **Why:** our `activity_events` table is the outbox for the Redis stream, and response jobs live in the same transaction as their anomaly.
- **When:** M4, M6.

### 2.4 Redis Streams and consumer groups

- **What:** a stream is an append-only log in Redis (`XADD`). A *consumer group* lets several workers share it: each message goes to one consumer (`XREADGROUP`), sits in a *pending entries list* until acknowledged (`XACK`), and can be reclaimed if its consumer dies (`XAUTOCLAIM`).
- **Why:** the event transport. See [ADR-0003](../adr/0003-event-transport-redis-streams-and-postgres-jobs.md).
- **When:** M4.
- **Watch out:** acknowledging *before* processing (that's at-most-once), and unbounded streams (use `MAXLEN ~`).

### 2.5 PostgreSQL as a job queue: `FOR UPDATE SKIP LOCKED` and leases

- **What:** `SELECT ... FOR UPDATE SKIP LOCKED` lets many workers each grab a *different* row without blocking each other. A *lease* (`locked_until`) means that if a worker dies holding a job, another can take it after the lease expires.
- **Why:** response jobs must never be lost and must be inspectable and retryable.
- **When:** M6.
- **Watch out:** a lease shorter than the job's real duration lets two workers run the same job at once. Idempotency saves you anyway, which is the point of having both.

### 2.6 Retries, exponential backoff and jitter [FG 17]

- **What:** wait 1 s, 2 s, 4 s... between retries (exponential), plus some randomness (jitter) so a thousand failed jobs don't all retry at the same instant. After N attempts, stop and park the job (dead letter).
- **When:** M4 (dead-letter stream), M6 (jobs).

### 2.7 Atomic compare-and-set in SQL [FG 11]

- **What:** "read a value, check it, then write" has a race: two requests can both read "unused" before either writes. Put the check *in* the write instead: `UPDATE refresh_tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL`. The database runs it atomically, so exactly one concurrent caller sees "1 row updated"; everyone else sees 0 and knows they lost.
- **Why:** refresh-token rotation (M3). The same pattern returns for job claiming (M6) and anywhere "only once" matters.
- **When:** M3.
- **Watch out:** an ORM that loads an entity, changes it in memory and saves it does *not* do this; it overwrites blindly unless you add a concurrency token.

### 2.8 Effect markers: making a multi-step job idempotent [FG 18]

- **What:** a job with several side effects (revoke, notify, ...) can crash between any two. To make a rerun safe, each step either is naturally idempotent ("set this key to `r`") or records *that it happened* **in the same transaction as its effect**: `UPDATE response_jobs SET notified_at = now()` commits together with the notification rows. A rerun checks the marker and skips the step. Because effect and marker commit or roll back together, "done" and "recorded as done" can never disagree.
- **Why:** Break B4. The naive responder, retried after crashes, notified admins 532 times instead of 300.
- **When:** M6.
- **Watch out:** derive repeated work from durable state, not from what *this* run saw. The naive responder wrote Redis markers only for the sessions its UPDATE returned; on a retry that's an empty list, so a crash in between left revoked sessions cached as "active". Also: read the marker `FOR UPDATE`, or two workers running the same job (lease expired) can both see "not done".

### 2.9 LISTEN/NOTIFY, polling and graceful shutdown

- **What:** PostgreSQL's built-in pub/sub. A session runs `LISTEN response_jobs`; any transaction can `pg_notify('response_jobs', ...)`, and listeners are told **when that transaction commits** (never for a rollback). Notifications aren't stored: a listener that is disconnected misses them.
- **Why:** time to revoke. Polling every 250 ms alone adds up to 250 ms; NOTIFY wakes the Worker as soon as the anomaly and its job commit. Polling stays for the cases nobody announces: retries coming due and expired leases.
- **When:** M6.
- **Watch out:** treat NOTIFY as a hint, never as the queue (the table is the queue). On shutdown, hand a running job back (status `pending`) instead of leaving it to its lease, or every deploy delays in-flight responses by up to 60 s. A crash can't do this, which is exactly why the lease exists too.

---

## Part 3. Detection

### 3.1 Rules vs baselines

- **What:** a *rule* is the same for everyone ("Tor = bad"). A *baseline* is learned per user ("Asha normally reads about 4 notes a minute, give or take 2").
- **Why:** rules are clear and explainable; baselines catch behaviour that is unusual *for this person*. D1, D2, D4, D5 are rules; D3 uses a baseline.
- **When:** M4, M8.

### 3.2 Mean, standard deviation, z-score, EWMA

- **What:** the mean μ is the average; the standard deviation σ measures spread. A value's *z-score* is `(x − μ) / σ`, i.e. how many "typical wiggles" away from normal it is. An *exponentially weighted moving average* gives recent data more weight so the baseline adapts as habits change.
- **Why:** D3 fires when reads per minute exceed `max(floor, μ + k·σ)`.
- **When:** M8.
- **Watch out:** cold start (a new user has no history, so use the org floor); σ = 0 (a perfectly regular user makes any change look infinite, so clamp it: `max(floor, …)` does that); slow poisoning (an attacker can ramp up gradually to drag the baseline upwards).
- **As built (M8):** `Ewma.Update` with α = 0.05 per active minute; the Worker folds complete minutes hourly from `activity_events`, behind a per-user watermark so a rerun changes nothing. Minutes above the user's current threshold are **capped** before they're learnt, or one flagged scraping burst would teach the baseline that bursts are normal (a mutation test removes the cap and a test fails).

### 3.3 Haversine and impossible travel

- **What:** the haversine formula gives the distance between two latitude/longitude points on a sphere. Divide by the time between events to get an implied speed.
- **Why:** D2. If you'd have to fly at 5,000 km/h, one of the two logins isn't really you.
- **When:** M4.
- **Watch out:** GeoIP inaccuracy, VPNs, mobile carriers and corporate proxies. These cause Break B3.

### 3.4 False positives, false negatives, precision and recall

- **What:** a *false positive* flags something benign; a *false negative* misses something bad. *Precision* = of the things we acted on, how many were real. *Recall* = of the real attacks, how many we caught.
- **Why:** every detector trades one for the other. Auto-revoking a CEO during a board meeting is a false positive with a cost, which is why per-org policy and `notify` mode exist.
- **When:** M8, M9.
- **Watch out:** the *base-rate fallacy*. If 1 in 10,000 sessions is malicious, even a detector that's "99 % accurate" will mostly flag innocent people. Always report counts, not just percentages.

### 3.5 Tor exit nodes

- **What:** Tor routes traffic through volunteer relays; the last hop (the *exit node*) is the IP your server sees. The Tor Project publishes the list of exits.
- **Why:** D1. Legitimate users of a corporate notes app rarely use Tor; attackers often do.
- **When:** M4.
- **Watch out:** the list changes hourly, and plenty of attackers use residential proxies instead.

### 3.6 Sliding windows on event time

- **What:** "how many reads in the last minute?" asked at every event, where "the last minute" is measured back from the *event's* timestamp, not the server clock. In Redis it's a sorted set scored by event time: add the event (`ZADD`, keyed by event id so a redelivery counts once), drop members older than the window, count the rest, all in one `MULTI`.
- **Why:** D3 (reads per minute) and D4 (distinct notes read since a new device's first login). Event time means the replay harness can push a day of traffic through in milliseconds and get exactly the counts live traffic would.
- **When:** M8.
- **Watch out:** a window that's never trimmed counts forever. A mutation test that removes the trim is caught only by a test against **real Redis**; the in-memory fake was correct, so unit tests alone didn't notice.

### 3.7 Session fingerprints

- **What:** what a session looked like when it started: here, the device id plus the user agent reduced to a **family** (`Chrome/Windows`). Every later event in the session is compared with it.
- **Why:** D5. A copied cookie or token used from the attacker's machine arrives with a different device id and browser. Break B2: revoked in ~0.5 s.
- **When:** M8.
- **Watch out:** compare families, not full strings, or every browser auto-update looks like a hijack (a mutation test proves it). Don't fingerprint on IP: phones change IP constantly. And all of it is client-supplied: a careful thief copies it too, which is why refresh-token reuse (Critical) backs it up.

---

## Part 4. Decision and response

### 4.1 Policy as data [FG 8.12]

- **What:** behaviour controlled by a versioned document each tenant can edit, rather than by code paths.
- **Why:** Slack's "decision framework". Different orgs tolerate different risks. Storing the version on each anomaly makes every decision explainable after the fact.
- **When:** M5.

### 4.2 Incident containment [FG 25.31]

- **What:** stop the damage first, investigate second. Here: revoke sessions, optionally lock the account.
- **Why:** the reason ThreatLock exists.
- **Watch out:** revocation alone doesn't help if the attacker has the password; hence `revoke_and_lock`.

### 4.3 Notification deduplication and grouping

- **What:** send one notice per *person*, not per role, and fold repeats into one item ("3 more anomalies for this user").
- **Why:** Slack called this out explicitly. Alert fatigue makes admins ignore the alert that matters.
- **When:** M6.

### 4.4 Optimistic concurrency and lost updates [FG 11]

- **What:** two admins open the policy, both edit, both save. Without protection the second save silently erases the first: a *lost update*. *Optimistic* concurrency doesn't lock anything while people edit; instead each save says "I started from version 4", and the database accepts it only if the current version is still 4. The loser gets `409 Conflict` and reloads.
- **Why:** policy edits (M5). The version check is part of the `INSERT ... WHERE (current version) = $expected`, and the `(org_id, version)` primary key catches the last race: two saves that both passed the check at the same instant.
- **When:** M5. Pessimistic locking (hold a lock while the form is open) is the alternative; it's wrong for web forms, which people leave open for hours.
- **Watch out:** "last write wins" is a design choice, not a default you get for free. Most CRUD code has it by accident.

---

## Part 5. Evidence

### 5.1 Hash chains [FG 25.18]

- **What:** each entry stores the hash of the previous entry. Change any entry and its hash changes, so the next entry's `prev_hash` no longer matches, and so on down the chain.
- **Why:** turns "we think nobody touched the audit log" into "we can prove whether anyone did". See [ADR-0005](../adr/0005-audit-log-per-org-sha256-hash-chain.md).
- **When:** M7 (Break B5).
- **Watch out:** someone who can rewrite *every* entry after the change can rebuild a valid chain. Publishing the head hash somewhere else (anchoring) closes that hole. Also, canonical serialisation must be unambiguous: hash the *same bytes* every time.

### 5.2 Advisory locks

- **What:** PostgreSQL locks on an arbitrary number you choose, not on a row. `pg_advisory_xact_lock(n)` is released automatically at commit.
- **Why:** two writers appending to the same org's chain at once would both read the same head and fork the chain. The lock makes them take turns. In M6, two response jobs about the same user both looking for "an unread notification to group into" would both find none and both insert; a lock keyed on the user (`hashtextextended('notify:' || user_id, 0)`) serialises them.
- **When:** M6 (notification grouping), M7 (audit chain).

### 5.3 Canonical serialisation

- **What:** one agreed byte representation of a record, so the same meaning always hashes the same. Three traps, all hit while building M7:
  - **Ambiguous boundaries:** `"ab"+"c"` and `"a"+"bc"` concatenate to the same bytes. Length prefixes (`action=2:ab`) fix it, and null needs its own marker (`~`), or it hashes like `""`.
  - **Storage that rewrites what you gave it:** PostgreSQL `jsonb` reorders keys and drops whitespace, so canonical JSON sorts keys at every level. A mutation test showed it: without the sort, verify failed on chains nobody had touched.
  - **Precision:** .NET timestamps have 100 ns ticks, PostgreSQL keeps microseconds; hash the stored precision.
- **Why:** a hash chain is only as good as its canonical form. If the verifier can't reproduce the appender's bytes, every chain looks tampered, and people learn to ignore the alarm.
- **When:** M7.
- **Watch out:** never change the canonical form for existing rows. Version it instead (`hash_version`).

### 5.4 Prevent vs detect

- **What:** permissions and triggers *prevent* changes by everyone below a certain privilege. Hashes *detect* changes by everyone above it, such as a database superuser who can switch triggers off. Anchors (a head hash kept outside the system) detect the last gap: a rewrite of everything after the edit, or a truncated tail.
- **Why:** Break B5. The trigger refused even the superuser's plain `UPDATE`. With triggers off for one session the edit went through and the row looked normal, but verify named `seq 3`. Deleting the newest entry fooled the chain and not the anchor.
- **When:** M7; real role separation (`threatlock_app` with only `INSERT, SELECT`) in M10.

---

## Part 6. Measuring

### 6.1 Percentiles (p50, p95, p99) [FG 24]

- **What:** sort all measurements; p95 is the value 95 % of them are at or below. The mean hides the slow tail; percentiles show it.
- **Why:** the headline metric is p95 time to revoke.
- **When:** M9.
- **Watch out:** you need enough samples (we use ≥ 200), and you can't average percentiles from different runs.

### 6.2 Testable time (`TimeProvider`) [FG 23]

- **What:** code asks an injected clock for "now" instead of calling `DateTime.UtcNow`. Tests can then freeze or fast-forward time.
- **Why:** lease expiry, backoff, token expiry and sliding windows are all time-based; tests that `Sleep` are slow and flaky.
- **When:** M1 onwards.

### 6.3 Testcontainers [FG 23]

- **What:** a library that starts real Docker containers (PostgreSQL, Redis) from inside a test and throws them away afterwards.
- **Why:** `SKIP LOCKED`, advisory locks, `inet` columns and Redis Streams can't be faked convincingly. Test against the real thing.
- **When:** M1 onwards.

### 6.4 Dependency-injection lifetimes and captive dependencies

- **What:** the DI container creates services as *singleton* (one per app), *scoped* (one per HTTP request) or *transient* (new every time). A singleton that holds a scoped service keeps that one instance forever, so a per-request object leaks across requests and threads. That's a *captive dependency*.
- **Why:** in M2 a singleton tried to take Identity's scoped password hasher; the container's scope validation (on in Development) refused to start. Fix: the singleton builds its own hasher from singleton options.
- **When:** M2.
- **Watch out:** the `DbContext` is scoped and not thread-safe. Never store one in a singleton or share one between parallel tasks.

### 6.5 Testing asynchronous systems [FG 23]

- **What:** when work happens in another process (the Worker), a test can't assert right after the request: the result doesn't exist *yet*. Three habits make such tests reliable:
  1. **Poll, don't sleep.** Check the condition every 100 ms up to a timeout (`Eventually`). Fast when things are fast, and a clear failure when they never happen. A fixed `Sleep(2000)` is both slow and flaky.
  2. **Prove absence with a marker.** "No anomaly appeared" might just mean "not processed yet". So trigger a *different*, known detection afterwards; once it shows up, everything before it in the stream has been processed too.
  3. **Isolate timing-sensitive tests.** Tests that tweak timeouts or inject poison messages run their own Worker on their own stream (or Redis database), so they can't disturb anyone else.
- **Why:** M4's end-to-end tests run the real API and the real Worker against real PostgreSQL and Redis.
- **When:** M4 onwards.
- **Watch out:** "it hasn't happened *yet*" assertions. Asserting an intermediate state (e.g. "not published yet") races the background process; a faster machine breaks it. Assert the final outcome and how you know who caused it. M4's CI run taught this one.
- **Watch out:** ordering guarantees. The marker trick works because one consumer reads the stream in order; with several consumers it would need a per-consumer marker.

---

## Part 7. Shipping

### 7.1 Containers, images and digests [FG 21]

- **What:** an image is a frozen filesystem plus a start command; a container is a running instance. A *tag* (`:abc123`) can be moved; a *digest* (`@sha256:...`) can't.
- **Why:** we deploy by digest so "what is running" is unambiguous.
- **When:** M10.

### 7.2 k3s, Deployments, StatefulSets, Jobs [FG 21]

- **What:** k3s is a lightweight Kubernetes. A *Deployment* runs stateless replicas (API, Worker); a *StatefulSet* runs things with stable storage (PostgreSQL, Redis); a *Job* runs to completion (migrations).
- **When:** M10.

### 7.3 CI/CD over a private network [FG 22]

- **What:** GitHub's runners are on the public internet; the home server isn't. The deploy job joins the tailnet briefly as an ephemeral node, does its work over SSH, and disappears.
- **Why:** deploy without opening a port to the internet. See [ADR-0008](../adr/0008-deployment-k3s-github-actions-tailscale.md).
- **When:** M10.
- **Watch out:** least privilege. The deploy key can run exactly one root helper, which can apply exactly one namespace's manifests.
