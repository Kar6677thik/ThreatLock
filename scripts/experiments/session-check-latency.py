"""Measures request latency for GET /api/me, to price the per-request session check (SPEC §16.3).

Run it against the API started three ways and compare:
  1. Auth__Mode=StatelessJwt       -> no session check (baseline)
  2. default (SessionChecked)      -> check served from the Redis cache
  3. default, with Redis stopped   -> every check falls back to PostgreSQL

Usage: python scripts/experiments/session-check-latency.py [label] [requests]
Standard library only. Uses one keep-alive connection so we time the server, not TCP setup.
"""

import http.client
import json
import statistics
import sys
import time
import uuid

HOST, PORT = "127.0.0.1", 5080
LABEL = sys.argv[1] if len(sys.argv) > 1 else "run"
REQUESTS = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
WARMUP = 200

conn = http.client.HTTPConnection(HOST, PORT)


def call(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request(method, path, body=json.dumps(body) if body else None, headers=headers)
    response = conn.getresponse()
    payload = response.read()
    return response.status, payload


run = uuid.uuid4().hex[:10]
status, payload = call("POST", "/api/auth/register-org", {
    "orgName": f"Latency {run}", "orgSlug": f"latency-{run}", "displayName": "Bench",
    "email": f"bench-{run}@latency.test", "password": "correct horse battery staple",
})
assert status == 201, (status, payload)
token = json.loads(payload)["accessToken"]

for _ in range(WARMUP):
    call("GET", "/api/me", token=token)

samples = []
for _ in range(REQUESTS):
    start = time.perf_counter()
    status, _ = call("GET", "/api/me", token=token)
    samples.append((time.perf_counter() - start) * 1000)
    assert status == 200, status

samples.sort()
pct = lambda p: samples[min(len(samples) - 1, int(p / 100 * len(samples)))]
print(f"{LABEL}: n={REQUESTS} p50={pct(50):.2f}ms p95={pct(95):.2f}ms p99={pct(99):.2f}ms mean={statistics.mean(samples):.2f}ms")
