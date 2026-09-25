#!/usr/bin/env python3
"""
Memory load test: many-argument form POSTs at a fixed rate, with the Kong
worker's memory sampled while the load runs.

Reproduces a shop "price lookup" endpoint: a POST
application/x-www-form-urlencoded body carrying thousands of arguments
(default 20000), sent at hundreds of requests per minute. While the load
runs, the script samples the Lua heap (collectgarbage("count")) and the RSS
of the worker that serves the traffic, through Karna's X-Karna-Profile
probe (KARNA_PROFILE must be set on the worker; run Kong with
KONG_NGINX_WORKER_PROCESSES=1 so every request, probe included, lands on the
same worker). At the end it asks the worker for a full GC and reports the
live set, so a leak (memory that survives a full collection) is told apart
from garbage the incremental collector had not reached yet.

Example (DEV stack, service on Host argmem.local):

    ./argmem_load.py --url http://localhost:28000/it/api/catalog/price-lookup \
        --host argmem.local --args 20000 --rate 300 --duration 120 --label before

Output: one CSV line per sample on stdout (t, lua_mb, rss_mb, sent, ...) and
a summary (start / peak / end, slope in MB/min, status distribution, latency
percentiles). Nothing is written to disk unless --csv is given.
"""
import argparse
import json
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request


def build_body(n_args, shape):
    """A form body with n_args arguments.

    dup    : ids[]=<n>  repeated (what a PHP/Symfony list of product ids looks
             like; Karna suffixes the duplicated labels with :<n>)
    unique : id_<n>=<n>
    mixed  : p[<n>][code]=SKU%2D<n> / p[<n>][qty]=<q> alternating — distinct
             names AND percent-encoded values, so every transformation
             produces a new string (worst case for the transform cache)
    """
    if shape == "dup":
        parts = ["ids%%5B%%5D=%d" % (100000 + i) for i in range(n_args)]
    elif shape == "unique":
        parts = ["id_%d=%d" % (i, 100000 + i) for i in range(n_args)]
    else:
        parts = []
        for i in range(n_args):
            if i % 2 == 0:
                parts.append("p%%5B%d%%5D%%5Bcode%%5D=SKU%%2D%d" % (i // 2, 100000 + i))
            else:
                parts.append("p%%5B%d%%5D%%5Bqty%%5D=%d" % (i // 2, i % 9 + 1))
    return "&".join(parts).encode()


def http(url, host, method="GET", body=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=body, method=method)
    if host:
        req.add_header("Host", host)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            return r.status, data, time.monotonic() - t0
    except urllib.error.HTTPError as e:
        data = e.read()
        return e.code, data, time.monotonic() - t0
    except Exception as e:  # noqa: BLE001
        return "ERR:%s" % type(e).__name__, b"", time.monotonic() - t0


def probe(url, host, mode="mem"):
    status, data, _ = http(url, host, headers={"X-Karna-Profile": mode})
    if status != 200:
        raise RuntimeError("probe %s failed: %s %r" % (mode, status, data[:200]))
    return json.loads(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="proxy URL of the endpoint under test")
    ap.add_argument("--host", default=None, help="Host header (route selector)")
    ap.add_argument("--args", type=int, default=20000, help="arguments per body (default 20000)")
    ap.add_argument("--shape", choices=["dup", "unique", "mixed"], default="dup", help="argument naming (default dup: ids[]=n)")
    ap.add_argument("--rate", type=float, default=300, help="requests per minute (default 300)")
    ap.add_argument("--duration", type=int, default=120, help="seconds of load (default 120)")
    ap.add_argument("--concurrency", type=int, default=4, help="parallel senders (default 4)")
    ap.add_argument("--sample-every", type=float, default=5.0, help="seconds between memory samples")
    ap.add_argument("--label", default="run", help="label printed in the summary")
    ap.add_argument("--csv", default=None, help="also append the samples to this CSV file")
    ap.add_argument("--no-gc", action="store_true", help="skip the final full-GC live-set probe")
    args = ap.parse_args()

    body = build_body(args.args, args.shape)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    interval = 60.0 / args.rate

    print("# label=%s args=%d shape=%s body=%d bytes rate=%.0f/min duration=%ds concurrency=%d"
          % (args.label, args.args, args.shape, len(body), args.rate, args.duration, args.concurrency))

    # one warm-up request so the status of the endpoint is known before the load
    st, data, lat = http(args.url, args.host, "POST", body, headers)
    print("# warm-up: status=%s latency=%.3fs body=%r" % (st, lat, data[:80]))

    base = probe(args.url, args.host, "gc" if not args.no_gc else "mem")
    print("# worker pid=%s id=%s  baseline (after full GC): lua=%.1f MB rss=%.1f MB"
          % (base["pid"], base["worker_id"], base["lua_kb"] / 1024, (base["rss_kb"] or 0) / 1024))

    stats = {"sent": 0, "status": {}, "lat": []}
    lock = threading.Lock()
    stop = threading.Event()
    t_start = time.monotonic()
    next_slot = [t_start]

    def sender():
        while not stop.is_set():
            with lock:
                slot = next_slot[0]
                next_slot[0] = slot + interval
            delay = slot - time.monotonic()
            if delay > 0:
                if stop.wait(delay):
                    return
            if time.monotonic() - t_start >= args.duration:
                return
            st, _, lat = http(args.url, args.host, "POST", body, headers, timeout=60)
            with lock:
                stats["sent"] += 1
                stats["status"][st] = stats["status"].get(st, 0) + 1
                stats["lat"].append(lat)

    threads = [threading.Thread(target=sender, daemon=True) for _ in range(args.concurrency)]
    for t in threads:
        t.start()

    samples = []
    csv = open(args.csv, "a") if args.csv else None
    print("t_s,lua_mb,rss_mb,sent")
    while time.monotonic() - t_start < args.duration:
        time.sleep(args.sample_every)
        try:
            m = probe(args.url, args.host, "mem")
        except Exception as e:  # noqa: BLE001
            print("# probe error: %s" % e, file=sys.stderr)
            continue
        with lock:
            sent = stats["sent"]
        row = (time.monotonic() - t_start, m["lua_kb"] / 1024, (m["rss_kb"] or 0) / 1024, sent)
        samples.append(row)
        line = "%.0f,%.1f,%.1f,%d" % row
        print(line)
        if csv:
            csv.write("%s,%s\n" % (args.label, line))
            csv.flush()
    stop.set()
    for t in threads:
        t.join(timeout=60)

    end_mem = probe(args.url, args.host, "mem")
    end_gc = None if args.no_gc else probe(args.url, args.host, "gc")

    # slope: least squares over the samples, in MB per minute
    def slope(idx):
        if len(samples) < 3:
            return float("nan")
        xs = [s[0] / 60.0 for s in samples]
        ys = [s[idx] for s in samples]
        mx, my = statistics.mean(xs), statistics.mean(ys)
        den = sum((x - mx) ** 2 for x in xs)
        if den == 0:
            return float("nan")
        return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den

    lat = sorted(stats["lat"])

    def pct(p):
        if not lat:
            return float("nan")
        return lat[min(len(lat) - 1, int(p * len(lat)))]

    print("# ---- summary [%s] ----" % args.label)
    print("# requests: %d in %.0fs (%.1f/min) status=%s"
          % (stats["sent"], args.duration, stats["sent"] * 60.0 / args.duration, stats["status"]))
    print("# latency: p50=%.3fs p95=%.3fs max=%.3fs" % (pct(0.5), pct(0.95), lat[-1] if lat else float("nan")))
    if samples:
        print("# lua heap MB: baseline=%.1f first=%.1f peak=%.1f last=%.1f slope=%+.1f MB/min"
              % (base["lua_kb"] / 1024, samples[0][1], max(s[1] for s in samples), samples[-1][1], slope(1)))
        print("# rss      MB: baseline=%.1f first=%.1f peak=%.1f last=%.1f slope=%+.1f MB/min"
              % ((base["rss_kb"] or 0) / 1024, samples[0][2], max(s[2] for s in samples), samples[-1][2], slope(2)))
    print("# end (no gc):  lua=%.1f MB rss=%.1f MB" % (end_mem["lua_kb"] / 1024, (end_mem["rss_kb"] or 0) / 1024))
    if end_gc:
        print("# end (full gc): lua=%.1f MB rss=%.1f MB  -> retained vs baseline: %+.1f MB lua, %+.1f MB rss"
              % (end_gc["lua_kb"] / 1024, (end_gc["rss_kb"] or 0) / 1024,
                 (end_gc["lua_kb"] - base["lua_kb"]) / 1024,
                 ((end_gc["rss_kb"] or 0) - (base["rss_kb"] or 0)) / 1024))
    if csv:
        csv.close()


if __name__ == "__main__":
    main()
