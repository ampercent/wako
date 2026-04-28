#!/usr/bin/env python3
"""
Load Test — Threat Hunting Query Engine
=========================================
Simulates concurrent query load against the /hunt/query endpoint
and measures latency, throughput, and error rates.

Usage:
    python scripts/load_test_hunt.py [--url URL] [--concurrency N] [--total N]

Example:
    python scripts/load_test_hunt.py --concurrency 20 --total 100
"""

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# ── Test Queries ─────────────────────────────────────────────────────────

TEST_QUERIES = [
    "process_name == 'powershell.exe' AND severity == 'HIGH'",
    "process_name == 'certutil.exe'",
    "severity == 'CRITICAL'",
    "event_type == 'injection' AND severity != 'LOW'",
    "process_name == 'cmd.exe' AND severity == 'MEDIUM'",
    "process_name == 'wscript.exe' OR process_name == 'mshta.exe'",
    "pid > 1000 AND severity == 'HIGH'",
    "source == 'host-finance-01' AND severity == 'HIGH'",
    "process_name == 'rundll32.exe'",
    "event_type == 'process_start' AND severity != 'LOW'",
]


# ── Single Request ───────────────────────────────────────────────────────

def execute_query(base_url: str, query: str, limit: int = 100, timeout: int = 10):
    """Execute a single hunt query and return timing/result info."""
    url = f"{base_url}/hunt/query"
    payload = json.dumps({"query": query, "limit": limit}).encode("utf-8")

    req = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    start = time.perf_counter()

    try:
        with urlopen(req, timeout=timeout) as resp:
            elapsed_ms = (time.perf_counter() - start) * 1000
            body = json.loads(resp.read().decode("utf-8"))
            return {
                "success": True,
                "status": resp.status,
                "latency_ms": round(elapsed_ms, 2),
                "result_count": body.get("count", 0),
                "total": body.get("total", 0),
                "truncated": body.get("truncated", False),
                "request_id": body.get("request_id", ""),
            }
    except HTTPError as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        detail = ""
        try:
            detail = json.loads(e.read().decode("utf-8")).get("detail", "")
        except Exception:
            pass
        return {
            "success": False,
            "status": e.code,
            "latency_ms": round(elapsed_ms, 2),
            "error": f"HTTP {e.code}: {detail}",
            "result_count": 0,
        }
    except (URLError, TimeoutError) as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {
            "success": False,
            "status": 0,
            "latency_ms": round(elapsed_ms, 2),
            "error": str(e),
            "result_count": 0,
        }


# ── Load Test Runner ─────────────────────────────────────────────────────

def run_load_test(
    base_url: str,
    concurrency: int = 20,
    total_requests: int = 100,
    limit: int = 100,
):
    """Run concurrent queries and collect statistics."""

    print(f"\n{'═' * 60}")
    print(f"  ANTIGRAVITY FORENSICS — Hunt Query Load Test")
    print(f"{'═' * 60}")
    print(f"  Target:      {base_url}/hunt/query")
    print(f"  Concurrency: {concurrency} threads")
    print(f"  Total:       {total_requests} requests")
    print(f"  Limit:       {limit} results/query")
    print(f"{'─' * 60}\n")

    results = []
    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for i in range(total_requests):
            query = TEST_QUERIES[i % len(TEST_QUERIES)]
            futures.append(executor.submit(execute_query, base_url, query, limit))

        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)

            # Progress indicator
            status = "✓" if result["success"] else "✗"
            if i % 10 == 0 or i == total_requests:
                success_count = sum(1 for r in results if r["success"])
                print(f"  [{i:>4}/{total_requests}] {status}  "
                      f"Success: {success_count}  "
                      f"Latency: {result['latency_ms']:.0f}ms")

    total_time = time.perf_counter() - start_time

    # ── Statistics ────────────────────────────────────────────────────

    successes = [r for r in results if r["success"]]
    failures = [r for r in results if not r["success"]]
    latencies = [r["latency_ms"] for r in successes]
    rate_limited = [r for r in failures if r.get("status") == 429]

    print(f"\n{'═' * 60}")
    print(f"  RESULTS")
    print(f"{'═' * 60}")
    print(f"  Total requests:    {total_requests}")
    print(f"  Successful:        {len(successes)}")
    print(f"  Failed:            {len(failures)}")
    print(f"  Rate limited:      {len(rate_limited)}")
    print(f"  Error rate:        {len(failures) / total_requests * 100:.1f}%")
    print(f"  Total time:        {total_time:.2f}s")
    print(f"  Throughput:        {total_requests / total_time:.1f} req/s")

    if latencies:
        sorted_lat = sorted(latencies)
        p50_idx = int(len(sorted_lat) * 0.50)
        p95_idx = int(len(sorted_lat) * 0.95)
        p99_idx = int(len(sorted_lat) * 0.99)

        print(f"\n  {'─' * 40}")
        print(f"  LATENCY (successful requests)")
        print(f"  {'─' * 40}")
        print(f"  Mean:              {statistics.mean(latencies):.1f}ms")
        print(f"  Median (P50):      {sorted_lat[min(p50_idx, len(sorted_lat)-1)]:.1f}ms")
        print(f"  P95:               {sorted_lat[min(p95_idx, len(sorted_lat)-1)]:.1f}ms")
        print(f"  P99:               {sorted_lat[min(p99_idx, len(sorted_lat)-1)]:.1f}ms")
        print(f"  Min:               {min(latencies):.1f}ms")
        print(f"  Max:               {max(latencies):.1f}ms")

    if failures:
        print(f"\n  {'─' * 40}")
        print(f"  ERRORS")
        print(f"  {'─' * 40}")
        error_types = {}
        for f in failures:
            key = f.get("error", "Unknown")[:60]
            error_types[key] = error_types.get(key, 0) + 1
        for err, count in sorted(error_types.items(), key=lambda x: -x[1]):
            print(f"  [{count:>3}x] {err}")

    print(f"\n{'═' * 60}\n")

    return {
        "total": total_requests,
        "successes": len(successes),
        "failures": len(failures),
        "rate_limited": len(rate_limited),
        "error_rate": round(len(failures) / total_requests, 4),
        "throughput_rps": round(total_requests / total_time, 2),
        "avg_latency_ms": round(statistics.mean(latencies), 2) if latencies else 0,
        "p95_latency_ms": round(sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0, 2),
    }


# ── CLI ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load test the hunting query engine")
    parser.add_argument("--url", default="http://localhost:8001", help="Base API URL")
    parser.add_argument("--concurrency", "-c", type=int, default=20, help="Concurrent threads")
    parser.add_argument("--total", "-n", type=int, default=100, help="Total requests")
    parser.add_argument("--limit", "-l", type=int, default=100, help="Result limit per query")
    args = parser.parse_args()

    try:
        summary = run_load_test(args.url, args.concurrency, args.total, args.limit)
        # Exit with error code if failure rate > 50%
        sys.exit(1 if summary["error_rate"] > 0.5 else 0)
    except KeyboardInterrupt:
        print("\n  Aborted.")
        sys.exit(130)
