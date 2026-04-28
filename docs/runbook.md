# Antigravity Forensics — Operations Runbook

## Quick Reference

| Action | Command |
|--------|---------|
| **Start** | `docker compose up -d` |
| **Stop** | `docker compose down` |
| **Rebuild** | `docker compose up -d --build` |
| **Logs (all)** | `docker compose logs -f` |
| **Logs (backend)** | `docker compose logs -f backend` |
| **Status** | `docker compose ps` |
| **Smoke test** | `bash scripts/smoke_test.sh` |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker Host (single machine)                       │
│                                                     │
│   ┌─────────────┐      ┌──────────────────────┐    │
│   │  Frontend    │      │  Backend             │    │
│   │  nginx:80    │─────▶│  uvicorn:8001        │    │
│   │  (static)    │ /api │  FastAPI + SQLite     │    │
│   └─────────────┘      └──────────┬───────────┘    │
│                                   │                 │
│                           ┌───────▼───────┐         │
│                           │  db-data vol  │         │
│                           │  (persistent) │         │
│                           └───────────────┘         │
└─────────────────────────────────────────────────────┘
```

---

## 1. Initial Setup

```bash
# 1. Clone and enter project
cd /path/to/Major_Project

# 2. Create environment file
cp .env.example .env

# 3. IMPORTANT: Change JWT secret
#    Edit .env and set JWT_SECRET_KEY to a random string
#    Example: openssl rand -hex 32

# 4. Start everything
docker compose up -d --build

# 5. Verify
bash scripts/smoke_test.sh
```

---

## 2. Endpoints

| Endpoint | Purpose | Auth Required |
|----------|---------|---------------|
| `GET /health` | Liveness probe | No |
| `GET /readiness` | Readiness probe (returns 503 if not ready) | No |
| `GET /metrics/hunting` | Hunting query performance (JSON) | No |
| `GET /metrics/prom` | Prometheus-format metrics | No |
| `GET /logs/recent` | Recent request logs | Admin |
| `GET /logs/errors` | Recent error logs | Admin |
| `POST /logs/frontend` | Frontend error telemetry | No |

---

## 3. Common Failures & Resolution

### 3.1 — `429 Too Many Requests`

**Cause**: Rate limit exceeded.

| Endpoint | Limit |
|----------|-------|
| `/hunt/query` | 10 requests / 10 seconds / user |
| `/ingest/event` | 100 events / second / source |

**Resolution**:
- Wait 10 seconds and retry
- If persistent, check for runaway client scripts
- Adjust limits in `.env`:
  ```
  HUNT_RATE_LIMIT=20
  INGEST_RATE_LIMIT=200
  ```

---

### 3.2 — `503 Query Engine Temporarily Unavailable`

**Cause**: Circuit breaker tripped after 3 consecutive query failures.

**Check**:
```bash
curl http://localhost:8001/health | python3 -m json.tool
# Look at circuit_breaker.state — should be "closed"
```

**Resolution**:
- Wait 5 seconds — circuit auto-resets (half-open → test request → close)
- If persists, check backend logs:
  ```bash
  docker compose logs backend --tail=50
  ```
- Common root cause: corrupted query engine data. Restart:
  ```bash
  docker compose restart backend
  ```

---

### 3.3 — `Database Locked`

**Cause**: SQLite WAL contention under concurrent writes.

**Resolution**:
1. Verify WAL mode is enabled:
   ```bash
   docker compose exec backend sqlite3 /app/data/cases.db "PRAGMA journal_mode;"
   # Should return: wal
   ```
2. If not WAL, enable it:
   ```bash
   docker compose exec backend sqlite3 /app/data/cases.db "PRAGMA journal_mode=WAL;"
   ```
3. If still locked, restart backend:
   ```bash
   docker compose restart backend
   ```

---

### 3.4 — Frontend Returns Blank Page

**Check**:
```bash
# Is nginx running?
docker compose ps frontend

# Can we reach it?
curl -I http://localhost:80/
```

**Resolution**:
```bash
docker compose restart frontend
```

---

### 3.5 — Backend Won't Start

**Check logs**:
```bash
docker compose logs backend --tail=100
```

**Common causes**:
- Missing evidence files → mount the Evidence directory
- Python import error → rebuild: `docker compose build backend`
- Port conflict → change `API_PORT` in `.env`

---

## 4. Operational Tasks

### 4.1 — Backup Database

```bash
# Manual backup
docker compose exec backend bash /app/scripts/backup_db.sh

# Or from host
bash scripts/backup_db.sh ./cases.db ./backups/

# Automated (add to crontab)
0 2 * * * cd /path/to/project && docker compose exec -T backend bash /app/scripts/backup_db.sh
```

### 4.2 — Rotate Logs

Docker handles log rotation via the `json-file` driver config in `docker-compose.yml`:
- Backend: 5 files × 50 MB = 250 MB max
- Frontend: 3 files × 10 MB = 30 MB max

To force rotation:
```bash
# Truncate current log
docker compose logs backend > /dev/null
```

### 4.3 — Clear Cache

```bash
# Restart backend (clears in-memory caches)
docker compose restart backend

# Or clear the cache database
docker compose exec backend sqlite3 /app/data/core_forensics.db "DELETE FROM cache;"
```

### 4.4 — Restart Services

```bash
# Restart specific service (zero-downtime for frontend)
docker compose restart backend
docker compose restart frontend

# Full restart
docker compose down && docker compose up -d
```

### 4.5 — Scale (future)

The current setup runs on a single machine. For scaling:
- Backend: increase `--workers` in Dockerfile.backend CMD
- Frontend: nginx is already efficient for static serving
- Database: migrate from SQLite to PostgreSQL

---

## 5. Monitoring

### 5.1 — Health Dashboard

```bash
# Quick health check
watch -n 5 'curl -s http://localhost:8001/health | python3 -m json.tool'
```

### 5.2 — Query Performance

```bash
# JSON metrics
curl -s http://localhost:8001/metrics/hunting | python3 -m json.tool

# Prometheus format (for Grafana integration)
curl -s http://localhost:8001/metrics/prom
```

### 5.3 — Error Investigation

```bash
# Recent errors
curl -s http://localhost:8001/logs/errors | python3 -m json.tool

# Recent request logs
curl -s http://localhost:8001/logs/recent?limit=20 | python3 -m json.tool
```

---

## 6. Load Testing

```bash
# Run from host (backend must be running)
python scripts/load_test_hunt.py --concurrency 20 --total 100

# Expected output:
#   Throughput: >10 req/s
#   P95 latency: <100ms
#   Error rate: <5% (mostly rate-limited 429s)
```

---

## 7. Security Checklist

- [ ] Changed `JWT_SECRET_KEY` from default
- [ ] Set `CORS_ORIGINS` to specific frontend origin
- [ ] Set `SIMULATE_MODE=true` until ready for real actions
- [ ] Verified no raw stack traces in error responses
- [ ] Backup script configured in cron
- [ ] Nginx security headers verified (`curl -I http://localhost:80/`)

---

## 8. Troubleshooting Flowchart

```
Problem?
  │
  ├─ Frontend blank → docker compose restart frontend
  │
  ├─ API returns 429 → Wait 10s, or increase HUNT_RATE_LIMIT
  │
  ├─ API returns 503 → Check circuit_breaker state in /health
  │                     Wait 5s for auto-recovery
  │
  ├─ DB locked → Enable WAL mode, restart backend
  │
  ├─ Backend won't start → Check logs: docker compose logs backend
  │
  └─ Slow queries → Check /metrics/hunting for P95
                     Run load test to identify bottleneck
```
