#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# Antigravity Forensics — Database Backup Script
# ═══════════════════════════════════════════════════════════════
# Creates timestamped SQLite backups using the .backup command
# for consistency (safe even during writes due to WAL mode).
#
# Usage:
#   ./scripts/backup_db.sh                    # defaults
#   ./scripts/backup_db.sh /path/to/db /out   # custom paths
#
# Cron example (daily at 2 AM):
#   0 2 * * * /app/scripts/backup_db.sh >> /var/log/backup.log 2>&1
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ────────────────────────────────────────────
DB_PATH="${1:-${DATABASE_PATH:-/app/data/cases.db}}"
BACKUP_DIR="${2:-/app/data/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# ── Pre-flight checks ───────────────────────────────────────
if [ ! -f "$DB_PATH" ]; then
    echo "[ERROR] Database file not found: $DB_PATH"
    exit 1
fi

if ! command -v sqlite3 &>/dev/null; then
    echo "[ERROR] sqlite3 not found. Install it first."
    exit 1
fi

# ── Create backup directory ──────────────────────────────────
mkdir -p "$BACKUP_DIR"

# ── Enable WAL mode (idempotent) ─────────────────────────────
sqlite3 "$DB_PATH" "PRAGMA journal_mode=WAL;"
echo "[INFO] WAL mode confirmed."

# ── Perform backup ───────────────────────────────────────────
BACKUP_FILE="$BACKUP_DIR/cases_${TIMESTAMP}.db"
echo "[INFO] Backing up: $DB_PATH → $BACKUP_FILE"

sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"

# Verify backup integrity
INTEGRITY=$(sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" 2>/dev/null)
if [ "$INTEGRITY" = "ok" ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "[OK] Backup verified. Size: $BACKUP_SIZE"
else
    echo "[WARN] Backup integrity check returned: $INTEGRITY"
fi

# ── Prune old backups ────────────────────────────────────────
PRUNED=$(find "$BACKUP_DIR" -name "cases_*.db" -mtime +"$RETENTION_DAYS" -delete -print | wc -l)
if [ "$PRUNED" -gt 0 ]; then
    echo "[INFO] Pruned $PRUNED backup(s) older than $RETENTION_DAYS days."
fi

echo "[DONE] Backup complete: $BACKUP_FILE"
