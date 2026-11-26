#!/usr/bin/env bash
# Back up one ARTEX Compose project — the PostgreSQL dump plus the data, keys and
# skills volumes — as a single verified archive, with rotation.
#
# Usage:
#   scripts/backup.sh [--project NAME] [--keep N] [--output-dir DIR]
#
#   --project NAME  Compose project to back up (default: $COMPOSE_PROJECT_NAME,
#                   else this checkout's directory name, lowercased — the name
#                   compose derives on its own)
#   --keep N        archives to keep (default 14)
#   --output-dir    where to write (default backups/, relative to the repo root)
#   --with-data     accepted for compatibility; the data volume is always included
#
# The volumes are found by their Compose labels
# (com.docker.compose.project=<project>, com.docker.compose.volume=<name>), never
# by the directory a stack was started from: a project whose containers were
# created elsewhere still backs up to its own volumes, and a missing volume stops
# the run instead of yielding an archive without it. A named volume that the
# compose file would bind instead (./data, ./keys, ./skills) is reported the same
# way: nothing labelled exists, so the run fails and says what it looked for.
#
# Archive layout:
#   manifest.txt               what was taken, from where, and when
#   db.sql                     pg_dump of the project's database
#   volumes/artex_data/…       the data volume (traffic index, tasks, transcripts…)
#   volumes/artex_keys/…       jwt.key and secret.key
#   volumes/artex_skills/…     the skill library
#
# Restore (volumes first, then the database; the stack must be stopped):
#   image=$(docker inspect -f '{{.Config.Image}}' "$(docker ps -aq \
#     --filter label=com.docker.compose.service=postgres | head -1)")
#   docker compose down
#   docker run --rm -v artex_artex_data:/dst -v "$PWD":/b:ro "$image" \
#     tar -xzf /b/backups/artex-state-<ts>.tar.gz -C /dst --strip-components=2 volumes/artex_data
#   … the same for artex_artex_keys and artex_artex_skills …
#   docker compose up -d postgres
#   docker exec -i "$(docker compose ps -q postgres)" psql -U "$POSTGRES_USER" \
#     -d "$POSTGRES_DB" < db.sql
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { sed -n '2,40p' "$0" | sed 's/^# \?//'; }

die() { echo "backup: $*" >&2; exit 1; }

KEEP=14
OUTPUT_DIR="backups"
PROJECT="${COMPOSE_PROJECT_NAME:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --project) PROJECT="${2:?--project needs a name}"; shift 2 ;;
    --keep) KEEP="${2:?--keep needs a number}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?--output-dir needs a path}"; shift 2 ;;
    --with-data) shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
# 0* rejects 0, which would delete the archive this run just wrote, and leading
# zeros, which $((KEEP + 1)) would read as octal.
case "$KEEP" in (*[!0-9]*|''|0*) echo "--keep must be a positive integer" >&2; exit 2 ;; esac
# Compose knows its own project name (and honours COMPOSE_PROJECT_NAME and the
# override file); ask it before guessing from the directory name.
if [ -z "$PROJECT" ]; then
  PROJECT=$(docker compose config --format json 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("name",""))' 2>/dev/null) || true
fi
if [ -z "$PROJECT" ]; then
  PROJECT=$(basename "$PWD" | tr '[:upper:]' '[:lower:]')
fi

command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon"

# volume_for prints the name of one labelled Compose volume of the project, and
# stops the run when there is none or more than one.
volume_for() {
  local key=$1 found count
  found=$(docker volume ls -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.volume=$key")
  count=$(printf '%s' "$found" | grep -c . || true)
  case "$count" in
    1) printf '%s\n' "$found" ;;
    0)
      echo "backup: no volume labelled com.docker.compose.project=$PROJECT and com.docker.compose.volume=$key" >&2
      echo "backup: volumes this project has:" >&2
      docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | sed 's/^/backup:   /' >&2
      echo "backup: a stack whose compose file bind-mounts ./data, ./keys or ./skills has no named volume to take; archive those directories yourself." >&2
      exit 1
      ;;
    *)
      echo "backup: $count volumes carry the label of $key, refusing to guess which one:" >&2
      printf '%s\n' "$found" | sed 's/^/backup:   /' >&2
      exit 1
      ;;
  esac
}

VOL_DATA=$(volume_for artex_data)
VOL_KEYS=$(volume_for artex_keys)
VOL_SKILLS=$(volume_for artex_skills)

# The running database container of the project: its image is the helper that
# reads the volumes and writes the archive, so nothing has to be pulled.
PG_CONTAINER=$(docker ps -q \
  --filter "label=com.docker.compose.project=$PROJECT" \
  --filter "label=com.docker.compose.service=postgres" | head -1)
[ -n "$PG_CONTAINER" ] || die "no running postgres container in Compose project '$PROJECT' (docker compose ls shows the projects and where they were started)"
HELPER_IMAGE=$(docker inspect -f '{{.Config.Image}}' "$PG_CONTAINER")
[ -n "$HELPER_IMAGE" ] || die "cannot read the image of container $PG_CONTAINER"
PG_USER=$(docker exec "$PG_CONTAINER" printenv POSTGRES_USER 2>/dev/null || true)
PG_DB=$(docker exec "$PG_CONTAINER" printenv POSTGRES_DB 2>/dev/null || true)
PG_USER=${PG_USER:-artex}
PG_DB=${PG_DB:-artex}

mkdir -p "$OUTPUT_DIR"
# The archive holds jwt.key and secret.key: owner-only, like them.
chmod 700 "$OUTPUT_DIR" 2>/dev/null || true
OUTPUT_ABS=$(cd "$OUTPUT_DIR" && pwd)
TS=$(date -u +%Y%m%dT%H%M%SZ)
NAME="artex-state-$TS.tar.gz"
[ -e "$OUTPUT_ABS/$NAME" ] && die "refusing to overwrite $OUTPUT_ABS/$NAME"

STAGING=$(mktemp -d "${TMPDIR:-/tmp}/artex-backup.XXXXXX")
trap 'rm -rf "$STAGING"' EXIT

echo "backup: project $PROJECT: pg_dump -U $PG_USER $PG_DB"
if ! docker exec "$PG_CONTAINER" pg_dump -U "$PG_USER" "$PG_DB" > "$STAGING/db.sql"; then
  die "pg_dump failed; nothing was written"
fi
[ -s "$STAGING/db.sql" ] || die "pg_dump wrote an empty dump; nothing was written"
head -30 "$STAGING/db.sql" | grep -q 'PostgreSQL database dump' \
  || die "the dump does not start like a pg_dump file; nothing was written"

{
  echo "project:   $PROJECT"
  echo "created:   $TS"
  echo "database:  $PG_DB (user $PG_USER)"
  echo "data:      $VOL_DATA -> volumes/artex_data"
  echo "keys:      $VOL_KEYS -> volumes/artex_keys"
  echo "skills:    $VOL_SKILLS -> volumes/artex_skills"
  echo "restore:   see scripts/backup.sh --help"
} > "$STAGING/manifest.txt"

# The volumes are mounted inside the staging tree so one tar run can take them
# with the dump: the helper image's tar (busybox) applies only the last -C, so
# each path has to sit under one root.
mkdir -p "$STAGING/volumes/artex_data" "$STAGING/volumes/artex_keys" "$STAGING/volumes/artex_skills"
echo "backup: archiving volumes $VOL_DATA, $VOL_KEYS, $VOL_SKILLS with $HELPER_IMAGE"
if ! docker run --rm \
  -v "$STAGING:/staging:ro" \
  -v "$VOL_DATA:/staging/volumes/artex_data:ro" \
  -v "$VOL_KEYS:/staging/volumes/artex_keys:ro" \
  -v "$VOL_SKILLS:/staging/volumes/artex_skills:ro" \
  -v "$OUTPUT_ABS:/out" \
  "$HELPER_IMAGE" \
  tar -czf "/out/$NAME" -C /staging manifest.txt db.sql volumes; then
  rm -f "$OUTPUT_ABS/$NAME"
  die "the archive could not be written (a volume unreadable by the helper image?)"
fi

# Verify before reporting success: the archive has to open, hold the dump, one
# entry per volume, and both key files.
echo "backup: verifying $NAME"
verify_output=$(docker run --rm -v "$OUTPUT_ABS:/out:ro" "$HELPER_IMAGE" \
  sh -c '
    set -eu
    f=/out/'"$NAME"'
    gzip -t "$f"
    tar -tzf "$f" > /tmp/list
    fail() { echo "verify: $*" >&2; exit 1; }
    for want in db.sql manifest.txt; do
      grep -qx "$want" /tmp/list || fail "missing $want"
    done
    for vol in artex_data artex_keys artex_skills; do
      grep -q "^volumes/$vol/" /tmp/list || fail "no entry for volumes/$vol"
    done
    for key in jwt.key secret.key; do
      grep -qx "volumes/artex_keys/$key" /tmp/list || fail "missing volumes/artex_keys/$key"
    done
    all=$(grep -c . /tmp/list)
    [ "$all" -gt 10 ] || fail "only $all entries, the volumes look empty"
    tar -xzOf "$f" db.sql | head -30 | grep -q "PostgreSQL database dump" || fail "db.sql is not a pg_dump file"
    echo "verify: $all entries, db.sql and volumes/artex_{data,keys,skills} present"
  ' 2>&1) || {
  rm -f "$OUTPUT_ABS/$NAME"
  echo "$verify_output" >&2
  die "the archive failed verification; it was removed"
}
echo "$verify_output"

chmod 600 "$OUTPUT_ABS/$NAME" 2>/dev/null || true
ls -1t "$OUTPUT_ABS"/artex-state-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
  echo "pruning $old"
  rm -f "$old"
done

echo "backup: $OUTPUT_ABS/$NAME ($(du -h "$OUTPUT_ABS/$NAME" | cut -f1)), $KEEP newest kept"
