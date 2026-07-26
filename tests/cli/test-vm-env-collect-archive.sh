#!/usr/bin/env bash
set -euo pipefail

[[ ${PLATFORM_TOOLS_DEV_CONTAINER:-0} == 1 ]] || {
  printf '%s\n' 'archive smoke test must run in the development container' >&2
  exit 1
}

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
ARCHIVE_DIR=''
trap 'rm -rf "$TMP_DIR" "$ARCHIVE_DIR"' EXIT HUP INT TERM

TOOL="$ROOT_DIR/bin/platform-vm-env-collect"
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"
FAKE_BIN="$TMP_DIR/fake-bin"

mkdir -p "$FAKE_BIN"
for command in ip ss systemctl; do
  cat >"$FAKE_BIN/$command" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
  chmod 755 "$FAKE_BIN/$command"
done

set +e
PATH="$FAKE_BIN:$PATH" \
  COLLECT_ENV=1 COLLECTOR_TEST_PASSWORD=collector-secret-value \
  "$TOOL" >"$STDOUT" 2>"$STDERR"
status=$?
set -e
if [[ $status -ne 0 ]]; then
  printf 'collector failed with status %s:\n' "$status" >&2
  while IFS= read -r line; do
    printf '  %s\n' "$line" >&2
  done <"$STDERR"
  exit 1
fi

archive=''
while IFS= read -r line; do
  case $line in
    '  /tmp/platform-vm-env-collect.'*.tar.gz)
      archive=${line#'  '}
      break
      ;;
  esac
done <"$STDOUT"

[[ -n $archive && -f $archive ]] || {
  printf '%s\n' 'collector did not report a readable archive' >&2
  exit 1
}
ARCHIVE_DIR=$(dirname "$archive")

[[ $(stat -c '%a' "$archive") == 600 ]] || {
  printf '%s\n' 'collector archive mode is not 600' >&2
  exit 1
}
[[ $(stat -c '%a' "$archive.sha256") == 600 ]] || {
  printf '%s\n' 'collector checksum mode is not 600' >&2
  exit 1
}
sha256sum -c "$archive.sha256" >/dev/null

extract_dir="$TMP_DIR/extracted"
mkdir -p "$extract_dir"
tar -C "$extract_dir" -xzf "$archive"
report_dir="$extract_dir/$(basename "$archive" .tar.gz)"

[[ -f $report_dir/SUMMARY.md ]] || {
  printf '%s\n' 'collector archive is missing SUMMARY.md' >&2
  exit 1
}
[[ -f $report_dir/meta/collector-env.txt ]] || {
  printf '%s\n' 'collector archive is missing environment metadata' >&2
  exit 1
}
grep -Fq 'COLLECTOR_TEST_PASSWORD=<REDACTED>' \
  "$report_dir/meta/collector-env.txt" || {
  printf '%s\n' 'collector did not redact the injected test password' >&2
  exit 1
}
if grep -Fq 'collector-secret-value' "$report_dir/meta/collector-env.txt"; then
  printf '%s\n' 'collector archive contains the injected test password' >&2
  exit 1
fi

printf '%s\n' 'test-vm-env-collect-archive.sh: ok'
