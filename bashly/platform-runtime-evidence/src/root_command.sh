IDENTITY=${args[--identity]}
ROLE=${args[--role]}
OWNER=${args[--owner]}
EXECUTES_PKI=${args[--executes-pki]}
INSTALL_DIR=${args[--install-dir]}
PLATFORM_PKI=${args[--platform-pki]-$INSTALL_DIR/platform-pki}
PROBE_DIR=${args[--probe-dir]-${TMPDIR:-/tmp}}
INVOKE_VERSION=false
PROBE_WORKSPACE=''
PROBE_WORKSPACE_NAME=''
PROBE_WORKSPACE_ID=''
PROBE_WORKSPACE_PARENT=''
PROBE_PARENT_ID=''
[[ ! -v args[--invoke-version] ]] || INVOKE_VERSION=true

for PATH_VALUE in "$INSTALL_DIR" "$PLATFORM_PKI" "$PROBE_DIR"; do
  [[ $PATH_VALUE == /* ]] || die 'Install, artifact, and probe paths must be absolute'
done
if [[ -L $INSTALL_DIR ]]; then
  die 'Install directory must not be a symlink'
fi
if [[ -e $INSTALL_DIR && ! -d $INSTALL_DIR ]]; then
  die 'Install directory must be a directory or absent'
fi
if [[ ! -d $PROBE_DIR || -L $PROBE_DIR ]]; then
  die 'Probe directory must be an existing non-symlink directory'
fi

emit schema 1
emit encoding percent-controls-v1
emit identity "$IDENTITY"
emit role "$ROLE"
emit owner "$OWNER"
emit executes_pki "$EXECUTES_PKI"
emit install_dir "$INSTALL_DIR"
emit install_dir_state "$(path_state "$INSTALL_DIR")"
emit platform_pki_path "$PLATFORM_PKI"
ARTIFACT_STATE=$(path_state "$PLATFORM_PKI")
emit platform_pki_state "$ARTIFACT_STATE"
emit kernel_name "$(command uname -s 2>/dev/null || printf unknown)"
emit kernel_release "$(command uname -r 2>/dev/null || printf unknown)"
emit architecture "$(command uname -m 2>/dev/null || printf unknown)"
emit os_id "$(read_os_release_value ID)"
emit os_version_id "$(read_os_release_value VERSION_ID)"

PYTHON_PATH=$(resolved_command_path python3)
PYTHON_VERSION=unavailable
PYTHON_MEETS=unknown
if [[ $PYTHON_PATH != absent ]]; then
  PYTHON_VERSION=$("$PYTHON_PATH" --version 2>&1 || true)
  PYTHON_VERSION=$(first_line "$PYTHON_VERSION")
  if [[ $PYTHON_VERSION =~ ^Python\ ([0-9]+)\.([0-9]+)(\.|$) ]]; then
    if (( BASH_REMATCH[1] > 3 || (BASH_REMATCH[1] == 3 && BASH_REMATCH[2] >= 14) )); then
      PYTHON_MEETS=yes
    else
      PYTHON_MEETS=no
    fi
  fi
fi
emit python3_path "$PYTHON_PATH"
emit python3_version "$PYTHON_VERSION"
emit python3_meets_3_14 "$PYTHON_MEETS"

ARTIFACT_METADATA='unavailable unavailable unavailable unavailable unavailable unavailable unavailable'
if [[ $ARTIFACT_STATE == regular-file && $PYTHON_PATH != absent ]]; then
  ARTIFACT_METADATA=$("$PYTHON_PATH" -c '
import hashlib
import os
import stat
import sys

path = sys.argv[1]
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise OSError("not a regular file")
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    after = os.fstat(descriptor)
    current = os.stat(path, follow_symlinks=False)
    def identity(value):
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
    stable = (
        identity(before) == identity(after) == identity(current)
        and stat.S_ISREG(current.st_mode)
    )
    executable = os.access(
        f"/proc/self/fd/{descriptor}", os.X_OK, effective_ids=True
    )
    print(before.st_uid, oct(stat.S_IMODE(before.st_mode))[2:], before.st_nlink, before.st_size, digest.hexdigest(), "yes" if stable else "no", "yes" if executable else "no")
finally:
    os.close(descriptor)
' "$PLATFORM_PKI" 2>/dev/null || printf 'unavailable unavailable unavailable unavailable unavailable no unavailable')
fi
read -r ARTIFACT_UID ARTIFACT_MODE ARTIFACT_LINKS ARTIFACT_SIZE ARTIFACT_SHA ARTIFACT_STABLE ARTIFACT_EXECUTABLE <<< "$ARTIFACT_METADATA"
emit platform_pki_owner_uid "$ARTIFACT_UID"
emit platform_pki_mode "$ARTIFACT_MODE"
emit platform_pki_links "$ARTIFACT_LINKS"
emit platform_pki_size "$ARTIFACT_SIZE"
emit platform_pki_sha256 "$ARTIFACT_SHA"
emit platform_pki_identity_stable "$ARTIFACT_STABLE"

if [[ $INVOKE_VERSION == true ]]; then
  if [[ $ARTIFACT_STATE != regular-file || $ARTIFACT_EXECUTABLE != yes ]]; then
    die 'Selected platform-pki must be an executable regular file for --invoke-version'
  fi
  VERSION_RESULT=$("$PYTHON_PATH" -c '
import fcntl
import hashlib
import os
import stat
import subprocess
import sys

path, expected_uid, expected_mode, expected_links, expected_size, expected_sha = sys.argv[1:]
source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
snapshot = os.memfd_create("platform-runtime-evidence", os.MFD_ALLOW_SEALING)
try:
    before = os.fstat(source)
    expected = (int(expected_uid), int(expected_mode, 8), int(expected_links), int(expected_size))
    observed = (before.st_uid, stat.S_IMODE(before.st_mode), before.st_nlink, before.st_size)
    if not stat.S_ISREG(before.st_mode) or observed != expected:
        raise OSError("selected artifact metadata changed")
    digest = hashlib.sha256()
    while chunk := os.read(source, 1024 * 1024):
        digest.update(chunk)
        remaining = memoryview(chunk)
        while remaining:
            written = os.write(snapshot, remaining)
            if written <= 0:
                raise OSError("could not copy selected artifact")
            remaining = remaining[written:]
    after = os.fstat(source)
    current = os.stat(path, follow_symlinks=False)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise OSError("selected artifact identity changed")
    if digest.hexdigest() != expected_sha:
        raise OSError("selected artifact digest changed")
    os.fchmod(snapshot, 0o700)
    fcntl.fcntl(
        snapshot,
        fcntl.F_ADD_SEALS,
        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE,
    )
    result = subprocess.run(
        [f"/proc/self/fd/{snapshot}", "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        pass_fds=(snapshot,),
        check=False,
    )
finally:
    os.close(source)
    os.close(snapshot)

line = result.stdout.splitlines()[0] if result.stdout.splitlines() else b""
encoded = bytearray()
for byte in line:
    if byte == 0x25 or byte < 0x20 or byte == 0x7F:
        encoded.extend(f"%{byte:02X}".encode("ascii"))
    else:
        encoded.append(byte)
sys.stdout.buffer.write(str(result.returncode).encode("ascii") + b"\t" + encoded + b"\n")
' "$PLATFORM_PKI" "$ARTIFACT_UID" "$ARTIFACT_MODE" "$ARTIFACT_LINKS" "$ARTIFACT_SIZE" "$ARTIFACT_SHA" 2>/dev/null) ||
    die 'Selected platform-pki changed or could not be invoked from a sealed snapshot'
  IFS=$'\t' read -r VERSION_STATUS VERSION_OUTPUT <<< "$VERSION_RESULT"
  emit platform_pki_version_status "$VERSION_STATUS"
  emit_encoded platform_pki_version "$VERSION_OUTPUT"
else
  emit platform_pki_version_status not-invoked
  emit platform_pki_version not-invoked
fi

declare -A LEGACY_ALIAS_STATES=()
ALL_ALIASES_ABSENT=yes
for ALIAS in "${LEGACY_PKI_ALIASES[@]}"; do
  LEGACY_ALIAS_STATES[$ALIAS]=$(path_state "$INSTALL_DIR/$ALIAS")
  emit "legacy_alias.${ALIAS}.state" "${LEGACY_ALIAS_STATES[$ALIAS]}"
  [[ ${LEGACY_ALIAS_STATES[$ALIAS]} == absent ]] || ALL_ALIASES_ABSENT=no
done

for TOOL in openssl ssh-keygen flock date mv tar age cmp findmnt lsblk; do
  emit_tool "$TOOL"
done

MV_PATH=$(command_path mv)
MV_HELP=''
[[ -z $MV_PATH ]] || MV_HELP=$("$MV_PATH" --help 2>/dev/null || true)
if [[ $MV_HELP == *'--no-copy'* ]]; then emit feature.mv_no_copy yes; else emit feature.mv_no_copy no; fi
if [[ $MV_HELP == *'none-fail'* ]]; then emit feature.mv_update_none_fail yes; else emit feature.mv_update_none_fail no; fi
if [[ $MV_HELP == *'--exchange'* ]]; then emit feature.mv_exchange yes; else emit feature.mv_exchange no; fi
TAR_PATH=$(command_path tar)
TAR_HELP=''
[[ -z $TAR_PATH ]] || TAR_HELP=$("$TAR_PATH" --help 2>/dev/null || true)
if [[ $TAR_HELP == *'--no-wildcards'* ]]; then emit feature.tar_no_wildcards yes; else emit feature.tar_no_wildcards no; fi
if [[ -d /proc/self/fd ]]; then emit feature.procfs yes; else emit feature.procfs no; fi

probe_filesystem_features "$PROBE_DIR" "$PYTHON_PATH"

if [[ $EXECUTES_PKI == no ]]; then
  RUNTIME_STATUS=not-applicable
elif [[ $EXECUTES_PKI == unknown ]]; then
  RUNTIME_STATUS=unknown
elif [[ $PYTHON_MEETS != yes || $ARTIFACT_STATE != regular-file || $ARTIFACT_STABLE != yes || $ARTIFACT_EXECUTABLE != yes ]]; then
  RUNTIME_STATUS=blocked
elif [[ $ALL_ALIASES_ABSENT != yes ]]; then
  RUNTIME_STATUS=blocked
else
  RUNTIME_STATUS=role-review-required
fi
emit runtime_status "$RUNTIME_STATUS"
