# Offline PKI Workspace

`platform-pki offline-workspace init` creates an owner-only, outside-Git
custody and staging skeleton for one exact protocol service:

```bash
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
OFFLINE_ROOT="$CONFIG_HOME/platform-pki-offline"
PROTOCOL_SERVICE=registry-dev-01

platform-pki offline-workspace init "$PROTOCOL_SERVICE"
```

The default root is
`${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-offline`. `--root` must be an
absolute, canonical, non-root path. When the configuration home is known, the
root must be component-wise disjoint from the default authoritative
`<config-home>/platform-infrastructure/pki` tree: it may not equal, contain, or
be contained by that tree. The service workspace is `<root>/<service>`.
Therefore the example creates
`${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-offline/registry-dev-01`.

`registry-dev-01` is the exact node-specific protocol service and
workspace name. The stable trust domain is `registry-dev`; dedicated approval
and response keys remain under the stable trust-domain path
`${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-keys/registry-dev/` so a new
protocol generation does not silently select or create new operator keys.

For a reviewed non-default location, override the root explicitly:

```bash
# Explicit custom-root example; this is not the canonical workstation default.
platform-pki offline-workspace init "$PROTOCOL_SERVICE" \
  --root /absolute/offline/root
```

## Created Tree

The initializer creates only directories and a concise non-secret `README.md`:

```text
<root>/<service>/
├── README.md
├── media-in/
│   ├── request/
│   ├── signer-input/
│   └── evidence/
├── work/
│   └── approved/
└── media-out/
    ├── approval/
    ├── response/
    └── outcome/
```

Directories created by the command are current-user-owned mode `0700`; the
README is mode `0600`. The command never creates private keys, public keys,
secret placeholders, transactions, protocol files, or symlinks. Approval and
response key paths remain explicit operator inputs to the commands that use
them and are not part of this tree. In the separate key hierarchy, the
`platform-pki-keys` root and each trust-domain directory are mode `0700`,
private keys are mode `0600`, and public keys are mode `0644`.

The directories have these intended roles:

- `media-in/request`: exact three-file request received for offline approval.
- `work/approved`: protected local five-file approved request produced by
  `platform-pki offline-csr approve`.
- `media-in/signer-input`: exact five-file approved request received by the
  disconnected signer.
- `media-in/evidence`: separately retained custody or transport evidence that
  is not signer command input.
- `media-out/approval`: approval files returning through controlled media.
- `media-out/response`: exact signer response payload returning through media.
- `media-out/outcome`: terminal outcome payload returning through media.

The initializer owns and validates the fixed directory skeleton and README
only. The seven leaf directories listed above are workflow-owned payload roots.
After creation they may contain normal operator payload files, directories, or
other entries. Reruns validate each payload root itself as a current-user-owned
mode-`0700` non-symlink directory, but do not enumerate, open, authenticate, or
claim any descendant payload. Structural directories above the payload roots
may contain only the documented child directories and README.

No `transactions` directory exists in this workspace. Signer replay,
transactions, candidates, and recovery records remain authoritative only under
`${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure/pki`, or under the
explicit `--namespace` or `--pki-dir` used by the signer command.

## Safety And Output

Initialization rejects relative or noncanonical paths, `/`, overlap with the
known default authoritative PKI tree, symlink components, foreign ownership,
non-directory structural collisions, unexpected structural entries, changed
README content, and unsafe skeleton owner or mode metadata. It does not chmod,
replace, or repair an unsafe initializer-owned object. A safe partial skeleton
can be completed; a safe rerun changes nothing and reports `existing` even when
workflow-owned payload roots contain normal payloads.

Success writes one compact fixed-order JSON object containing `status`,
`service`, `root`, `workspace_dir`, `authoritative_pki_default`, and
`directories`. `status` is `created` when any node was added and `existing`
when no change was required. The output contains paths and service identity but
no key, credential, token, protocol payload, or other secret value. With an
explicit `--root`, both `HOME` and `XDG_CONFIG_HOME` may be absent; in that case
`authoritative_pki_default` is JSON `null` because no default can be derived.
Without `--root`, one of those environment variables is required.

Initialization does not authorize approval, signing, transport, CA mutation,
deployment, finalization, or recovery. Operators still supply exact reviewed
inputs and key paths to each separate command. `offline-workspace init` creates
only this skeleton and README; it does not generate or enroll trust keys.

## One-Workstation Tradeoff

On a one-workstation deployment, the authoritative PKI tree, offline workspace,
and external operator-key tree remain logically separate. Exact paths, explicit
key flags, protocol signatures, digest pins, and approval/signing stages still
apply. This layout does not provide an air gap or an independent machine, and a
compromise of the workstation has a larger blast radius because it may reach
all three trees. Separate keys operated by one person are role separation, not
independent-human approval.
