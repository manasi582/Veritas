# Linux Test Findings (v1.0.15, Ubuntu)

Status: **logged, not yet fixed.** Discussion first, then resolution.

## Test results (Ubuntu, .deb v1.0.15)

| Part | Result |
|---|---|
| A Install | OK. User, dirs and enabled unit are correct. With no license the service crash-loops with a clear error (it does not stay inactive). |
| B Fingerprint | `veritas fingerprint` prints `d130e954…c54cdb`, which is misleading for licensing. |
| D Start | Works with the runtime fingerprint or an unbound license. |
| E Health | `/health` returns `{"status":"ok"}`, `/setup` returns 200, `/api/auth/me` returns 401, port 8000 is listening. |
| F restart / SIGKILL | OK. Auto-restart gives a new PID and health is OK. |
| F wrong-machine license | Clear rejection. |
| F no license | Clear "not found" message, then a restart loop. |
| F reboot, G agent .deb, H uninstall | Not run. |

## Finding 1 (critical): CLI fingerprint != runtime fingerprint

A license bound to the output of `veritas fingerprint` is rejected by the service:

```
Veritas license is not valid for this machine.
```

| Source | MAC used | Fingerprint |
|---|---|---|
| `veritas fingerprint` (host Python) | enp7s0 -> 0x40c2ba985cf8 | d130e954…c54cdb |
| `veritas-runtime` (PyInstaller 3.11) | wlp0s20f3 -> 0x5cb47e6c49d1 | 8ef2ef21…5dae43 |

- The NVMe serial `24384B269041` was read correctly by both, so the disk-serial logic is not the cause.
- A license bound to the wifi (runtime) fingerprint starts. One bound to the ethernet (CLI) fingerprint fails.
- Root cause: the MAC comes from different, nondeterministic sources. The MAC is chosen by `uuid.getnode()` in the CLI, `license.py` and `tools/fingerprint.py`, and by the first `net.Interfaces()` entry with a hardware address in Go (`veritas-launcher/license.go`). Different Python builds and interface orders pick different NICs.
- The Go launcher also formats the MAC as `aa:bb:..`, while Python uses `hex(int)`. The two formats cannot produce the same hash.
- Working license on the test box: `~/ubuntu_runtime_bound.vlic`, bound to the runtime fingerprint.

Correction to an earlier hypothesis: the `/dev/sda` versus NVMe mismatch in `license_linux.go` (Go only tries `sda`) is real, but it is not what failed in this test. It should still be fixed.

## Proposed fix (to be discussed)

1. Linux anchor: `/etc/machine-id` first, then disk serial, then a MAC as a last resort.
2. If a MAC is kept, use one deterministic rule in one place: physical interfaces only (`/sys/class/net/<if>/device`), ethernet before wireless, sorted by name.
3. One source of truth: `veritas fingerprint` should call the runtime or launcher, not host Python. This also removes the host `python3` and `lsblk` dependency.
4. Version the fingerprint (`v2:` prefix) and give existing bound licenses a grace path or reissue them via the license portal.
5. Consider dropping hostname, because renaming a server breaks the license.
6. Add a CI check that the CLI and runtime fingerprints are equal on the same machine.

## Decisions (agreed)

- Anchor on `/etc/machine-id` (Linux), with the disk serial as a fallback. No MAC address.
- Drop hostname from the fingerprint.
- Reissue existing bound licenses (no dual-fingerprint grace path in the validator).
- Still to define: the equivalent anchor on macOS (`IOPlatformUUID`) and Windows (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`), the `v2:` fingerprint format, and the portal reissue flow.
- Implementation waits until the rest of the agenda has been discussed.

## Other open items from the first review

- No Linux install-test workflow (macOS and Windows have one).
- `veritas-launcher/license_linux.go` only reads `/dev/sda` (fix with the finding above).
- `postinst` says `https://localhost:8000` and the CLI says `http://`. Make them consistent.
- `INSTALL.md` is at 1.0.12 while the release is 1.0.15.
- `veritas-license-portal` shows as modified, and many files show line-ending churn. Check `.gitignore` covers `tools/private_key.pem` and `*.vlic`.

## Agenda (one by one)

1. Fingerprint design (this document).
2. Architecture brush-up.
3. Demo simulation environment that continuously sends telemetry.
4. License portal: make it simpler.
