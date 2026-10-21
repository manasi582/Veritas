"""
Veritas Backup & Recovery
==========================
Creates and restores complete, verified backups of all Veritas data.

What is backed up:
  - evidence.db        — compliance verdicts (tamper-evident ledger)
  - agents.db          — agent registrations and tokens
  - users.db           — user accounts and org memberships
  - audit.db           — system audit log
  - org_config/        — organisation compliance policies (YAML)
  - veritas.vlic       — license file
  - certs/             — TLS certificate and key
  - secrets/           — JWT signing key

What is NOT backed up:
  - pipeline.log       — transient logs, not required for recovery
  - .veritas_state.json — agent state, re-established on re-registration

Backup format: ZIP archive with a manifest.json listing all files and their
SHA-256 checksums for integrity verification.

Usage (CLI):
  python backup.py backup [--out /path/to/backup.zip]
  python backup.py restore /path/to/backup.zip [--dry-run]
  python backup.py verify /path/to/backup.zip

API:
  from backup import create_backup, restore_backup, verify_backup
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import socket
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, List, Optional

logger = logging.getLogger("veritas.backup")

_BACKUP_VERSION = "1"
_MANIFEST_FILE  = "backup_manifest.json"

# Files/dirs to include (relative to data_root())
_BACKUP_TARGETS = [
    "evidence.db",
    "agents.db",
    "users.db",
    "audit.db",
    "veritas.vlic",
    "org_config/configs",
    "certs",
    "secrets",
]

# Files that are critical for restore to succeed
_CRITICAL_FILES = ["evidence.db", "agents.db", "users.db"]


def _data_root() -> Path:
    from runtime_paths import data_root
    return data_root()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _consistent_copy(src: Path, tmpdir: Path) -> Path:
    """
    A point-in-time copy of a SQLite database that is safe while the server is writing to it.
    (Copying the file of a live database can capture a half-written page.) Other files are
    returned unchanged.
    """
    if src.suffix != ".db":
        return src
    dst = tmpdir / src.name
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
    try:
        target = sqlite3.connect(dst)
        try:
            source.backup(target)
            # the live databases use write-ahead logging; a backup must be one self-contained file
            target.execute("PRAGMA journal_mode=DELETE")
        finally:
            target.close()
    finally:
        source.close()
    return dst


def create_backup(output_path: Optional[Path] = None) -> Path:
    """
    Create a complete backup ZIP of all Veritas data.

    Returns the path to the created backup file.

    The backup is verified immediately after creation — if the manifest
    checksums don't match the written data, an error is raised before
    the backup is considered complete.
    """
    root = _data_root()
    now  = datetime.now(timezone.utc)

    if output_path is None:
        ts = now.strftime("%Y%m%dT%H%M%SZ")
        output_path = root / "backups" / f"veritas-backup-{ts}.zip"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    manifest: Dict = {
        "backup_version": _BACKUP_VERSION,
        "app_version":    _app_version(),
        "created_at":     now.isoformat(),
        "data_root":      str(root),
        "files":          {},
    }

    logger.info("Creating backup at %s ...", output_path)
    files_added = 0

    with tempfile.TemporaryDirectory(prefix="veritas-backup-") as _tmp, \
            zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        tmpdir = Path(_tmp)
        for target in _BACKUP_TARGETS:
            src = root / target
            if not src.exists():
                logger.debug("Skipping (not found): %s", src)
                continue

            if src.is_file():
                arcname = target
                snapshot = _consistent_copy(src, tmpdir)
                zf.write(snapshot, arcname)
                manifest["files"][arcname] = {
                    "type":   "file",
                    "sha256": _sha256_file(snapshot),
                    "size":   snapshot.stat().st_size,
                }
                files_added += 1

            elif src.is_dir():
                for child in sorted(src.rglob("*")):
                    if child.is_file():
                        # Use forward slashes so manifest keys match zipfile's namelist
                        # (zipfile normalises to forward slashes on all platforms)
                        arcname = child.relative_to(root).as_posix()
                        zf.write(child, arcname)
                        manifest["files"][arcname] = {
                            "type":   "file",
                            "sha256": _sha256_file(child),
                            "size":   child.stat().st_size,
                        }
                        files_added += 1

        # Write manifest last
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        zf.writestr(_MANIFEST_FILE, manifest_bytes)

    # Immediate verification
    ok, errors = verify_backup(output_path)
    if not ok:
        output_path.unlink(missing_ok=True)
        raise RuntimeError(f"Backup verification failed after creation: {errors}")

    try:
        output_path.chmod(0o600)    # holds the user database, the license and the signing secrets
    except OSError:
        pass

    size_mb = output_path.stat().st_size / 1_048_576
    logger.info(
        "Backup created: %s (%.1f MB, %d files, verified OK)",
        output_path, size_mb, files_added,
    )
    return output_path


def verify_backup(backup_path: Path) -> tuple[bool, List[str]]:
    """
    Verify a backup archive by checking all file SHA-256 checksums
    against the manifest.

    Returns (True, []) if all checksums match.
    Returns (False, [list of errors]) if any file is missing or corrupted.
    """
    errors: List[str] = []

    if not backup_path.exists():
        return False, [f"Backup file not found: {backup_path}"]

    try:
        with zipfile.ZipFile(backup_path, "r") as zf:
            # Read manifest
            if _MANIFEST_FILE not in zf.namelist():
                return False, ["Manifest file missing from backup."]

            manifest = json.loads(zf.read(_MANIFEST_FILE))

            # Check each file
            for arcname, info in manifest.get("files", {}).items():
                if arcname not in zf.namelist():
                    errors.append(f"Missing file in archive: {arcname}")
                    continue

                data = zf.read(arcname)
                actual_sha256 = _sha256_bytes(data)
                if actual_sha256 != info["sha256"]:
                    errors.append(f"Checksum mismatch: {arcname}")
                    continue

                if len(data) != info.get("size", len(data)):
                    errors.append(f"Size mismatch: {arcname}")

    except zipfile.BadZipFile:
        return False, ["Backup file is corrupt (not a valid ZIP)."]
    except Exception as e:
        return False, [f"Verification error: {e}"]

    return len(errors) == 0, errors


_DB_SIDECARS = ("-wal", "-shm", "-journal")     # SQLite files that belong to a database file
_DIR_TARGETS = [t for t in _BACKUP_TARGETS if not t.endswith(".db") and not t.endswith(".vlic")]


def _app_version() -> str:
    try:
        from veritas_version import get_version
        return get_version()
    except Exception:
        return "unknown"


def _safe_arcname(arcname: str) -> bool:
    """A path inside the archive is accepted only if it stays inside one of the backed-up targets."""
    if not arcname or "\\" in arcname or PureWindowsPath(arcname).drive or PurePosixPath(arcname).is_absolute():
        return False
    if ".." in PurePosixPath(arcname).parts:
        return False
    return any(arcname == t or arcname.startswith(t + "/") for t in _BACKUP_TARGETS)


def _server_running() -> bool:
    """True when something accepts connections on the Veritas port of this machine."""
    port = int(os.environ.get("VERITAS_PORT", "8000") or 8000)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


def _integrity_problem(db_path: Path) -> Optional[str]:
    """None when the SQLite file is healthy, else a short description."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
        try:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
        finally:
            conn.close()
    except sqlite3.Error as e:
        return str(e)
    return None if rows == [("ok",)] else "; ".join(str(r[0]) for r in rows[:3])


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def _copy_in(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)


def _newer_than_this_release(backup_version: Optional[str]) -> bool:
    try:
        from veritas_version import parse
        theirs, mine = parse(backup_version), parse(_app_version())
        return bool(theirs and mine and theirs > mine)
    except Exception:
        return False


def restore_backup(backup_path: Path, *, dry_run: bool = False,
                   target_root: Optional[Path] = None,
                   restore_license: bool = False, force: bool = False) -> dict:
    """
    Restore Veritas data from a backup archive, safely.

    The service must be stopped (the `veritas restore` command does that). Steps:
      1. the archive's checksums, version and file paths are checked;
      2. everything is extracted to a staging folder and every database is integrity-checked,
         so a bad backup is refused before any live file is touched;
      3. what is about to be replaced is copied to  <data>/backups/pre-restore-<time>/ ;
      4. files are swapped in (stale SQLite journal files removed); if anything fails the
         previous state is put back;
      5. the live databases are integrity-checked again.

    The license in the backup is NOT restored over an existing license unless restore_license
    is set (a restore must not bring back an older or expired license).

    Returns: restored_files, skipped_files, warnings, errors, safety_copy, success.
    """
    result = {"restored_files": [], "skipped_files": [], "warnings": [], "errors": [],
              "safety_copy": None, "success": False}

    ok, verify_errors = verify_backup(backup_path)
    if not ok:
        result["errors"] = verify_errors
        logger.error("Restore aborted: backup verification failed: %s", verify_errors)
        return result

    try:
        with zipfile.ZipFile(backup_path, "r") as zf:
            manifest = json.loads(zf.read(_MANIFEST_FILE))
    except Exception as e:
        result["errors"].append(f"Cannot read the backup: {e}")
        return result

    if manifest.get("backup_version") != _BACKUP_VERSION:
        result["errors"].append(f"Unsupported backup format {manifest.get('backup_version')!r}.")
        return result
    if _newer_than_this_release(manifest.get("app_version")) and not force:
        result["errors"].append(
            f"This backup was made by Veritas {manifest.get('app_version')}, which is newer than this "
            f"program ({_app_version()}). Upgrade Veritas first, or use --force.")
        return result

    names = list(manifest.get("files", {}))
    unsafe = [a for a in names if not _safe_arcname(a)]
    if unsafe:
        result["errors"].append(f"The backup contains unexpected file paths and was refused: {unsafe[:3]}")
        return result
    missing_critical = [c for c in _CRITICAL_FILES if c not in names]
    if missing_critical:
        result["errors"].append(f"The backup lacks required files: {', '.join(missing_critical)}")
        return result

    root = target_root or _data_root()

    if target_root is None and not force and not dry_run and _server_running():
        result["errors"].append(
            "Veritas appears to be running (the port answers). Stop it first (sudo veritas stop); "
            "restoring under a running server would corrupt the databases.")
        return result

    to_restore = []
    for arcname in names:
        if arcname == "veritas.vlic" and not restore_license and (root / arcname).exists():
            result["skipped_files"].append(arcname)
            result["warnings"].append("The current license was kept (the backup's license was not restored). "
                                      "Use --restore-license to restore it too.")
            continue
        to_restore.append(arcname)

    if dry_run:
        # The same checks the real restore makes before it touches anything, in a scratch folder.
        with tempfile.TemporaryDirectory(prefix="veritas-restore-check-") as scratch, \
                zipfile.ZipFile(backup_path, "r") as zf:
            for arcname in to_restore:
                if arcname.endswith(".db"):
                    probe = Path(scratch) / arcname
                    probe.write_bytes(zf.read(arcname))
                    problem = _integrity_problem(probe)
                    if problem:
                        result["errors"].append(f"{arcname} in the backup is damaged ({problem}).")
                        return result
        result["restored_files"] = to_restore
        result["success"] = True
        return result

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    n = 1
    while (root / "backups" / f"pre-restore-{ts}{'' if n == 1 else f'-{n}'}").exists() or \
            (root / f".restore-staging-{ts}{'' if n == 1 else f'-{n}'}").exists():
        n += 1                                      # two restores in the same second must not collide
    ts = ts if n == 1 else f"{ts}-{n}"
    staging = root / f".restore-staging-{ts}"
    safety = root / "backups" / f"pre-restore-{ts}"
    touched: List[str] = []         # backup targets whose live copy has been modified

    def rollback() -> None:
        for t in touched:
            try:
                _remove(root / t)
                if (safety / t).exists():
                    _copy_in(safety / t, root / t)
                if t.endswith(".db"):                     # a database's write-ahead log goes back with it
                    for suffix in _DB_SIDECARS:
                        _remove(root / (t + suffix))
                        if (safety / (t + suffix)).exists():
                            shutil.copy2(safety / (t + suffix), root / (t + suffix))
            except Exception as e:                       # pragma: no cover - last resort
                result["errors"].append(f"ROLLBACK PROBLEM for {t}: {e}. Your previous data is in {safety}")

    try:
        # 1. stage and check
        with zipfile.ZipFile(backup_path, "r") as zf:
            for arcname in to_restore:
                dest = staging / arcname
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(arcname))
        for arcname in to_restore:
            if arcname.endswith(".db"):
                problem = _integrity_problem(staging / arcname)
                if problem:
                    result["errors"].append(f"{arcname} in the backup is damaged ({problem}). Nothing was changed.")
                    return result

        # 2. keep what is about to be replaced
        targets = [t for t in _BACKUP_TARGETS if any(a == t or a.startswith(t + "/") for a in to_restore)]
        existing = [t for t in targets if (root / t).exists()]
        if existing:
            safety.mkdir(parents=True, exist_ok=True)
            try:
                safety.chmod(0o700)
            except OSError:
                pass
            for t in existing:
                _copy_in(root / t, safety / t)
            for t in existing:                            # journal files belong to the copy too
                for suffix in _DB_SIDECARS:
                    side = root / (t + suffix)
                    if side.exists():
                        shutil.copy2(side, safety / (t + suffix))
            result["safety_copy"] = str(safety)

        # 3. swap in
        for t in targets:
            touched.append(t)
            if t in _DIR_TARGETS:
                _remove(root / t)                         # no leftovers from the replaced state
            else:
                for suffix in _DB_SIDECARS:
                    _remove(root / (t + suffix))
        for arcname in to_restore:
            dest = root / arcname
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging / arcname, dest)
            result["restored_files"].append(arcname)
            if arcname.startswith("secrets/") or arcname == "certs/server.key":
                try:
                    dest.chmod(0o600)
                except OSError:
                    pass

        # 4. the live databases must be healthy
        for arcname in to_restore:
            if arcname.endswith(".db"):
                problem = _integrity_problem(root / arcname)
                if problem:
                    raise RuntimeError(f"{arcname} failed its integrity check after restore ({problem})")

    except Exception as e:
        result["errors"].append(f"Restore failed and was rolled back: {e}")
        rollback()
        result["restored_files"] = []
        return result
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    result["success"] = True
    try:     # a rewind must be visible to the chain, the audit log and the verifier: the server records it at its next start
        import restore_notice
        before = (safety / "evidence.db") if result.get("safety_copy") else None
        restore_notice.write_marker(root, backup_path, before, root / "evidence.db")
    except Exception as e:                           # pragma: no cover - the restore itself succeeded
        result["warnings"].append(f"The restore was not recorded for the audit trail ({e}).")
    logger.info("RESTORE complete: %d files restored, %d skipped; previous data kept in %s",
                len(result["restored_files"]), len(result["skipped_files"]), result["safety_copy"])
    return result


def list_backups(backup_dir: Optional[Path] = None) -> List[dict]:
    """List available backup files with metadata."""
    if backup_dir is None:
        backup_dir = _data_root() / "backups"

    if not backup_dir.exists():
        return []

    backups = []
    for f in sorted(backup_dir.glob("veritas-backup-*.zip"), reverse=True):
        try:
            with zipfile.ZipFile(f, "r") as zf:
                if _MANIFEST_FILE in zf.namelist():
                    manifest = json.loads(zf.read(_MANIFEST_FILE))
                    backups.append({
                        "filename":   f.name,
                        "path":       str(f),
                        "created_at": manifest.get("created_at"),
                        "file_count": len(manifest.get("files", {})),
                        "size_bytes": f.stat().st_size,
                    })
        except Exception:
            backups.append({
                "filename": f.name, "path": str(f),
                "created_at": None, "file_count": None,
                "size_bytes": f.stat().st_size,
            })

    return backups


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def _cli():
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Veritas Backup & Recovery")
    sub = parser.add_subparsers(dest="command", required=True)

    # backup
    bp = sub.add_parser("backup", help="Create a backup")
    bp.add_argument("--out", type=Path, help="Output path (default: data_root/backups/)")

    # restore
    rp = sub.add_parser("restore", help="Restore from backup")
    rp.add_argument("path", type=Path, help="Path to backup ZIP")
    rp.add_argument("--dry-run", action="store_true", help="Validate without writing")
    rp.add_argument("--restore-license", action="store_true", help="Also replace the current license")
    rp.add_argument("--force", action="store_true", help="Restore even if the server seems to be running or the backup is newer")

    # verify
    vp = sub.add_parser("verify", help="Verify backup integrity")
    vp.add_argument("path", type=Path, help="Path to backup ZIP")

    # list
    sub.add_parser("list", help="List available backups")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if args.command == "backup":
        try:
            out = create_backup(args.out)
            print(f"Backup created: {out}")
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr); sys.exit(1)

    elif args.command == "restore":
        print("WARNING: Restore will overwrite existing data. Stop Veritas first.")
        result = restore_backup(args.path, dry_run=args.dry_run,
                                restore_license=args.restore_license, force=args.force)
        for f in result["restored_files"]:
            print(f"  {'[DRY RUN] ' if args.dry_run else ''}restored: {f}")
        for e in result["errors"]:
            print(f"  ERROR: {e}", file=sys.stderr)
        print(f"\n{'DRY RUN ' if args.dry_run else ''}{'OK' if result['success'] else 'FAILED'}: "
              f"{len(result['restored_files'])} files")
        sys.exit(0 if result["success"] else 1)

    elif args.command == "verify":
        ok, errors = verify_backup(args.path)
        if ok:
            print(f"VERIFIED OK: {args.path}")
        else:
            for e in errors:
                print(f"  ERROR: {e}", file=sys.stderr)
            print(f"VERIFICATION FAILED: {args.path}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "list":
        backups = list_backups()
        if not backups:
            print("No backups found.")
        for b in backups:
            size_mb = b["size_bytes"] / 1_048_576
            print(f"  {b['filename']}  {b['created_at'] or 'unknown'}  "
                  f"{b.get('file_count', '?')} files  {size_mb:.1f} MB")


if __name__ == "__main__":
    _cli()
