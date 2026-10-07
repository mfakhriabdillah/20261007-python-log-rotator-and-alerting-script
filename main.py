```python
#!/usr/bin/env python3
"""
Python Log Rotator and Alerting Script
=======================================
A CLI tool for cloud/DevOps engineers to rotate logs and monitor them for
alert-worthy events (error thresholds, pattern matches, disk usage).

Usage:
    python log_rotator_alert.py rotate --path /var/log/myapp --max-size 100M
    python log_rotator_alert.py alert  --path /var/log/myapp --check-interval 300
    python log_rotator_alert.py auto   --path /var/log/myapp
"""

import argparse
import glob
import logging
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.text import mime_text
from pathlib import Path
from smtplib import SMTPException
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_ROTATE_EXTENSIONS = [".log", ".txt"]
DEFAULT_COMPRESSION = "gzip"
DEFAULT_MAX_AGE_DAYS = 30
DEFAULT_ERROR_THRESHOLD = 50
DEFAULT_ALERT_CHECK_INTERVAL = 600  # seconds
DEFAULT_DISK_WARN_PCT = 85
DEFAULT_DISK_CRITICAL_PCT = 95

SUPPORTED_COMPRESSION = {"gzip", "bz2", "none"}

ERROR_LEVELS = {
    "critical": r"\bcritical\b|\bfatal\b|\bpanicked\b",
    "error":    r"\berror\b|\bfail(?:ed|ure)?\b",
    "warning":  r"\bwarn(?:ing)?\b",
    "trace":    r"\btrace\b",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class LogStats:
    """Aggregate stats for a single log file."""
    path: str
    size_bytes: int
    line_count: int
    error_count: int
    warning_count: int
    last_modified: datetime
    first_line_ts: Optional[datetime] = None
    last_line_ts: Optional[datetime] = None


@dataclass
class RotationPlan:
    """Describes what the rotator will do for a given file."""
    source: str
    reason: str
    compressed: bool
    compression_type: str
    dest_path: str
    estimated_saved_bytes: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_size(size_str: str) -> int:
    """Convert a human-readable size string to bytes.

    Supports: 512, 10K, 2M, 1.5G
    """
    if isinstance(size_str, (int, float)):
        return int(size_str)

    match = re.match(r"^([0-9]*\.?[0-9]+)\s*([KMGTP]?)B?$", size_str.strip(), re.IGNORECASE)
    if not match:
        raise ValueError(f"Invalid size string: {size_str!r}")

    number, unit = match.groups()
    unit = unit.upper()
    value = float(number)
    multipliers = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3,
                   "T": 1024 ** 4, "P": 1024 ** 5}
    return int(value * multipliers[unit])


def format_size(size_bytes: int) -> str:
    """Format byte count into a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}PB"


def discover_log_files(path: str, extensions: list[str] | None = None) -> list[str]:
    """Return sorted absolute paths of log files under *path*."""
    extensions = extensions or DEFAULT_ROTATE_EXTENSIONS
    p = Path(path)
    found: list[str] = []
    if p.is_file():
        if p.suffix in extensions:
            found.append(str(p.resolve()))
    elif p.is_dir():
        for ext in extensions:
            found.extend(str(fp.resolve()) for fp in p.rglob(f"*{ext}"))
            found.extend(str(fp.resolve()) for fp in p.rglob(f"*{ext}*"))
    else:
        raise FileNotFoundError(f"Path does not exist: {path}")
    return sorted(set(found))


def count_lines_and_errors(
    filepath: str,
    patterns: dict[str, str] | None = None,
    max_lookback: int = 10_000,
) -> dict[str, int]:
    """Scan the last *max_lookback* lines of *filepath* and tally matches."""
    counts: dict[str, int] = {}
    if patterns is None:
        patterns = ERROR_LEVELS

    try:
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            return counts
        # Read from the tail to avoid loading huge files into memory
        chunk = 8192
        with open(filepath, "rb") as fh:
            fh.seek(0, 2)
            end = fh.tell()
            start = max(0, end - max_lookback * chunk)
            fh.seek(start)
            text = fh.read(end - start).decode("utf-8", errors="replace")

        lines = text.splitlines()
        # Skip blank lines at the very beginning (padding from chunk boundary)
        skip = 0
        for line in lines:
            if line.strip():
                break
            skip += 1
        lines = lines[skip:]

        for line in lines:
            line_lower = line.lower()
            for level, pattern in patterns.items():
                if re.search(pattern, line_lower):
                    counts[level] = counts.get(level, 0) + 1
    except OSError as exc:
        logging.error("Cannot read %s: %s", filepath, exc)
    return counts


# ---------------------------------------------------------------------------
# Rotation engine
# ---------------------------------------------------------------------------
class LogRotator:
    """Rotate log files based on size or age."""

    def __init__(
        self,
        max_age_days: float = DEFAULT_MAX_AGE_DAYS,
        compress: str = DEFAULT_COMPRESSION,
        keep_backups: int = 5,
    ):
        if compress not in SUPPORTED_COMPRESSION:
            raise ValueError(f"Unsupported compression {compress!r}; choose from {SUPPORTED_COMPRESSION}")
        self.max_age_days = max_age_days
        self.compress = compress
        self.keep_backups = keep_backups

    def _rotation_dest(self, source: str, index: int) -> str:
        base, ext = os.path.splitext(source)
        dest = f"{base}.rotated{index}{ext}"
        if self.compress != "none":
            dest += f".{self.compress}"
        return dest

    def _compress_file(self, src: str, method: str) -> None:
        if method == "gzip":
            import gzip
            with open(src, "rb") as f_in:
                with gzip.open(src + ".gz", "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(src)
        elif method == "bz2":
            import bz2
            with open(src, "rb") as f_in:
                with bz2.open(src + ".bz2", "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(src)

    def should_rotate(self, filepath: str, max_size_bytes: int) -> tuple[bool, str]:
        """Decide whether *filepath* needs rotation and return (should_rotate, reason)."""
        try:
            stat = os.stat(filepath)
        except OSError as exc:
            return False, f"Stat failed: {exc}"

        age_days = (time.time() - stat.st_mtime) / 86400
        if age_days > self.max_age_days:
            return True, f"age {age_days:.1f}d > {self.max_age_days}d"
        if stat.st_size > max_size_bytes:
            return True, f"size {stat.st_size}B > {max_size_bytes}B"
        return False, ""

    def execute_rotation(self, source: str, index: int = 0) -> RotationPlan:
        """Perform one rotation of *source* and return a RotationPlan."""
        plan = RotationPlan(
            source=source,
            reason="",
            compressed=self.compress != "none",
            compression_type=self.compress,
            dest_path="",
        )
        try:
            original_size = os.path.getsize(source)
            plan.estimated_saved_bytes = original_size

            dest = self._rotation_dest(source, index)
            plan.dest_path = dest
            plan.reason = f"rotated {format_size(original_size)} → {dest}"

            shutil.copy2(source, dest)
            # Truncate the original without removing it so FDs stay valid
            with open(source, "w"):
                pass

            if self.compress != "none":
                self._compress_file(dest, self.compress)

            # Prune old backups
            base, ext = os.path.splitext(source)
            for old in sorted(glob.glob(f"{base}.rotated*.{ext}*")):
                if old != dest and not old.endswith(f".{self.compress}"):
                    pass  # keep all compressed variants
            excess = sorted(glob.glob(f"{base}.rotated*"))
            for extra in excess[self.keep_backups:]:
                try:
                    os.remove(extra)
                except OSError as exc:
                    logging.warning("Could not prune %s: %s", extra, exc)

        except OSError as exc:
            logging.error("Rotation failed for %s: %s", source, exc)
            plan.reason = f"rotation failed: {exc}"
        return plan

    def rotate_all(
        self,
        paths: list[str],
        max_size_bytes: int,
        dry_run: bool = False,
    ) -> list[RotationPlan]:
        """Rotate every file in *paths* that qualifies; return all plans."""
        plans: list[RotationPlan] = []
        for filepath in paths:
            should, reason = self.should_rotate(filepath, max_size_bytes)
            if not should:
                continue
            if dry_run:
                plans.append(RotationPlan(
                    source=filepath,
                    reason=f"WOULD ROTATE: {reason}",
                    compressed=self.compress != "none",
                    compression_type=self.compress,
                    dest_path=self._rotation_dest(filepath, 0),
                ))
            else:
                plans.append(self.execute_rotation(filepath))
        return plans


# ---------------------------------------------------------------------------
# Alerting engine
# ---------------------------------------------------------------------------
class LogAlertChecker:
    """Monitor log files for error spikes and send alerts."""

    def __init__(
        self,
        error_threshold: int = DEFAULT_ERROR_THRESHOLD,
        warning_threshold: int = 200,
        disk_warn_pct: float = DEFAULT_DISK_WARN_PCT,
        disk_crit_pct: float = DEFAULT_DISK_CRITICAL_PCT,
        alert_email: str | None = None,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
    ):
        self.error_threshold = error_threshold
        self.warning_threshold = warning_threshold
        self.disk_warn_pct = disk_warn_pct
        self.disk_crit_pct = disk_crit_pct
        self.alert_email = alert_email
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self._last_check: dict[str, LogStats] = {}

    def _disk_usage_pct(self, path: str) -> Optional[float]:
        try:
            st = shutil.disk_usage(path)
            return (st.used / st.total) * 100
        except OSError:
            return None

    def check_file(self, filepath: str) -> list[dict]:
        """Return a list of alert dicts for *filepath*."""
        alerts: list[dict] = []
        stats = LogStats(
            path=filepath,
            size_bytes=os.path.getsize(filepath),
            line_count=0,
            error_count=0,
            warning_count=0,
            last_modified=datetime.fromtimestamp(os.path.getmtime(filepath)),
        )
        counts = count_lines_and_errors(filepath)
        stats.error_count = counts.get("error", 0)
        stats.warning_count = counts.get("warning", 0)

        prev = self._last_check.get(filepath)
        delta_error = stats.error_count - (prev.error_count if prev else 0)
        delta_warning = stats.warning_count - (prev.warning_count if prev else 0)
        self._last_check[filepath] = stats

        # Threshold alerts
        if stats.error_count >= self.error_threshold:
            alerts.append({
                "level": "CRITICAL",
                "message": (
                    f"[{filepath}] error count {stats.error_count} exceeds "
                    f"threshold {self.error_threshold}"
                ),
            })
        elif delta_error > 0 and stats.error_count >= self.error_threshold // 2:
            alerts.append({
                "level": "WARNING",
                "message": (
                    f"[{filepath}] error count rising (+{delta_error}) to "
                    f"{stats.error_count} — approaching threshold {self.error_threshold}"
                ),
            })

        if stats.warning_count >= self.warning_threshold:
            alerts.append({
                "level": "WARNING",
                "message": (
                    f"[{filepath}] warning count {stats.warning_count} exceeds "
                    f"threshold {self.warning_threshold}"
                ),
            })

        # Disk usage alert
        pct = self._disk_usage_pct(filepath)
        if pct is not None:
            if pct >= self.disk_crit_pct:
                alerts.append({
                    "level": "CRITICAL",
                    "message": (
                        f"Disk usage at {filepath}: {pct:.1f}% "
                        f"(critical threshold {self.disk_crit_pct}%)"
                    ),
                })
            elif pct >= self.disk_warn_pct:
                alerts.append({
                    "level": "WARNING",
                    "message": (
                        f"Disk usage at {filepath}: {pct:.1f}% "
                        f"(warning threshold {self.disk_warn_pct}%)"
                    ),
                })

        # Pattern-based custom alerts from command-line
        return alerts

    def send_email_alert(
        self,
        subject: str,
        body: str,
    ) -> bool:
        """Attempt to send an alert via SMTP. Returns success flag."""
        if not self.alert_email:
            logging.warning("No alert email configured; skipping email send.")
            return False
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.alert_email
        msg["To"] = self.alert_email
        try:
            import smtplib
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.sendmail(self.alert_email, [self.alert_email], msg.as_string())
            return True
        except (OSError, SMTPException) as exc:
            logging.error("Failed to send email alert: %s", exc)
            return False

    def run_once(self, paths: list[str]) -> list[dict]:
        """Check every path and return combined alerts."""
        all_alerts: list[dict] = []
        for p in paths:
            all_alerts.extend(self.check_file(p))
        return all_alerts

    def run_loop(self, paths: list[str], interval: int) -> None:
        """Continuously check at *interval* seconds until interrupted."""
        logging.info("Alert loop started — checking every %ds", interval)
        try:
            while True:
                alerts = self.run_once(paths)
                for a in alerts:
                    logging.warning("[%s] %s", a["level"], a["message"])
                if alerts and self.alert_email:
                    subject = f"Log Alerts: {len(alerts)} issue(s) detected"
                    body = "\n".join(f"[{a['level']}] {a['message']}" for a in alerts)
                    self.send_email_alert(subject, body)
                time.sleep(interval)
        except KeyboardInterrupt:
            logging.info("Alert loop stopped by user.")


# ---------------------------------------------------------------------------
# Pretty formatters
# ---------------------------------------------------------------------------
def fmt_plan(plan: RotationPlan) -> str:
    prefix = "▶ " if "WOULD" in plan.reason else "✔ "
    return f"{prefix}{plan.reason}"


def fmt_alert(alert: dict) -> str:
    tag = "🔴" if alert["level"] == "CRITICAL" else "🟡"
    return f"{tag} [{alert['level']}] {alert['message']}"


# ---------------------------------------------------------------------------
# Sub-command implementations
# ---------------------------------------------------------------------------
def cmd_rotate(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Execute the rotate sub-command."""
    try:
        extensions = args.extensions.split(",") if args.extensions else DEFAULT_ROTATE_EXTENSIONS
        paths = discover_log_files(args.path, extensions)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return 1

    if not paths:
        logger.info("No log files found matching %s", args.path)
        return 0

    max_size = parse_size(args.max_size)
    rotator = LogRotator(
        max_age_days=args.max_age,
        compress=args.compress,
        keep_backups=args.keep_backups,
    )

    plans = rotator.rotate_all(paths, max_size, dry_run=args.dry_run)

    if not plans:
        logger.info("All log files are within limits — nothing to rotate.")
        return 0

    logger.info("Processed %d file(s); %d need rotation.", len(paths), len(plans))
    for plan in plans:
        print(fmt_plan(plan))
        logger.debug(plan.reason)

    if args.report:
        total_before = sum(os.path.getsize(p.source) for p in plans if not "WOULD" in p.reason)
        print(f"\nReport: {len(plans)} rotation(s) executed, ~{format_size(total_before)} reclaimed.")
        if args.dry_run:
            print("(dry-run — no files were actually rotated)")

    return 0


def cmd_alert(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Execute the alert sub-command."""
    try:
        extensions = args.extensions.split(",") if args.extensions else DEFAULT_ROTATE_EXTENSIONS
        paths = discover_log_files(args.path, extensions)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return 1

    if not paths:
        logger.info("No log files found matching %s", args.path)
        return 0

    checker = LogAlertChecker(
        error_threshold=args.error_threshold,
        warning_threshold=args.warning_threshold,
        disk_warn_pct=args.disk_warn,
        disk_crit_pct=args.disk_crit,
        alert_email=args.email,
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port,
    )

    if args.loop:
        checker.run_loop(paths, args.check_interval)
        return 0

    alerts = checker.run_once(paths)
    if not alerts:
        logger.info("No alerts — all clear.")
        print("✓ All clear. No alerts triggered.")
        return 0

    print(f"\n⚠ {len(alerts)} alert(s) detected:\n")
    for a in alerts:
        print(fmt_alert(a))
        logger.warning("[%s] %s", a["level"], a["message"])

    if args.email and alerts:
        subject = f"Log Alerts: {len(alerts)} issue(s)"
        body = "\n".join(f"[{a['level']}] {a['message']}" for a in alerts)
        ok = checker.send_email_alert(subject, body)
        print(f"\n{'✓' if ok else '✗'} Email alert {'sent' if ok else 'FAILED'} to {args.email}")

    return 2 if any(a["level"] == "CRITICAL" for a in alerts) else 0


def cmd_auto(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Execute the auto sub-command: rotate then alert."""
    rc_rotate = cmd_rotate(args, logger)
    rc_alert = cmd_alert(args, logger)
    return max(rc_rotate, rc_alert)


def cmd_status(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Print a summary status of log files."""
    try:
        extensions = args.extensions.split(",") if args.extensions else DEFAULT_ROTATE_EXTENSIONS
        paths = discover_log_files(args.path, extensions)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return 1

    if not paths:
        print("No log files found.")
        return 0

    print(f"\n{'FILE':<50} {'SIZE':>10} {'LINES':>10} {'ERR':>8} {'WARN':>8}  {'MODIFIED'}")
    print("-" * 110)
    for filepath in paths:
        counts = count_lines_and_errors(filepath)
        try:
            sz = os.path.getsize(filepath)
            mt = os.path.getmtime(filepath)
        except OSError:
            continue
        dt = datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M")
        print(f"{filepath:<50} {format_size(sz):>10} {'N/A':>10} {counts.get('error',0):>8} {counts.get('warning',0):>8}  {dt}")

    # Disk summary
    for filepath in paths[:1]:
        pct = shutil.disk_usage(filepath).used / shutil.disk_usage(filepath).total * 100
        print(f"\nDisk usage for {os.path.dirname(filepath) or '.'}: {pct:.1f}%")

    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_rotator_alert",
        description="Rotate logs and monitor them for alert-worthy events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    parser.add_argument("--log-file", help="Write logs to this file in addition to stderr.")
    parser.add_argument("--log-format", default="%(asctime)s [%(levelname)s] %(message)s",
                        help="Logging format string.")

    sub = parser.add_subparsers(dest="command", title="commands", required=True)

    # ---- rotate ----
    p_rot = sub.add_parser("rotate", help="Rotate log files past size/age limits.")
    p_rot.add_argument("path", help="Log directory or single log file to rotate.")
    p_rot.add_argument("--max-size", default="100M",
                       help="Max log size before rotation (default: 100M).")
    p_rot.add_argument("--max-age", type=float, default=DEFAULT_MAX_AGE_DAYS,
                       help=f"Max log age in days before forced rotation (default: {DEFAULT_MAX_AGE_DAYS}).")
    p_rot.add_argument("--compress", default=DEFAULT_COMPRESSION,
                       choices=sorted(SUPPORTED_COMPRESSION),
                       help="Compression for rotated files (default: gzip).")
    p_rot.add_argument("--keep-backups", type=int, default=5,
                       help="Number of old rotated backups to retain (default: 5).")
    p_rot.add_argument("--extensions", default=None,
                       help="Comma-separated list of extensions to match (default: .log,.txt).")
    p_rot.add_argument("-n", "--dry-run", action="store_true",
                       help="Show what would be done without making changes.")
    p_rot.add_argument("--report", action="store_true",
                       help="Print a summary report after rotation.")

    # ---- alert ----
    p_al = sub.add_parser("alert", help="Check logs for error patterns and send alerts.")
    p_al.add_argument("path", help="Log directory or single log file to monitor.")
    p_al.add_argument("--error-threshold", type=int, default=DEFAULT_ERROR_THRESHOLD,
                      help=f"Error count trigger for CRITICAL alert (default: {DEFAULT_ERROR_THRESHOLD}).")
    p_al.add_argument("--warning-threshold", type=int, default=200,
                      help=f"Warning count trigger for WARNING alert (default: 200).")
    p_al.add_argument("--disk-warn", type=float, default=DEFAULT_DISK_WARN_PCT,
                      help=f"Disk usage % to warn (default: {DEFAULT_DISK_WARN_PCT}%).")
    p_al.add_argument("--disk-crit", type=float, default=DEFAULT_DISK_CRITICAL_PCT,
                      help=f"Disk usage % to critical alert (default: {DEFAULT_DISK_CRITICAL_PCT}%).")
    p_al.add_argument("--email", default=None, help="Send alerts to this email address via SMTP.")
    p_al.add_argument("--smtp-host", default="localhost", help="SMTP server hostname (default: localhost).")
    p_al.add_argument("--smtp-port", type=int, default=25, help="SMTP server port (default: 25).")
    p_al.add_argument("--check-interval", type=int, default=DEFAULT_ALERT_CHECK_INTERVAL,
                      help=f"Seconds between checks in loop mode (default: {DEFAULT_ALERT_CHECK_INTERVAL}).")
    p_al.add_argument("--loop", action="store_true",
                      help="Run continuously, checking every --check-interval seconds.")
    p_al.add_argument("--extensions", default=None,
                      help="Comma-separated extensions to scan (default: .log,.txt).")

    # ---- auto ----
    p_auto = sub.add_parser("auto", help="Rotate then alert in one shot.")
    p_auto.add_argument("path", help="Log directory or single log file.")
    p_auto.add_argument("--max-size", default="100M")
    p_auto.add_argument("--max-age", type=float, default=DEFAULT_MAX_AGE_DAYS)
    p_auto.add_argument("--compress", default=DEFAULT_COMPRESSION,
                        choices=sorted(SUPPORTED_COMPRESSION))
    p_auto.add_argument("--keep-backups", type=int, default=5)
    p_auto.add_argument("--extensions", default=None)
    p_auto.add_argument("-n", "--dry-run", action="store_true")
    p_auto.add_argument("--report", action="store_true")
    p_auto.add_argument("--error-threshold", type=int, default=DEFAULT_ERROR_THRESHOLD)
    p_auto.add_argument("--warning-threshold", type=int, default=200)
    p_auto.add_argument("--disk-warn", type=float, default=DEFAULT_DISK_WARN_PCT)
    p_auto.add_argument("--disk-crit", type=float, default=DEFAULT_DISK_CRITICAL_PCT)
    p_auto.add_argument("--email", default=None)
    p_auto.add_argument("--smtp-host", default="localhost")
    p_auto.add_argument("--smtp-port", type=int, default=25)
    p_auto.add_argument("--check-interval", type=int, default=DEFAULT_ALERT_CHECK_INTERVAL)
    p_auto.add_argument("--loop", action="store_true")

    # ---- status ----
    p_st = sub.add_parser("status", help="Show a summary of monitored log files.")
    p_st.add_argument("path", help="Log directory or single log file.")
    p_st.add_argument("--extensions", default=None,
                      help="Comma-separated extensions to scan.")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Configure logging
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    stderr_hdl = logging.StreamHandler(sys.stderr)
    stderr_hdl.setLevel(logging.DEBUG)
    stderr_hdl.setFormatter(logging.Formatter(args.log_format))
    root.addHandler(stderr_hdl)

    if getattr(args, "log_file", None):
        try:
            file_hdl = logging.FileHandler(args.log_file, encoding="utf-8")
            file_hdl.setLevel(logging.DEBUG)
            file_hdl.setFormatter(logging.Formatter(args.log_format))
            root.addHandler(file_hdl)
        except OSError as exc:
            print(f"Failed to open log file {args.log_file}: {exc}", file=sys.stderr)
            return 1

    dispatch = {
        "rotate": cmd_rotate,
        "alert":  cmd_alert,
        "auto":   cmd_auto,
        "status": cmd_status,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    try:
        return handler(args, logging.getLogger(args.command))
    except Exception as exc:
        logging.getLogger(__name__).exception("Unhandled exception: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```