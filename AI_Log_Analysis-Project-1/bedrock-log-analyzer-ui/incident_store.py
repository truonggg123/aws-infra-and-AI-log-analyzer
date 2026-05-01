"""
Incident Store — Persist analysis results to disk for dashboard viewing.

Saves each batch run as a JSON file. Provides listing, loading, and cleanup.
Used by auto_analyzer.py (write) and streamlit_app.py (read).
"""
import os
import json
import glob
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Default data directory (overridden by env var)
DEFAULT_DATA_DIR = "/data/incidents"


class IncidentStore:
    """Manages incident data on disk."""

    def __init__(self, data_dir: str = None, retention_days: int = 7):
        """
        Args:
            data_dir: Directory to store incident JSON files.
            retention_days: Auto-delete files older than this many days.
        """
        self.data_dir = data_dir or os.getenv("INCIDENT_DATA_DIR", DEFAULT_DATA_DIR)
        self.retention_days = retention_days
        os.makedirs(self.data_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save_incident(
        self,
        batch_id: str,
        time_range: Dict[str, str],
        status: str,
        total_logs: int,
        sources: List[str],
        signals: List[Dict] = None,
        correlated_events_summary: List[Dict] = None,
        global_rca: Dict = None,
        telegram_sent: bool = False,
        cost: Dict = None,
    ) -> str:
        """
        Save a single batch result to disk.

        Args:
            batch_id: ISO timestamp string identifying this batch.
            status: "incident" or "clean".

        Returns:
            Path to saved file.
        """
        record = {
            "batch_id": batch_id,
            "saved_at": datetime.utcnow().isoformat() + "Z",
            "time_range": time_range,
            "status": status,
            "total_logs_analyzed": total_logs,
            "sources_analyzed": sources,
            "signals_count": len(signals) if signals else 0,
            "signals": (signals or [])[:30],  # cap to avoid huge files
            "correlated_events_count": len(correlated_events_summary) if correlated_events_summary else 0,
            "correlated_events": correlated_events_summary or [],
            "global_rca": global_rca,
            "telegram_sent": telegram_sent,
            "cost": cost or {"tokens": 0, "usd": 0.0},
        }

        # File name: safe timestamp + status
        safe_ts = batch_id.replace(":", "-").replace(" ", "T")
        filename = f"{safe_ts}_{status}.json"
        filepath = os.path.join(self.data_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False, default=str)

        # Update latest symlink / copy
        latest_path = os.path.join(self.data_dir, "latest.json")
        try:
            with open(latest_path, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2, ensure_ascii=False, default=str)
        except Exception:
            pass

        logger.info(f"Saved incident: {filepath}")
        return filepath

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_incidents(self, last_n: int = 50, status_filter: str = None) -> List[Dict]:
        """
        List recent incidents (metadata only, no full RCA).

        Args:
            last_n: Maximum number of records to return.
            status_filter: "incident" or "clean" to filter. None = all.

        Returns:
            List of dicts with summary info, newest first.
        """
        pattern = os.path.join(self.data_dir, "*.json")
        files = sorted(glob.glob(pattern), reverse=True)

        results = []
        for fpath in files:
            basename = os.path.basename(fpath)
            if basename == "latest.json":
                continue

            # Quick filter by filename before loading
            if status_filter:
                if f"_{status_filter}.json" not in basename:
                    continue

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Return summary only (exclude large fields)
                summary = {
                    "batch_id": data.get("batch_id", ""),
                    "saved_at": data.get("saved_at", ""),
                    "status": data.get("status", "unknown"),
                    "total_logs_analyzed": data.get("total_logs_analyzed", 0),
                    "sources_analyzed": data.get("sources_analyzed", []),
                    "signals_count": data.get("signals_count", 0),
                    "correlated_events_count": data.get("correlated_events_count", 0),
                    "telegram_sent": data.get("telegram_sent", False),
                    "cost": data.get("cost", {}),
                    "filepath": fpath,
                }

                # Extract severity from global_rca if available
                rca = data.get("global_rca")
                if rca and isinstance(rca, dict):
                    ta = rca.get("threat_assessment", {})
                    summary["severity"] = ta.get("severity", "Unknown")
                    summary["attack_narrative"] = (rca.get("attack_narrative") or "")[:200]
                    summary["root_cause"] = (rca.get("root_cause") or "")[:200]
                else:
                    summary["severity"] = "N/A"
                    summary["attack_narrative"] = ""
                    summary["root_cause"] = ""

                results.append(summary)
            except Exception as e:
                logger.warning(f"Failed to read {fpath}: {e}")
                continue

            if len(results) >= last_n:
                break

        return results

    def load_incident(self, filepath: str) -> Optional[Dict]:
        """Load full incident data from a file path."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load incident {filepath}: {e}")
            return None

    def load_latest(self) -> Optional[Dict]:
        """Load the most recent incident."""
        latest_path = os.path.join(self.data_dir, "latest.json")
        if os.path.exists(latest_path):
            return self.load_incident(latest_path)
        # Fallback: find newest file
        incidents = self.list_incidents(last_n=1)
        if incidents:
            return self.load_incident(incidents[0]["filepath"])
        return None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_summary_stats(self) -> Dict:
        """Get summary statistics across all stored incidents."""
        all_incidents = self.list_incidents(last_n=9999)

        total_batches = len(all_incidents)
        incident_count = sum(1 for i in all_incidents if i["status"] == "incident")
        clean_count = sum(1 for i in all_incidents if i["status"] == "clean")
        total_logs = sum(i.get("total_logs_analyzed", 0) for i in all_incidents)
        total_cost = sum(i.get("cost", {}).get("usd", 0) for i in all_incidents)
        telegram_sent = sum(1 for i in all_incidents if i.get("telegram_sent"))

        # Today's stats
        today_str = datetime.utcnow().strftime("%Y-%m-%d")
        today_incidents = [i for i in all_incidents if i.get("batch_id", "").startswith(today_str)]
        today_incident_count = sum(1 for i in today_incidents if i["status"] == "incident")

        return {
            "total_batches": total_batches,
            "incident_count": incident_count,
            "clean_count": clean_count,
            "total_logs_analyzed": total_logs,
            "total_cost_usd": round(total_cost, 4),
            "telegram_alerts_sent": telegram_sent,
            "today_batches": len(today_incidents),
            "today_incidents": today_incident_count,
            "last_batch": all_incidents[0] if all_incidents else None,
        }

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_old(self) -> int:
        """
        Delete incident files older than retention_days.

        Returns:
            Number of files deleted.
        """
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        pattern = os.path.join(self.data_dir, "*.json")
        files = glob.glob(pattern)

        deleted = 0
        for fpath in files:
            basename = os.path.basename(fpath)
            if basename == "latest.json":
                continue

            try:
                # Check file modification time
                mtime = datetime.utcfromtimestamp(os.path.getmtime(fpath))
                if mtime < cutoff:
                    os.remove(fpath)
                    deleted += 1
                    logger.info(f"Cleaned up old incident: {basename}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {fpath}: {e}")

        if deleted:
            logger.info(f"Cleaned up {deleted} incident files older than {self.retention_days} days")
        return deleted
