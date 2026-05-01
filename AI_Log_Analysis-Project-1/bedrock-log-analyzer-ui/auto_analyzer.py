#!/usr/bin/env python3
"""
Auto Log Analyzer — Automated pipeline running every 5 minutes via cron.

Pipeline steps:
  1. Pull logs from all CloudWatch Log Groups (last 5 minutes)
  2. Parse + tag source
  3. Pattern analysis (clustering, temporal)
  4. Cross-source correlation (AdvancedCorrelator)
  5. If anomaly detected → Bedrock AI Global RCA
  6. Send Telegram alert (if threat found)
  7. Save results to disk (incident_store)
  8. Cleanup old files (>7 days)

Reuses 100% of existing src/ modules — no duplication.
"""
import os
import sys
import json
import logging
from datetime import datetime, timedelta
from dataclasses import asdict

# Add src/ to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Load environment
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Existing modules (reused 100%)
from cloudwatch_client import CloudWatchClient
from log_parser import LogParser
from pattern_analyzer import PatternAnalyzer
from advanced_correlator import AdvancedCorrelator
from log_preprocessor import build_unified_context
from bedrock_enhancer import BedrockEnhancer
from telegram_notifier import TelegramNotifier
from incident_store import IncidentStore

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

REGION = os.getenv("AWS_REGION", "ap-southeast-1")
AWS_PROFILE = os.getenv("AWS_PROFILE", "") or None

# All 9 log groups
ALL_LOG_GROUPS = [
    g.strip()
    for g in os.getenv(
        "AUTO_ANALYSIS_LOG_GROUPS",
        "/aws/vpc/flowlogs,"
        "/aws/cloudtrail/logs,"
        "/aws/ec2/web-tier/system,"
        "/aws/ec2/web-tier/httpd,"
        "/aws/ec2/web-tier/application,"
        "/aws/ec2/app-tier/system,"
        "/aws/ec2/app-tier/streamlit,"
        "/aws/rds/mysql/error,"
        "/aws/rds/mysql/slowquery",
    ).split(",")
    if g.strip()
]

INTERVAL_MINUTES = int(os.getenv("AUTO_ANALYSIS_INTERVAL_MINUTES", "5"))
BEDROCK_MODEL = os.getenv("AUTO_BEDROCK_MODEL", "anthropic.claude-3-haiku-20240307-v1:0")
RULES_PATH = os.path.join(os.path.dirname(__file__), "correlation_rules.json")
RETENTION_DAYS = int(os.getenv("INCIDENT_RETENTION_DAYS", "7"))

# Anomaly thresholds — only call Bedrock when these are met
MIN_CORRELATED_EVENTS = 1      # At least 1 correlated attack pattern
MIN_ERROR_RATE = 0.20           # Or overall error rate > 20%
MIN_HIGH_SEVERITY_SIGNALS = 3   # Or 3+ HIGH/CRITICAL signals

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("auto_analyzer")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline():
    """Execute one batch of the analysis pipeline."""
    now = datetime.utcnow()
    start = now - timedelta(minutes=INTERVAL_MINUTES)
    batch_id = now.strftime("%Y-%m-%dT%H:%M:%S")

    logger.info(f"{'='*60}")
    logger.info(f"BATCH START: {batch_id}")
    logger.info(f"Time range: {start.isoformat()} → {now.isoformat()}")
    logger.info(f"Scanning {len(ALL_LOG_GROUPS)} log groups")
    logger.info(f"{'='*60}")

    store = IncidentStore(retention_days=RETENTION_DAYS)

    # ──────────────────────────────────────────────────────────
    # Step 1: Pull logs from all CloudWatch Log Groups
    # ──────────────────────────────────────────────────────────
    cw_client = CloudWatchClient(region=REGION, profile=AWS_PROFILE if AWS_PROFILE != "default" else None)
    all_source_logs = {}
    total_logs_pulled = 0

    for log_group in ALL_LOG_GROUPS:
        try:
            raw_logs = cw_client.get_logs(
                log_group=log_group,
                start_time=start,
                end_time=now,
                max_matches=100000,
            )
            if raw_logs:
                all_source_logs[log_group] = raw_logs
                total_logs_pulled += len(raw_logs)
                logger.info(f"  ✅ {log_group}: {len(raw_logs)} logs")
            else:
                logger.info(f"  ⏭️  {log_group}: no logs")
        except Exception as e:
            logger.warning(f"  ❌ {log_group}: {e}")

    if total_logs_pulled == 0:
        logger.info("No logs found in this batch — saving clean result")
        store.save_incident(
            batch_id=batch_id,
            time_range={"start": start.isoformat(), "end": now.isoformat()},
            status="clean",
            total_logs=0,
            sources=list(all_source_logs.keys()),
        )
        store.cleanup_old()
        return

    logger.info(f"Total: {total_logs_pulled} logs from {len(all_source_logs)} sources")

    # ──────────────────────────────────────────────────────────
    # Step 2: Parse + Tag source
    # ──────────────────────────────────────────────────────────
    parser = LogParser()
    all_parsed = []

    for log_group, raw_logs in all_source_logs.items():
        for log in raw_logs:
            entry = parser.parse_log_entry(log)
            if entry:
                entry.component = log_group
                all_parsed.append(entry)

    logger.info(f"Parsed: {len(all_parsed)} entries")

    # ──────────────────────────────────────────────────────────
    # Step 3: Pattern Analysis
    # ──────────────────────────────────────────────────────────
    analyzer = PatternAnalyzer()
    analysis = analyzer.analyze_log_entries(all_parsed)
    logger.info(f"Patterns: {len(analysis.error_patterns)} error patterns found")

    # ──────────────────────────────────────────────────────────
    # Step 4: Cross-source Correlation
    # ──────────────────────────────────────────────────────────
    correlated_events = []
    if len(all_source_logs) >= 2:
        correlator = AdvancedCorrelator(
            rules_config_path=RULES_PATH if os.path.exists(RULES_PATH) else None
        )
        correlated_events = correlator.correlate_multi_source(
            log_entries=all_parsed,
            clustered_patterns=analysis.error_patterns,
            time_window_seconds=INTERVAL_MINUTES * 60,
        )
        logger.info(f"Correlation: {len(correlated_events)} attack patterns")

    # ──────────────────────────────────────────────────────────
    # Step 5: Build unified context + decide if AI needed
    # ──────────────────────────────────────────────────────────
    per_source_entries = {}
    for log_group in all_source_logs:
        per_source_entries[log_group] = [
            e for e in all_parsed if e.component == log_group
        ]

    time_range_str = f"{start.strftime('%H:%M %d/%m')} → {now.strftime('%H:%M %d/%m')}"

    unified_ctx = build_unified_context(
        per_source_entries=per_source_entries,
        analysis=analysis,
        correlated_events=correlated_events,
        time_range_str=time_range_str,
    )

    # --- Anomaly detection: decide if Bedrock AI call is needed ---
    has_correlation = len(correlated_events) >= MIN_CORRELATED_EVENTS

    # Count HIGH/CRITICAL signals
    high_signals = sum(
        1 for s in unified_ctx.get("signals", [])
        if s.get("severity") in ("HIGH", "CRITICAL")
    )
    has_high_signals = high_signals >= MIN_HIGH_SEVERITY_SIGNALS

    # Overall error rate
    total_entries = len(all_parsed)
    error_entries = sum(
        1 for e in all_parsed
        if (e.severity or "").upper() in ("ERROR", "CRITICAL", "FATAL")
    )
    error_rate = error_entries / total_entries if total_entries > 0 else 0
    has_high_error_rate = error_rate >= MIN_ERROR_RATE

    needs_ai = has_correlation or has_high_signals or has_high_error_rate

    logger.info(
        f"Anomaly check: correlations={len(correlated_events)}, "
        f"high_signals={high_signals}, error_rate={error_rate:.1%} "
        f"→ {'🔴 AI NEEDED' if needs_ai else '🟢 CLEAN'}"
    )

    # ──────────────────────────────────────────────────────────
    # Step 6: Global RCA (only if anomaly detected)
    # ──────────────────────────────────────────────────────────
    global_rca = None
    global_rca_dict = None
    cost_info = {"tokens": 0, "usd": 0.0}

    if needs_ai:
        logger.info("🤖 Running Bedrock Global RCA...")
        enhancer = BedrockEnhancer(region=REGION, model=BEDROCK_MODEL)

        if enhancer.is_available():
            try:
                rca_obj, usage_stats = enhancer.generate_global_rca(unified_ctx)
                global_rca = rca_obj

                if usage_stats.get("ai_enhancement_used"):
                    cost_info = {
                        "tokens": usage_stats.get("total_tokens_used", 0),
                        "usd": usage_stats.get("estimated_total_cost", 0.0),
                    }
                    logger.info(
                        f"  RCA complete — tokens: {cost_info['tokens']}, "
                        f"cost: ${cost_info['usd']:.4f}"
                    )

                    # Convert GlobalRCA to dict for storage
                    global_rca_dict = {
                        "incident_story": rca_obj.incident_story,
                        "threat_assessment": rca_obj.threat_assessment,
                        "attack_narrative": rca_obj.attack_narrative,
                        "affected_components": rca_obj.affected_components,
                        "root_cause": rca_obj.root_cause,
                        "mitre_mapping": rca_obj.mitre_mapping,
                        "immediate_actions": rca_obj.immediate_actions,
                        "remediation_plan": rca_obj.remediation_plan,
                        "raw_ai_response": rca_obj.raw_ai_response,
                    }
                else:
                    logger.warning(f"  AI failed: {usage_stats.get('error', 'unknown')}")
            except Exception as e:
                logger.error(f"  Bedrock error: {e}")
        else:
            logger.warning("  Bedrock not available — skipping AI")

    # ──────────────────────────────────────────────────────────
    # Step 7: Send Telegram alert (if threat found)
    # ──────────────────────────────────────────────────────────
    telegram_sent = False

    if global_rca_dict:
        logger.info("📱 Sending Telegram alert...")
        try:
            notifier = TelegramNotifier()
            alert_metadata = {
                "time_range": time_range_str,
                "total_logs": total_logs_pulled,
            }
            telegram_sent = notifier.send_attack_alert(
                global_rca=global_rca_dict,
                correlated_events=correlated_events,
                analysis_metadata=alert_metadata,
            )
            if telegram_sent:
                logger.info("  ✅ Telegram alert sent")
            else:
                logger.warning("  ⚠️ Telegram alert not sent (check config)")
        except Exception as e:
            logger.error(f"  ❌ Telegram error: {e}")

    # ──────────────────────────────────────────────────────────
    # Step 8: Save results + cleanup
    # ──────────────────────────────────────────────────────────
    # Build correlated events summary (serializable)
    corr_summary = []
    for ev in correlated_events:
        corr_summary.append({
            "attack_name": ev.attack_name,
            "severity": ev.severity,
            "confidence": ev.confidence_score,
            "sources": ev.sources,
            "events_count": len(ev.timeline),
            "correlation_key": ev.primary_correlation_key,
            "intent": ev.intent,
            "matched_rules": ev.matched_rules,
        })

    # Signals summary
    signals = unified_ctx.get("signals", [])

    status = "incident" if needs_ai else "clean"
    filepath = store.save_incident(
        batch_id=batch_id,
        time_range={"start": start.isoformat(), "end": now.isoformat()},
        status=status,
        total_logs=total_logs_pulled,
        sources=list(all_source_logs.keys()),
        signals=signals,
        correlated_events_summary=corr_summary,
        global_rca=global_rca_dict,
        telegram_sent=telegram_sent,
        cost=cost_info,
    )

    logger.info(f"💾 Saved: {filepath}")

    # Cleanup old files
    deleted = store.cleanup_old()
    if deleted:
        logger.info(f"🗑️ Cleaned up {deleted} old files")

    logger.info(f"{'='*60}")
    logger.info(f"BATCH END: {status.upper()} | {total_logs_pulled} logs | {len(correlated_events)} correlations")
    logger.info(f"{'='*60}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        run_pipeline()
    except Exception as e:
        logger.critical(f"Pipeline crashed: {e}", exc_info=True)
        sys.exit(1)
