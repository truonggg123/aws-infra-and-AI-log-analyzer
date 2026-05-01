"""
Streamlit UI for Bedrock Log Analyzer

Dual-mode interface:
  1. DASHBOARD MODE: View automated incident results (from auto_analyzer.py cron)
  2. MANUAL MODE: Run on-demand analysis with custom time range / search term

Auto pipeline runs every 5 minutes via cron (see auto_analyzer.py).
Streamlit is the optional UI layer for incident review.
"""
import streamlit as st
import sys
import os
from datetime import datetime, timedelta, date, time
import json

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cloudwatch_client import CloudWatchClient
from log_parser import LogParser
from pattern_analyzer import PatternAnalyzer
from rule_detector import RuleBasedDetector
from bedrock_enhancer import BedrockEnhancer
from log_preprocessor import LogPreprocessor, build_unified_context, build_deep_dive_context
from models import Metadata, AIInfo, AnalysisResult, GlobalRCA, DeepDiveResult
from advanced_correlator import AdvancedCorrelator, AdvancedCorrelatedEvent
from telegram_notifier import TelegramNotifier
from incident_store import IncidentStore

# Page config
st.set_page_config(
    page_title="Bedrock Log Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .solution-card {
        background-color: #e8f4f8;
        padding: 15px;
        border-left: 4px solid #0066cc;
        margin: 10px 0;
        border-radius: 5px;
    }
    .ai-badge {
        background-color: #ffd700;
        color: #000;
        padding: 5px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_result' not in st.session_state:
    st.session_state.analysis_result = None
if 'is_analyzing' not in st.session_state:
    st.session_state.is_analyzing = False
if 'advanced_correlated_events' not in st.session_state:
    st.session_state.advanced_correlated_events = []
if 'global_rca' not in st.session_state:
    st.session_state.global_rca = None
if 'deep_dive_results' not in st.session_state:
    st.session_state.deep_dive_results = {}
if 'per_source_entries' not in st.session_state:
    st.session_state.per_source_entries = {}
if 'analysis_data' not in st.session_state:
    st.session_state.analysis_data = None

# ============================================================
# SIDEBAR — Configuration
# ============================================================
st.sidebar.title("⚙️ Configuration")

# --- AWS Settings ---
st.sidebar.subheader("AWS Settings")
aws_region = st.sidebar.text_input("AWS Region", value="ap-southeast-1")
aws_profile = st.sidebar.text_input("AWS Profile", value="")

# --- Log Source Selection ---
st.sidebar.subheader("📂 Log Sources")

LOG_GROUP_OPTIONS = [
    "/aws/vpc/flowlogs",
    "/aws/cloudtrail/logs",
    "/aws/ec2/web-tier/system",
    "/aws/ec2/web-tier/httpd",
    "/aws/ec2/web-tier/application",
    "/aws/ec2/app-tier/system",
    "/aws/ec2/app-tier/streamlit",
    "/aws/rds/mysql/error",
    "/aws/rds/mysql/slowquery",
]

selected_log_groups = st.sidebar.multiselect(
    "Log Groups",
    options=LOG_GROUP_OPTIONS,
    default=LOG_GROUP_OPTIONS,  # ALL selected by default
    help="Mặc định: tất cả sources để AI có context đầy đủ nhất. Hệ thống tự động correlation khi có 2+ sources."
)

if not selected_log_groups:
    st.sidebar.error("⚠️ Vui lòng chọn ít nhất 1 log group.")
elif len(selected_log_groups) >= 2:
    st.sidebar.success(f"✅ {len(selected_log_groups)} sources → Cross-source correlation sẽ tự động chạy")

# --- Search Term (always optional) ---
st.sidebar.subheader("🔍 Search Settings")

search_term = st.sidebar.text_input(
    "Search Term (tùy chọn)",
    value="",
    help="Nhập từ khóa lọc (ví dụ: REJECT, error, SQL Injection). Để trống = quét toàn bộ logs tự động.",
    placeholder="Để trống = auto-scan toàn bộ"
)

# Internal limit for retrieval (increased for large-scale analysis)
max_matches = 100000

# --- Time Range (replaces "hours back") ---
st.sidebar.subheader("⏰ Time Range")

# Default: last 1 hour
default_end = datetime.now()
default_start = default_end - timedelta(hours=1)

col_date1, col_date2 = st.sidebar.columns(2)
with col_date1:
    start_date = st.date_input("Start Date", value=default_start.date())
with col_date2:
    start_time_input = st.time_input("Start Time", value=default_start.time().replace(second=0, microsecond=0))

col_date3, col_date4 = st.sidebar.columns(2)
with col_date3:
    end_date = st.date_input("End Date", value=default_end.date())
with col_date4:
    end_time_input = st.time_input("End Time", value=default_end.time().replace(second=0, microsecond=0))

# Combine date + time into datetime
start_dt = datetime.combine(start_date, start_time_input)
end_dt = datetime.combine(end_date, end_time_input)

# --- AI Configuration ---
st.sidebar.subheader("AI Enhancement")
enable_ai = st.sidebar.checkbox("Enable AI Enhancement", value=True)
bedrock_model = st.sidebar.selectbox(
    "Bedrock Model",
    [
        "anthropic.claude-3-haiku-20240307-v1:0", 
        "apac.anthropic.claude-3-5-sonnet-20240620-v1:0",
        "apac.anthropic.claude-3-sonnet-20240229-v1:0",
        "us.anthropic.claude-3-5-sonnet-20240620-v1:0"
    ],
    help="Dùng 'apac.' cho khu vực Singapore (ap-southeast-1) hoặc 'anthropic.claude-3-haiku' bản gốc. Haiku thường luôn chạy ổn trên on-demand."
)

# ============================================================
# MAIN CONTENT — Page Selector
# ============================================================
st.title("📊 AI-Powered Log Analysis System")

page_mode = st.radio(
    "Mode",
    ["🔴 Incident Dashboard", "🔍 Manual Analysis"],
    horizontal=True,
    help="Dashboard: xem kết quả auto-scan mỗi 5 phút. Manual: chạy phân tích thủ công."
)

# ============================================================
# MANUAL ANALYSIS MODE
# ============================================================
if page_mode == "🔍 Manual Analysis" and st.sidebar.button("🚀 Analyze Logs", use_container_width=True, type="primary"):

    # --- Input validation ---
    validation_errors = []

    if not selected_log_groups:
        validation_errors.append("⚠️ Vui lòng chọn ít nhất 1 log group.")

    if start_dt >= end_dt:
        validation_errors.append("⚠️ Start Time phải trước End Time.")

    if validation_errors:
        for err in validation_errors:
            st.error(err)
    else:
        # --- All inputs valid → run analysis ---
        st.session_state.is_analyzing = True

        with st.status("🔍 Analyzing logs...", expanded=True) as status:
            try:
                cw_client = CloudWatchClient(region=aws_region, profile=aws_profile)
                effective_search = search_term.strip() if search_term and search_term.strip() else None

                if not effective_search:
                    st.write("🔍 Không có search term → Quét toàn bộ logs để phát hiện bất thường tự động")

                # ============================================================
                # Step 1: Pull logs from all selected sources
                # ============================================================
                st.write(f"📂 Pulling logs from {len(selected_log_groups)} sources...")
                
                all_source_logs = {}
                total_logs_pulled = 0
                
                for log_group in selected_log_groups:
                    st.write(f"  📂 Pulling from {log_group}...")
                    raw_logs = cw_client.get_logs(
                        log_group=log_group,
                        start_time=start_dt,
                        end_time=end_dt,
                        search_term=effective_search,
                        max_matches=max_matches
                    )
                    if raw_logs:
                        all_source_logs[log_group] = raw_logs
                        total_logs_pulled += len(raw_logs)
                        st.write(f"    ✅ {len(raw_logs)} logs from {log_group}")
                    else:
                        st.write(f"    ⚠️ No logs from {log_group}")
                
                if total_logs_pulled == 0:
                    st.warning("⚠️ Không tìm thấy logs nào trong khoảng thời gian đã chọn.")
                    st.session_state.is_analyzing = False
                    status.update(label="⚠️ No logs found", state="error", expanded=True)
                else:
                    st.write(f"✅ Total: {total_logs_pulled} logs from {len(all_source_logs)} sources")
                    
                    # ============================================================
                    # Step 2: Parse + Tag with source
                    # ============================================================
                    st.write("🔍 Parsing logs...")
                    parser = LogParser()
                    all_parsed_entries = []
                    
                    for log_group, raw_logs in all_source_logs.items():
                        for log in raw_logs:
                            entry = parser.parse_log_entry(log)
                            if entry:
                                entry.component = log_group
                                all_parsed_entries.append(entry)
                    
                    st.write(f"✅ Parsed {len(all_parsed_entries)} log entries")
                    
                    # ============================================================
                    # Step 3: Pattern Analysis (clustering + temporal)
                    # ============================================================
                    st.write("📊 Analyzing patterns...")
                    analyzer = PatternAnalyzer()
                    analysis = analyzer.analyze_log_entries(all_parsed_entries)
                    
                    reduction_pct = ((len(all_parsed_entries) - len(analysis.error_patterns)) / len(all_parsed_entries) * 100) if all_parsed_entries else 0
                    st.write(f"✅ Found {len(analysis.error_patterns)} error patterns ({reduction_pct:.1f}% noise reduction)")
                    
                    if analysis.error_patterns:
                        st.write("🔍 Top Patterns Detected:")
                        for i, pattern in enumerate(analysis.error_patterns[:5], 1):
                            preview = pattern.pattern[:80] + "..." if len(pattern.pattern) > 80 else pattern.pattern
                            st.write(f"  {i}. **{preview}** (Count: {pattern.count}, Source: {pattern.component})")
                    
                    # ============================================================
                    # Step 4a: Smart Rule-based Detection (skip when AI enabled)
                    # ============================================================
                    # Smart decision: Skip Layer 1 when AI enabled and Bedrock available
                    should_skip_layer1 = enable_ai and BedrockEnhancer(region=aws_region, model=bedrock_model).is_available()
                    
                    issues = []
                    solutions = []
                    
                    if should_skip_layer1:
                        st.write("⏭️ Skipping rule-based detection (AI enabled, will use comprehensive analysis)")
                    else:
                        st.write("🎯 Running rule-based detection...")
                        detector = RuleBasedDetector()
                        issues = detector.detect_issues(analysis)
                        solutions = detector.generate_basic_solutions(issues)
                        st.write(f"✅ Detected {len(issues)} rule-based issues")
                    
                    # ============================================================
                    # Step 4b: Cross-source Correlation (auto when 2+ sources)
                    # ============================================================
                    correlated_events = []
                    
                    if len(all_source_logs) >= 2:
                        st.write("🔗 Running cross-source correlation (Advanced)...")
                        
                        rules_path = os.path.join(os.path.dirname(__file__), 'correlation_rules.json')
                        correlator = AdvancedCorrelator(rules_config_path=rules_path)
                        
                        correlated_events = correlator.correlate_multi_source(
                            log_entries=all_parsed_entries,
                            clustered_patterns=analysis.error_patterns,
                            time_window_seconds=3600
                        )
                        
                        st.session_state.advanced_correlated_events = correlated_events
                        st.write(f"✅ Found {len(correlated_events)} correlated attack patterns")
                    else:
                        st.session_state.advanced_correlated_events = []
                    
                    # ============================================================
                    # Step 5: Build Unified Context (Event Abstraction Layer)
                    # ============================================================
                    st.write("⚡ Building unified context with event signals...")
                    
                    # Group entries by source for per-source analysis
                    per_source_entries = {}
                    for log_group, raw_logs in all_source_logs.items():
                        per_source_entries[log_group] = [
                            e for e in all_parsed_entries if e.component == log_group
                        ]
                    st.session_state.per_source_entries = per_source_entries
                    st.session_state.analysis_data = analysis
                    
                    time_range_str = f"{start_dt.strftime('%H:%M %d/%m')} to {end_dt.strftime('%H:%M %d/%m')}"
                    
                    unified_ctx = build_unified_context(
                        per_source_entries=per_source_entries,
                        analysis=analysis,
                        correlated_events=correlated_events,
                        time_range_str=time_range_str,
                    )
                    
                    st.write(
                        f"✅ Unified context ready — {len(unified_ctx.get('signals', []))} event signals, "
                        f"{len(unified_ctx.get('suspicious_ips', []))} suspicious IPs, "
                        f"{unified_ctx.get('correlation_count', 0)} correlated attacks"
                    )
                    
                    # ============================================================
                    # Step 6: Global RCA (1 AI call for full picture)
                    # ============================================================
                    ai_info = None
                    global_rca = None
                    
                    if enable_ai:
                        st.write("🤖 Running Global Root Cause Analysis (1 comprehensive AI call)...")
                        enhancer = BedrockEnhancer(region=aws_region, model=bedrock_model)
                        
                        if enhancer.is_available():
                            try:
                                global_rca, usage_stats = enhancer.generate_global_rca(unified_ctx)
                                st.session_state.global_rca = global_rca
                                
                                if usage_stats.get("error"):
                                    st.write(f"❌ {usage_stats['error']}")
                                    ai_info = AIInfo(ai_enhancement_used=False)
                                    
                                    # Fallback to Layer 1 if AI failed and we skipped it earlier
                                    if not issues:
                                        st.write("🔄 Falling back to rule-based detection...")
                                        detector = RuleBasedDetector()
                                        issues = detector.detect_issues(analysis)
                                        solutions = detector.generate_basic_solutions(issues)
                                        st.write(f"✅ Fallback complete: {len(issues)} issues detected")
                                else:
                                    ai_info = AIInfo(
                                        ai_enhancement_used=True,
                                        bedrock_model_used=usage_stats.get("bedrock_model_used"),
                                        total_tokens_used=usage_stats.get("total_tokens_used"),
                                        estimated_total_cost=usage_stats.get("estimated_total_cost"),
                                        api_calls_made=usage_stats.get("api_calls_made")
                                    )
                                    st.write(f"✅ Global RCA complete (Cost: ${ai_info.estimated_total_cost:.4f}, 1 API call)")
                            except Exception as e:
                                st.write(f"❌ AI analysis failed: {str(e)}")
                                ai_info = AIInfo(ai_enhancement_used=False)
                                
                                # Fallback to Layer 1 if AI failed and we skipped it earlier
                                if not issues:
                                    st.write("🔄 Falling back to rule-based detection...")
                                    detector = RuleBasedDetector()
                                    issues = detector.detect_issues(analysis)
                                    solutions = detector.generate_basic_solutions(issues)
                                    st.write(f"✅ Fallback complete: {len(issues)} issues detected")
                        else:
                            st.write("⚠️ AWS Bedrock not available")
                            ai_info = AIInfo(ai_enhancement_used=False)
                            
                            # Fallback to Layer 1 if Bedrock not available and we skipped it earlier
                            if not issues:
                                st.write("🔄 Falling back to rule-based detection...")
                                detector = RuleBasedDetector()
                                issues = detector.detect_issues(analysis)
                                solutions = detector.generate_basic_solutions(issues)
                                st.write(f"✅ Fallback complete: {len(issues)} issues detected")
                    else:
                        ai_info = AIInfo(ai_enhancement_used=False)
                    
                    # ============================================================
                    # Step 7: Create Results
                    # ============================================================
                    # Generate basic solutions for backward compat
                    metadata = Metadata(
                        timestamp=datetime.now().isoformat(),
                        search_term=effective_search or "Auto-scan (all logs)",
                        log_directory=', '.join(selected_log_groups),
                        total_files_searched=len(selected_log_groups),
                        total_matches=len(all_parsed_entries)
                    )
                    
                    results = AnalysisResult(
                        metadata=metadata,
                        matches=all_parsed_entries,
                        analysis=analysis,
                        solutions=solutions,
                        ai_info=ai_info
                    )
                    
                    st.session_state.analysis_result = results
                    st.write("✅ Analysis complete!")
                    
                    # ============================================================
                    # Step 8: Send Telegram Alert (if enabled and attack detected)
                    # ============================================================
                    # Send alert if we have Global RCA (regardless of correlation)
                    if global_rca:
                        st.write("📱 Sending Telegram alert...")
                        try:
                            notifier = TelegramNotifier()
                            
                            alert_metadata = {
                                "time_range": time_range_str,
                                "total_logs": len(all_parsed_entries),
                            }
                            alert_sent = notifier.send_attack_alert(
                                global_rca=global_rca.__dict__ if hasattr(global_rca, '__dict__') else global_rca,
                                correlated_events=correlated_events,  # Can be empty list
                                analysis_metadata=alert_metadata
                            )
                            if alert_sent:
                                st.write("✅ Telegram alert sent successfully!")
                            else:
                                st.write("⚠️ Telegram alert not sent (check configuration)")
                        except Exception as telegram_error:
                            st.code(traceback.format_exc())
                            
                    # Update status to complete and COLLAPSE it to save screen space
                    status.update(label="✅ Analysis complete!", state="complete", expanded=False)

            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                import traceback
                st.error(traceback.format_exc())
                status.update(label="❌ Analysis failed", state="error", expanded=True)
            finally:
                st.session_state.is_analyzing = False

# ============================================================
# RESULTS TABS
# ============================================================
has_correlation = bool(st.session_state.advanced_correlated_events)
has_global_rca = st.session_state.global_rca is not None

if has_correlation:
    tab1, tab2, tab3 = st.tabs(["📋 Global Report", "🔗 Correlation", "📊 Analysis & Deep Dive"])
else:
    tab1, tab2, tab3 = st.tabs(["📋 Global Report", "📊 Analysis & Deep Dive", "ℹ️ Info"])

if st.session_state.analysis_result is None:
    st.info("👈 Configure settings and click 'Analyze Logs' in the sidebar to see results")
else:
    result = st.session_state.analysis_result
    
    with tab1:
        st.subheader("Global Report")
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Logs", result.metadata.total_matches)
        with col2:
            st.metric("Sources", result.metadata.total_files_searched)
        with col3:
            if result.ai_info and result.ai_info.ai_enhancement_used:
                st.metric("AI Calls", f"{result.ai_info.api_calls_made or 1}")
            else:
                st.metric("AI", "Off")
        with col4:
            if result.ai_info and result.ai_info.estimated_total_cost:
                st.metric("Cost", f"${result.ai_info.estimated_total_cost:.4f}")
            else:
                st.metric("Cost", "$0.00")
        
        st.divider()
        
        # === GLOBAL RCA CONTENT ===
        global_rca = st.session_state.global_rca
        
        if global_rca and (global_rca.incident_story or global_rca.attack_narrative):
            # Check if system is healthy (no issues)
            threat_assessment = global_rca.threat_assessment or {}
            severity = threat_assessment.get('severity', '')
            
            if severity == 'None' or (global_rca.raw_ai_response and global_rca.raw_ai_response.get('status') == 'healthy'):
                # HEALTHY STATUS - No significant issues
                st.success("✅ System Health: NORMAL")
                st.info(global_rca.attack_narrative or "No significant security threats or operational issues detected.")
                
                if global_rca.raw_ai_response and global_rca.raw_ai_response.get('details'):
                    with st.expander("📋 Analysis Details"):
                        st.write(global_rca.raw_ai_response['details'])
                
                st.divider()
                st.markdown("**What was analyzed:**")
                st.write(f"- {result.metadata.total_matches} log entries from {result.metadata.total_files_searched} sources")
                st.write(f"- Time range: {result.metadata.search_term}")
                st.write(f"- No attacks, critical errors, or operational issues detected")
                
            else:
                # ISSUES DETECTED - Show full RCA
                # --- Incident Story (TL;DR) ---
                if global_rca.incident_story:
                    st.subheader("🚨 Incident Story (TL;DR)")
                    for step in global_rca.incident_story:
                        st.markdown(f"- {step}")
                    st.divider()
            
            # --- Threat Assessment ---
            if global_rca.threat_assessment:
                st.subheader("🎯 Threat Assessment")
                ta = global_rca.threat_assessment
                
                # Row 1: Severity, Confidence, Scope
                ta_col1, ta_col2 = st.columns(2)
                with ta_col1:
                    severity = ta.get('severity', 'Unknown')
                    sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                    st.metric("Severity", f"{sev_icon} {severity}")
                with ta_col2:
                    confidence = ta.get('confidence', 0)
                    conf_pct = f"{confidence * 100:.0f}%" if isinstance(confidence, float) else str(confidence)
                    st.metric("Confidence", conf_pct)
                
                # Row 2: Scope (full width for longer text)
                scope = ta.get('scope', 'N/A')
                if scope and scope != 'N/A':
                    st.markdown(f"**Scope:** {scope}")
                
                # Reasoning
                if ta.get('reasoning'):
                    st.info(f"**Reasoning:** {ta['reasoning']}")
                st.divider()
            
            # --- Attack Narrative ---
            if global_rca.attack_narrative:
                st.subheader("📖 Attack Narrative")
                st.warning(global_rca.attack_narrative)
                st.divider()
            
            # --- Affected Components ---
            if global_rca.affected_components:
                st.subheader("🏗️ Affected Components")
                for comp in global_rca.affected_components:
                    impact = comp.get('impact_level', 'Unknown')
                    impact_icon = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(impact, "⚪")
                    with st.expander(f"{impact_icon} {comp.get('component', '?')} — Impact: {impact}"):
                        st.write(f"**Evidence:** {comp.get('evidence', 'N/A')}")
                st.divider()
            
            # --- Root Cause ---
            if global_rca.root_cause:
                st.subheader("🔍 Root Cause")
                st.error(global_rca.root_cause)
                
                # Display 5 Why Analysis if available in raw_ai_response
                if global_rca.raw_ai_response and 'root_cause_analysis' in global_rca.raw_ai_response:
                    rca_data = global_rca.raw_ai_response['root_cause_analysis']
                    
                    with st.expander("📊 5 Why Analysis (Detailed)", expanded=True):
                        st.markdown("**Digging deeper to find the TRUE root cause:**")
                        
                        # Display each Why question with evidence
                        for i in range(1, 6):
                            why_key = f"why_{i}"
                            if why_key in rca_data:
                                why_item = rca_data[why_key]
                                question = why_item.get('question', f'Why #{i}?')
                                answer = why_item.get('answer', 'N/A')
                                evidence = why_item.get('evidence', '')
                                
                                # Color coding: deeper = more important
                                if i <= 2:
                                    st.info(f"**WHY #{i}:** {question}\n\n→ {answer}")
                                    if evidence:
                                        st.caption(f"📋 Evidence: {evidence}")
                                elif i <= 4:
                                    st.warning(f"**WHY #{i}:** {question}\n\n→ {answer}")
                                    if evidence:
                                        st.caption(f"📋 Evidence: {evidence}")
                                else:
                                    st.error(f"**WHY #{i}:** {question}\n\n→ ⭐ **ROOT CAUSE:** {answer}")
                                    if evidence:
                                        st.caption(f"📋 Evidence: {evidence}")
                        
                        # Root cause summary
                        if 'root_cause_summary' in rca_data:
                            st.divider()
                            st.success(f"**🎯 Root Cause Summary:** {rca_data['root_cause_summary']}")
                
                # Display Control Gaps if available
                if global_rca.raw_ai_response and 'control_gaps' in global_rca.raw_ai_response:
                    with st.expander("🔒 Control Gaps Identified", expanded=True):
                        st.markdown("**Security controls that are missing or insufficient:**")
                        
                        control_gaps = global_rca.raw_ai_response['control_gaps']
                        
                        # Critical gaps
                        if 'critical' in control_gaps and control_gaps['critical']:
                            st.markdown("### 🔴 Critical Gaps")
                            for gap in control_gaps['critical']:
                                st.error(f"**{gap.get('control', 'Unknown')}**")
                                st.write(f"- **Expected:** {gap.get('expected', 'N/A')}")
                                st.write(f"- **Actual:** {gap.get('actual', 'N/A')}")
                                st.write(f"- **Impact:** {gap.get('impact', 'N/A')}")
                                if gap.get('fix'):
                                    st.code(gap['fix'], language='bash')
                        
                        # Medium gaps
                        if 'medium' in control_gaps and control_gaps['medium']:
                            st.markdown("### 🟡 Medium Gaps")
                            for gap in control_gaps['medium']:
                                st.warning(f"**{gap.get('control', 'Unknown')}**")
                                st.write(f"- **Expected:** {gap.get('expected', 'N/A')}")
                                st.write(f"- **Actual:** {gap.get('actual', 'N/A')}")
                                st.write(f"- **Impact:** {gap.get('impact', 'N/A')}")
                        
                        # Low gaps
                        if 'low' in control_gaps and control_gaps['low']:
                            st.markdown("### 🟢 Low Priority Gaps")
                            for gap in control_gaps['low']:
                                st.info(f"**{gap.get('control', 'Unknown')}** - {gap.get('expected', 'N/A')}")
                
                st.divider()
            
            # --- MITRE Mapping ---
            if global_rca.mitre_mapping:
                st.subheader("🗺️ MITRE ATT&CK Mapping")
                mitre_col1, mitre_col2 = st.columns(2)
                with mitre_col1:
                    st.markdown("**Tactics:**")
                    for t in global_rca.mitre_mapping.get('tactics', []):
                        st.markdown(f"- {t}")
                with mitre_col2:
                    st.markdown("**Techniques:**")
                    for t in global_rca.mitre_mapping.get('techniques', []):
                        st.markdown(f"- {t}")
                st.divider()
            
            # --- Immediate Actions ---
            if global_rca.immediate_actions:
                st.subheader("🔥 Immediate Actions")
                for action in global_rca.immediate_actions:
                    priority = action.get('priority', 'P2')
                    st.warning(f"**[{priority}]** {action.get('action', 'N/A')}")
                    if action.get('command'):
                        st.code(action['command'], language='bash')
                st.divider()
        else:
            # Fallback if no Global RCA
            st.info("Global RCA not available. Enable AI Enhancement and re-run analysis.")
            
            # Show basic component summary
            st.subheader("🎯 Component Error Summary")
            if result.analysis.components:
                total_errors = sum(result.analysis.components.values())
                table_data = []
                for comp, count in result.analysis.components.items():
                    ratio = f"{(count / total_errors) * 100:.1f}%" if total_errors > 0 else "0%"
                    table_data.append({"Component": comp, "Errors": count, "Ratio": ratio})
                st.dataframe(table_data, use_container_width=True, hide_index=True)
        
        st.divider()
        
        # Export
        st.subheader("📥 Export")
        json_str = result.to_json()
        st.download_button(
            label="📄 Download JSON",
            data=json_str,
            file_name=f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

    # Correlation Tab (auto when correlation data exists)
    if has_correlation:
        with tab2:
            st.subheader("🔗 Advanced Correlation Results")
            
            if not st.session_state.advanced_correlated_events:
                st.info("No correlated events found. Try adjusting time range or log sources.")
            else:
                st.success(f"Found {len(st.session_state.advanced_correlated_events)} correlated attack patterns")
                
                for i, event in enumerate(st.session_state.advanced_correlated_events, 1):
                    with st.expander(f"🚨 {i}. {event.attack_name} (Confidence: {event.confidence_score:.1f}%)", expanded=(i <= 3)):
                        # Header metrics
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Confidence", f"{event.confidence_score:.1f}%")
                        with col2:
                            st.metric("Severity", event.severity)
                        with col3:
                            st.metric("Sources", len(event.sources))
                        with col4:
                            st.metric("Events", len(event.timeline))
                        
                        st.divider()
                        
                        # Correlation keys
                        st.markdown("**Correlation Keys:**")
                        for key, value in event.correlation_keys.items():
                            if value:
                                st.write(f"- **{key}:** {value}")
                        
                        # Timeline
                        st.markdown("**Attack Timeline:**")
                        for j, timeline_event in enumerate(event.timeline, 1):
                            # Calculate delay from previous event
                            if j > 1:
                                delay = (timeline_event.timestamp - event.timeline[j-2].timestamp).total_seconds()
                                delay_info = f" (+{delay:.1f}s)"
                            else:
                                delay_info = ""
                            ts_str = timeline_event.timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(timeline_event.timestamp, 'strftime') else str(timeline_event.timestamp)
                            msg = (timeline_event.message or '')[:100]
                            st.write(f"{j}. [{ts_str}] **{timeline_event.source}**: {msg}...{delay_info}")
                        
                        # Matched rules
                        if event.matched_rules:
                            st.markdown("**Matched Detection Rules:**")
                            for rule in event.matched_rules:
                                st.write(f"- {rule}")
                        
                        # AI Recommendation
                        st.markdown("**AI Recommendation:**")
                        st.info(event.ai_recommendation)
                        
                        # Evidence
                        if event.evidence:
                            st.markdown("**Evidence:**")
                            for ev_item in event.evidence[:5]:
                                st.code(ev_item, language='text')
    
    # Analysis & Deep Dive tab
    analysis_tab = tab3 if has_correlation else tab2
    
    with analysis_tab:
        st.subheader("Analysis & Deep Dive")
        
        # Severity & Component charts
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Severity Distribution**")
            severity_data = result.analysis.severity_distribution
            if severity_data:
                st.bar_chart(severity_data)
        with col2:
            st.markdown("**Component Distribution**")
            component_data = result.analysis.components
            if component_data:
                st.bar_chart(component_data)
        
        st.divider()
        
        # Error patterns
        st.subheader("🔴 Error Patterns")
        if result.analysis.error_patterns:
            for i, pattern in enumerate(result.analysis.error_patterns[:10], 1):
                with st.expander(f"{i}. {pattern.pattern[:60]}... (Count: {pattern.count})"):
                    st.write(f"**Component:** {pattern.component}")
                    st.write(f"**Count:** {pattern.count}")
                    st.write(f"**Pattern:** {pattern.pattern}")
        else:
            st.info("No error patterns found")
        
        st.divider()
        
        # === DEEP DIVE SECTION ===
        st.subheader("🔬 Deep Dive (Per-Source Analysis)")
        st.caption("Click a button to run a focused AI analysis on a single log group, enriched with Global RCA context.")
        
        per_source = st.session_state.per_source_entries
        
        if per_source:
            for log_group, entries in per_source.items():
                sev_counts = {}
                for e in entries:
                    s = (e.severity or 'UNKNOWN').upper()
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                error_count = sev_counts.get('ERROR', 0) + sev_counts.get('CRITICAL', 0)
                
                with st.expander(f"📂 {log_group} ({len(entries)} entries, {error_count} errors)"):
                    # Metrics row
                    m1, m2, m3 = st.columns(3)
                    with m1:
                        st.metric("Entries", len(entries))
                    with m2:
                        st.metric("Errors", error_count)
                    with m3:
                        rate = f"{(error_count / len(entries) * 100):.1f}%" if entries else "0%"
                        st.metric("Error Rate", rate)
                    
                    # Deep Dive button
                    btn_key = f"deep_dive_{log_group}"
                    if st.button(f"🔬 Deep Dive into {log_group.split('/')[-1]}", key=btn_key):
                        with st.spinner(f"Running Deep Dive on {log_group}..."):
                            # Build global RCA summary for context injection
                            global_rca = st.session_state.global_rca
                            rca_summary = ""
                            if global_rca and global_rca.attack_narrative:
                                rca_summary = (
                                    f"Attack: {global_rca.attack_narrative}\n"
                                    f"Root Cause: {global_rca.root_cause}\n"
                                    f"Severity: {global_rca.threat_assessment.get('severity', 'N/A')}"
                                )
                            
                            dd_ctx = build_deep_dive_context(
                                log_group=log_group,
                                entries=entries,
                                analysis=st.session_state.analysis_data,
                                global_rca_summary=rca_summary,
                            )
                            
                            enhancer = BedrockEnhancer(region=aws_region, model=bedrock_model)
                            dd_result, dd_stats = enhancer.generate_deep_dive(dd_ctx)
                            st.session_state.deep_dive_results[log_group] = dd_result
                    
                    # Show Deep Dive results if available
                    dd = st.session_state.deep_dive_results.get(log_group)
                    if dd and dd.component_summary:
                        st.markdown("---")
                        st.markdown(f'<span class="ai-badge">✨ AI Deep Dive</span>', unsafe_allow_html=True)
                        
                        st.markdown(f"**Summary:** {dd.component_summary}")
                        
                        if dd.specific_findings:
                            st.markdown("**Findings:**")
                            for finding in dd.specific_findings:
                                sev = finding.get('severity', 'Medium')
                                sev_icon = {"High": "🔴", "Medium": "🟡", "Low": "🟢", "Critical": "🔴"}.get(sev, "⚪")
                                st.markdown(f"- {sev_icon} **{finding.get('finding', 'N/A')}**")
                                if finding.get('evidence'):
                                    st.caption(f"  Evidence: {finding['evidence']}")
                        
                        if dd.recommendations:
                            st.markdown("**Recommendations:**")
                            for rec in dd.recommendations:
                                st.markdown(f"- {rec}")
                        
                        if dd.tokens_used:
                            st.caption(f"Tokens: {dd.tokens_used} | Cost: ${dd.cost:.4f}")


# ============================================================
# INCIDENT DASHBOARD RENDERING
# ============================================================

def _render_incident_dashboard():
    """Render the Incident Dashboard — reads auto-generated results from disk."""
    store = IncidentStore()
    stats = store.get_summary_stats()

    # --- Dashboard Tabs ---
    dash_tab1, dash_tab2, dash_tab3 = st.tabs([
        "🔴 Live Incidents",
        "📊 Timeline",
        "⚙️ System Status",
    ])

    # ========================
    # TAB 1: Live Incidents
    # ========================
    with dash_tab1:
        st.subheader("🔴 Live Incidents")
        st.caption("Kết quả từ auto-analyzer pipeline (chạy mỗi 5 phút)")

        # Auto-refresh
        auto_refresh = st.checkbox("Auto-refresh (30s)", value=False)
        if auto_refresh:
            import time
            st.empty()
            time.sleep(0.1)  # Prevent immediate re-render
            st.rerun()  # Streamlit >= 1.27

        # Summary row
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Today Incidents", stats.get("today_incidents", 0))
        with col2:
            st.metric("Today Batches", stats.get("today_batches", 0))
        with col3:
            st.metric("Total Incidents", stats.get("incident_count", 0))
        with col4:
            st.metric("Total Cost", f"${stats.get('total_cost_usd', 0):.4f}")

        st.divider()

        # List incidents
        incidents = store.list_incidents(last_n=30, status_filter="incident")

        if not incidents:
            st.info("✅ Không có incident nào. Hệ thống đang hoạt động bình thường.")
            st.caption("Auto-analyzer chạy mỗi 5 phút. Nếu phát hiện anomaly, incident sẽ hiển thị tại đây.")
        else:
            for i, inc in enumerate(incidents):
                severity = inc.get("severity", "Unknown")
                sev_icon = {
                    "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"
                }.get(severity, "⚪")

                batch_id = inc.get("batch_id", "?")
                attack = inc.get("attack_narrative", "No narrative")
                sources = inc.get("sources_analyzed", [])
                corr_count = inc.get("correlated_events_count", 0)
                signals_count = inc.get("signals_count", 0)
                tg = "✅ Sent" if inc.get("telegram_sent") else "—"

                with st.expander(
                    f"{sev_icon} [{batch_id}] {severity} — {attack[:80]}",
                    expanded=(i == 0),
                ):
                    # Metrics
                    mc1, mc2, mc3, mc4 = st.columns(4)
                    with mc1:
                        st.metric("Logs Analyzed", inc.get("total_logs_analyzed", 0))
                    with mc2:
                        st.metric("Signals", signals_count)
                    with mc3:
                        st.metric("Correlations", corr_count)
                    with mc4:
                        st.metric("Telegram", tg)

                    # Root cause
                    root_cause = inc.get("root_cause", "")
                    if root_cause:
                        st.error(f"**Root Cause:** {root_cause}")

                    # Sources
                    if sources:
                        st.markdown(f"**Sources:** {', '.join(s.split('/')[-1] for s in sources)}")

                    # Full details button
                    if st.button(f"📄 View Full Report", key=f"view_{i}"):
                        full_data = store.load_incident(inc["filepath"])
                        if full_data:
                            _render_full_incident(full_data)

    # ========================
    # TAB 2: Timeline
    # ========================
    with dash_tab2:
        st.subheader("📊 Batch Timeline")
        st.caption("Lịch sử tất cả các batch (incidents + clean)")

        all_batches = store.list_incidents(last_n=100)

        if not all_batches:
            st.info("Chưa có dữ liệu batch nào. Auto-analyzer sẽ bắt đầu tạo dữ liệu sau khi deploy.")
        else:
            # Timeline table
            table_data = []
            for batch in all_batches:
                status = batch.get("status", "unknown")
                status_icon = "🔴" if status == "incident" else "🟢"
                table_data.append({
                    "Status": f"{status_icon} {status}",
                    "Batch ID": batch.get("batch_id", "?"),
                    "Logs": batch.get("total_logs_analyzed", 0),
                    "Signals": batch.get("signals_count", 0),
                    "Correlations": batch.get("correlated_events_count", 0),
                    "Severity": batch.get("severity", "N/A"),
                    "Telegram": "✅" if batch.get("telegram_sent") else "—",
                    "Cost": f"${batch.get('cost', {}).get('usd', 0):.4f}",
                })

            st.dataframe(table_data, use_container_width=True, hide_index=True)

            # Stats
            st.divider()
            incident_batches = [b for b in all_batches if b.get("status") == "incident"]
            clean_batches = [b for b in all_batches if b.get("status") == "clean"]
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Batches", len(all_batches))
            with col2:
                st.metric("Incidents", len(incident_batches))
            with col3:
                pct = (len(incident_batches) / len(all_batches) * 100) if all_batches else 0
                st.metric("Incident Rate", f"{pct:.1f}%")

    # ========================
    # TAB 3: System Status
    # ========================
    with dash_tab3:
        st.subheader("⚙️ System Status")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Pipeline Status")
            last_batch = stats.get("last_batch")
            if last_batch:
                st.success(f"✅ Last batch: {last_batch.get('batch_id', '?')}")
                st.write(f"Status: **{last_batch.get('status', '?').upper()}**")
                st.write(f"Logs analyzed: **{last_batch.get('total_logs_analyzed', 0)}**")
            else:
                st.warning("⚠️ No batch data yet — waiting for first cron run")

            st.divider()
            st.markdown("### Configuration")
            st.write(f"Interval: **{os.getenv('AUTO_ANALYSIS_INTERVAL_MINUTES', '5')} minutes**")
            st.write(f"Retention: **{os.getenv('INCIDENT_RETENTION_DAYS', '7')} days**")
            st.write(f"Bedrock Model: **{os.getenv('AUTO_BEDROCK_MODEL', 'N/A')}**")
            st.write(f"Data Directory: `{os.getenv('INCIDENT_DATA_DIR', '/data/incidents')}`")

        with col2:
            st.markdown("### Cumulative Stats")
            st.metric("Total Batches", stats.get("total_batches", 0))
            st.metric("Incidents Detected", stats.get("incident_count", 0))
            st.metric("Clean Batches", stats.get("clean_count", 0))
            st.metric("Telegram Alerts Sent", stats.get("telegram_alerts_sent", 0))
            st.metric("Total Cost", f"${stats.get('total_cost_usd', 0):.4f}")
            st.metric("Total Logs Analyzed", f"{stats.get('total_logs_analyzed', 0):,}")

        st.divider()
        st.markdown("### Log Groups Monitored")
        log_groups = os.getenv("AUTO_ANALYSIS_LOG_GROUPS", "").split(",")
        for lg in log_groups:
            if lg.strip():
                st.write(f"  📂 `{lg.strip()}`")


def _render_full_incident(data: dict):
    """Render full incident details from stored JSON."""
    st.divider()
    st.subheader(f"📄 Full Report — {data.get('batch_id', '?')}")

    # Global RCA
    rca = data.get("global_rca")
    if rca:
        # Incident Story
        if rca.get("incident_story"):
            st.markdown("### 🚨 Incident Story")
            for step in rca["incident_story"]:
                st.markdown(f"- {step}")

        # Threat Assessment
        ta = rca.get("threat_assessment", {})
        if ta:
            st.markdown("### 🎯 Threat Assessment")
            tc1, tc2 = st.columns(2)
            with tc1:
                sev = ta.get("severity", "Unknown")
                sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sev, "⚪")
                st.metric("Severity", f"{sev_icon} {sev}")
            with tc2:
                conf = ta.get("confidence", 0)
                st.metric("Confidence", f"{conf * 100:.0f}%" if isinstance(conf, float) else str(conf))
            if ta.get("reasoning"):
                st.info(ta["reasoning"])

        # Attack Narrative
        if rca.get("attack_narrative"):
            st.markdown("### 📖 Attack Narrative")
            st.warning(rca["attack_narrative"])

        # Root Cause
        if rca.get("root_cause"):
            st.markdown("### 🔍 Root Cause")
            st.error(rca["root_cause"])

        # 5 Why Analysis
        rca_analysis = rca.get("raw_ai_response", {}).get("root_cause_analysis", {})
        if rca_analysis:
            with st.expander("📊 5 Why Analysis", expanded=True):
                for i in range(1, 6):
                    why_key = f"why_{i}"
                    if why_key in rca_analysis:
                        why_item = rca_analysis[why_key]
                        q = why_item.get("question", f"Why #{i}?")
                        a = why_item.get("answer", "N/A")
                        ev = why_item.get("evidence", "")
                        if i <= 2:
                            st.info(f"**WHY #{i}:** {q}\n\n→ {a}")
                        elif i <= 4:
                            st.warning(f"**WHY #{i}:** {q}\n\n→ {a}")
                        else:
                            st.error(f"**WHY #{i}:** {q}\n\n→ ⭐ {a}")
                        if ev:
                            st.caption(f"📋 Evidence: {ev}")

        # Immediate Actions
        if rca.get("immediate_actions"):
            st.markdown("### 🔥 Immediate Actions")
            for action in rca["immediate_actions"]:
                priority = action.get("priority", "P2")
                st.warning(f"**[{priority}]** {action.get('action', 'N/A')}")
                if action.get("command"):
                    st.code(action["command"], language="bash")

    # Correlated Events
    corr = data.get("correlated_events", [])
    if corr:
        st.markdown("### 🔗 Correlated Attacks")
        for ev in corr:
            st.markdown(
                f"- **{ev.get('attack_name', '?')}** "
                f"(Confidence: {ev.get('confidence', 0):.1f}%, "
                f"Severity: {ev.get('severity', '?')}, "
                f"Sources: {', '.join(ev.get('sources', []))})"
            )

    # Signals
    signals = data.get("signals", [])
    if signals:
        with st.expander(f"⚡ Event Signals ({len(signals)})"):
            for sig in signals[:20]:
                st.write(
                    f"- [{sig.get('severity', '?')}] {sig.get('event_type', '?')} "
                    f"(source: {sig.get('source', '?')}, count: {sig.get('count', 0)})"
                )


# ============================================================
# INCIDENT DASHBOARD MODE (called after functions are defined)
# ============================================================
if page_mode == "🔴 Incident Dashboard":
    _render_incident_dashboard()
