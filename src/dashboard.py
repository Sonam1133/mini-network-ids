
import json
import time
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
ALERT_FILE = ROOT / "logs" / "alerts.json"

st.set_page_config(
    page_title="Mini Network IDS | SOC Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Mini Network IDS")
st.caption("Security Operations Center | Network Threat Monitoring")


@st.fragment(run_every="5s")
def show_dashboard():
    st.caption(
        f"Last dashboard update: {time.strftime('%H:%M:%S')} "
        "| Auto-refresh: every 5 seconds"
    )

    # Read live alerts, or use an empty list if no report exists.
    if not ALERT_FILE.exists():
        alerts = []
    else:
        try:
            with ALERT_FILE.open("r", encoding="utf-8") as file:
                alerts = json.load(file)
        except (json.JSONDecodeError, OSError) as error:
            st.error(f"Unable to read alert report: {error}")
            return

    if not isinstance(alerts, list):
        st.error("Invalid alert report format.")
        return

    df = pd.DataFrame(alerts)

    total_alerts = len(df)
    unique_sources = (
        df["source_ip"].nunique()
        if not df.empty and "source_ip" in df.columns
        else 0
    )
    high_alerts = (
        int((df["severity"] == "HIGH").sum())
        if not df.empty and "severity" in df.columns
        else 0
    )

    st.subheader("Security Overview")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Alerts", total_alerts)
    c2.metric("Unique Source IPs", unique_sources)
    c3.metric("High-Severity Alerts", high_alerts)

    st.divider()
    st.subheader("Detected Security Events")

    if df.empty:
        st.info("No live alerts detected yet.")
        return

    columns = [
        "timestamp",
        "severity",
        "alert_type",
        "source_ip",
        "destination_ip",
        "unique_ports",
        "destination_port",
        "attempts_in_window",
        "window_seconds",
    ]
    visible = [column for column in columns if column in df.columns]

    st.dataframe(
        df[visible],
        width="stretch",
        hide_index=True,
    )

    left, right = st.columns(2)

    with left:
        st.subheader("Alerts by Severity")
        if "severity" in df.columns:
            st.bar_chart(df["severity"].value_counts(), height=260)

    with right:
        st.subheader("Alerts by Source IP")
        if "source_ip" in df.columns:
            st.bar_chart(df["source_ip"].value_counts(), height=260)

    st.divider()
    st.subheader("Investigation Details")

    for index, alert in enumerate(alerts, start=1):
        with st.expander(
            f"Alert {index}: {alert.get('alert_type', 'Unknown event')}"
        ):
            st.json(alert)


show_dashboard()

st.caption(
    "Source: logs/alerts.json (live alerts). "
    "Simulated test results are stored separately in logs/test_alerts.json."
)
