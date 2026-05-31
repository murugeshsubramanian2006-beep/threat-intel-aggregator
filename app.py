import streamlit as st
import pandas as pd
import plotly.express as px
from modules.database import init_db, save_iocs, load_iocs, clear_iocs
from modules.parser import parse_iocs
from modules.normalizer import normalize_iocs
from modules.validator import validate_iocs
from modules.correlator import correlate_iocs
from modules.fetcher import fetch_feed
from modules.logger import (
    log_info,
    log_warning,
    log_error
)

# ---------------- DATABASE INIT ----------------

init_db()

# ---------------- PAGE CONFIG ----------------

st.set_page_config(
    page_title="Threat Intelligence Aggregator",
    layout="wide"
)

# ---------------- SESSION STATE ----------------

if "data_lines" not in st.session_state:
    st.session_state.data_lines = []

# ---------------- CUSTOM CSS ----------------

st.markdown("""
<style>

html, body, [class*="css"] {
    background-color: #050816;
    color: white;
}

.main {
    background-color: #050816;
}

h1, h2, h3 {
    color: white;
}

section[data-testid="stSidebar"] {
    background-color: #081229;
}

.stButton>button {
    background: linear-gradient(90deg,#00c6ff,#0072ff);
    color: white;
    border-radius: 10px;
    border: none;
    padding: 0.6rem 1rem;
    font-weight: bold;
}

.stButton>button:hover {
    box-shadow: 0px 0px 15px #00c6ff;
}

</style>
""", unsafe_allow_html=True)

# ---------------- TITLE ----------------

st.title("Threat Intelligence Aggregator")

st.markdown("""
Analyze cyber threat feeds, correlate Indicators of Compromise (IOCs),
generate intelligence, and visualize cyber risk.
""")

# ---------------- SIDEBAR ----------------

st.sidebar.title("Input Options")

mode = st.sidebar.radio(
    "Select Input Mode",
    ["Upload File", "Fetch from URL"]
)

# ---------------- FILE MODE ----------------

if mode == "Upload File":

    uploaded_file = st.sidebar.file_uploader(
        "Upload Threat Feed",
        type=["txt"]
    )

    if uploaded_file:

        content = uploaded_file.read().decode("utf-8")
        st.session_state.data_lines = content.splitlines()

        log_info(
            f"Feed uploaded with {len(st.session_state.data_lines)} lines"
        )

# ---------------- URL MODE ----------------

elif mode == "Fetch from URL":

    feed_options = {
        "Emerging Threats IP Feed":
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",

        "OpenPhish Feed":
            "https://openphish.com/feed.txt"
    }

    selected_feed = st.sidebar.selectbox(
        "Select Threat Feed",
        list(feed_options.keys())
    )

    if st.sidebar.button("Fetch Feed"):

        url = feed_options[selected_feed]

        with st.spinner("Fetching live threat intelligence..."):
            st.session_state.data_lines = fetch_feed(url)

        log_info(
            f"Feed fetched successfully: {selected_feed}"
        )

        st.sidebar.success("Threat feed fetched successfully")

# ---------------- PROCESS ----------------

if st.session_state.data_lines:

    if st.button("Process Threat Feed"):

        temp_file = "temp_feed.txt"

        with open(temp_file, "w") as f:
            for line in st.session_state.data_lines:
                f.write(line + "\n")

        # Parse
        iocs = parse_iocs(temp_file)

        total_parsed = sum(len(v) for v in iocs.values())

        log_info(
            f"Parsed {total_parsed} indicators"
        )

        # Validate
        validated_iocs, invalid_count = validate_iocs(iocs)

        if invalid_count > 0:
            log_warning(
                f"Removed {invalid_count} invalid indicators"
            )
        else:
            log_info(
                "Validation completed successfully"
            )

        # Normalize
        normalized = normalize_iocs(validated_iocs)

        # Correlate
        correlated = correlate_iocs(normalized)

        log_info(
            f"Correlated {len(correlated)} indicators"
        )

        # Save
        save_iocs(correlated)

        log_info(
            f"Stored {len(correlated)} indicators in database"
        )

        # Summary
        total = len(correlated)

        high = sum(
            1 for x in correlated
            if x["severity"] == "HIGH"
        )

        medium = sum(
            1 for x in correlated
            if x["severity"] == "MEDIUM"
        )

        low = sum(
            1 for x in correlated
            if x["severity"] == "LOW"
        )

        # Metrics
        st.markdown("## Threat Overview")

        st.info(
            f"Validation Engine Removed {invalid_count} malformed indicators."
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total IOCs", total)
        col2.metric("High Risk", high)
        col3.metric("Medium Risk", medium)
        col4.metric("Low Risk", low)

        st.divider()

        # Analytics
        st.markdown("## Threat Analytics")

        chart_col1, chart_col2 = st.columns(2)

        severity_df = pd.DataFrame({
            "Severity": ["HIGH", "MEDIUM", "LOW"],
            "Count": [high, medium, low]
        })

        fig1 = px.pie(
            severity_df,
            names="Severity",
            values="Count",
            title="Threat Severity Distribution",
            hole=0.55
        )

        fig1.update_layout(
            paper_bgcolor="#050816",
            plot_bgcolor="#050816",
            font_color="white"
        )

        chart_col1.plotly_chart(
            fig1,
            use_container_width=True
        )

        category_df = pd.DataFrame({
            "Category": list(validated_iocs.keys()),
            "Count": [len(v) for v in validated_iocs.values()]
        })

        fig2 = px.bar(
            category_df,
            x="Category",
            y="Count",
            title="IOC Category Analysis",
            text_auto=True
        )

        fig2.update_layout(
            paper_bgcolor="#050816",
            plot_bgcolor="#050816",
            font_color="white"
        )

        chart_col2.plotly_chart(
            fig2,
            use_container_width=True
        )

        st.divider()

        # IOC Breakdown
        st.markdown("## IOC Breakdown")

        break1, break2 = st.columns(2)

        break1.metric("Total IPs", len(iocs["ips"]))
        break1.metric("Total Domains", len(iocs["domains"]))

        break2.metric("Total URLs", len(iocs["urls"]))
        break2.metric("Total Hashes", len(iocs["hashes"]))

        st.divider()

        # Top IOC Table
        st.markdown("## Top Threat Indicators")

        ioc_df = pd.DataFrame(correlated)

        if not ioc_df.empty:

            ioc_df = ioc_df.sort_values(
                by="count",
                ascending=False
            )

            st.dataframe(
                ioc_df,
                use_container_width=True
            )

        st.divider()

        # Parsed IOCs
        st.markdown("## Parsed IOCs")

        for key, values in iocs.items():

            with st.expander(f"{key.upper()} ({len(values)})"):

                for v in values:
                    st.code(v)

        st.divider()

        # Normalized Intelligence
        st.markdown("## Normalized Intelligence")

        for category, items in normalized.items():

            with st.expander(
                f"{category.upper()} Intelligence"
            ):

                for item in items:
                    st.json(item)

        st.divider()

        # Correlation Results
        st.markdown("## Correlation Results")

        corr_df = pd.DataFrame(correlated)

        search_term = st.text_input(
            "Search IOC"
        )

        if search_term:

            corr_df = corr_df[
                corr_df["ioc"].str.contains(
                    search_term,
                    case=False,
                    na=False
                )
            ]

        severity_filter = st.selectbox(
            "Filter Severity",
            ["ALL", "HIGH", "MEDIUM", "LOW"]
        )

        if severity_filter != "ALL":

            corr_df = corr_df[
                corr_df["severity"] == severity_filter
            ]

        st.dataframe(
            corr_df,
            use_container_width=True,
            height=450
        )

        st.divider()

        # Footer
        st.markdown("""
        <div style='text-align:center; padding:20px; color:gray;'>
        Threat Intelligence Aggregator | Cybersecurity Analytics Dashboard
        </div>
        """, unsafe_allow_html=True)

else:

    st.info(
        "Upload a threat feed or fetch live threat data from URL."
    )
# ---------------- DATABASE HISTORY ----------------

st.markdown("---")
st.subheader("Stored Threat Intelligence")

if st.button("Clear Stored Threat Data"):

    clear_iocs()

    log_warning(
        "Threat intelligence database cleared"
    )

    st.success(
        "Stored threat intelligence cleared successfully."
    )

    st.rerun()

stored_data = load_iocs()

if stored_data:

    st.write(
        f"Total Stored Records: {len(stored_data)}"
    )

    for row in stored_data[:20]:

        st.code(
            f"""
IOC: {row[1]}
Type: {row[2]}
Source: {row[3]}
Timestamp: {row[4]}
Severity: {row[5]}
            """
        )

else:

    st.info(
        "No IOC history stored yet."
    )