import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from modules.database import init_db, save_iocs, load_iocs, clear_iocs


init_db()
from modules.parser import parse_iocs
from modules.normalizer import normalize_iocs
from modules.correlator import correlate_iocs
from modules.fetcher import fetch_feed

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

        st.sidebar.success("Threat feed fetched successfully")

# ---------------- PROCESS ----------------

if st.session_state.data_lines:

    if st.button("Process Threat Feed"):

        temp_file = "temp_feed.txt"

        with open(temp_file, "w") as f:

            for line in st.session_state.data_lines:
                f.write(line + "\n")

        # ---------------- PARSE ----------------

        iocs = parse_iocs(temp_file)

        # ---------------- NORMALIZE ----------------

        normalized = normalize_iocs(iocs)

        # ---------------- CORRELATION ----------------

        correlated = correlate_iocs(normalized)
        save_iocs(correlated)

        # ---------------- SUMMARY ----------------

        total = len(correlated)

        high = sum(
            1 for x in correlated if x["severity"] == "HIGH"
        )

        medium = sum(
            1 for x in correlated if x["severity"] == "MEDIUM"
        )

        low = sum(
            1 for x in correlated if x["severity"] == "LOW"
        )

        # ---------------- METRICS ----------------

        st.markdown("## Threat Overview")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total IOCs", total)
        col2.metric("High Risk", high)
        col3.metric("Medium Risk", medium)
        col4.metric("Low Risk", low)

        st.divider()

        # ---------------- ANALYTICS ----------------

        st.markdown("## Threat Analytics")

        chart_col1, chart_col2 = st.columns(2)

        # ---------------- PIE CHART ----------------

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

        # ---------------- BAR CHART ----------------

        category_df = pd.DataFrame({
            "Category": list(iocs.keys()),
            "Count": [len(v) for v in iocs.values()]
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

        # ---------------- IOC BREAKDOWN ----------------

        st.markdown("## IOC Breakdown")

        break1, break2 = st.columns(2)

        break1.metric("Total IPs", len(iocs["ips"]))
        break1.metric("Total Domains", len(iocs["domains"]))

        break2.metric("Total URLs", len(iocs["urls"]))
        break2.metric("Total Hashes", len(iocs["hashes"]))

        st.divider()

        # ---------------- TOP IOC TABLE ----------------

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

        # ---------------- PARSED IOCS ----------------

        st.markdown("## Parsed IOCs")

        for key, values in iocs.items():

            with st.expander(f"{key.upper()} ({len(values)})"):

                for v in values:
                    st.code(v)

        st.divider()

        # ---------------- NORMALIZED ----------------

        st.markdown("## Normalized Intelligence")

        for category, items in normalized.items():

            with st.expander(f"{category.upper()} Intelligence"):

                for item in items:
                    st.json(item)

        st.divider()

        # ---------------- CORRELATION ----------------

        st.markdown("## Correlation Results")

        for item in correlated:

            severity = item["severity"]

            if severity == "HIGH":

                st.error(
                    f"{item['ioc']} -> Count: {item['count']} | Severity: {severity}"
                )

            elif severity == "MEDIUM":

                st.warning(
                    f"{item['ioc']} -> Count: {item['count']} | Severity: {severity}"
                )

            else:

                st.success(
                    f"{item['ioc']} -> Count: {item['count']} | Severity: {severity}"
                )

        st.divider()

        # ---------------- FOOTER ----------------

        st.markdown("""
        <div style='text-align:center; padding:20px; color:gray;'>

        Threat Intelligence Aggregator | Cybersecurity Analytics Dashboard

        </div>
        """, unsafe_allow_html=True)

# ---------------- EMPTY STATE ----------------

else:

    st.info("Upload a threat feed or fetch live threat data from URL.")

# ---------------- DATABASE HISTORY ----------------

st.markdown("---")
st.subheader("Stored Threat Intelligence")
if st.button("Clear Stored Threat Data"):
    
    clear_iocs()

    st.success("Stored threat intelligence cleared successfully.")

    st.rerun()

stored_data = load_iocs()

if stored_data:

    st.write(f"Total Stored Records: {len(stored_data)}")

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
    st.info("No IOC history stored yet.")


    
    