"""When Severity Does Not Equal Risk: minimal threshold explorer.

Run from the repo root:  streamlit run dashboard/app.py
"""
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

DATA = Path(__file__).parent / "data"

CWE_NAMES = {
    "CWE-20": "Improper input validation", "CWE-22": "Path traversal", "CWE-77": "Command injection",
    "CWE-78": "OS command injection", "CWE-79": "Cross-site scripting", "CWE-89": "SQL injection",
    "CWE-94": "Code injection", "CWE-119": "Memory buffer bounds error", "CWE-125": "Out-of-bounds read",
    "CWE-190": "Integer overflow", "CWE-200": "Information exposure", "CWE-269": "Improper privilege management",
    "CWE-284": "Improper access control", "CWE-287": "Improper authentication", "CWE-306": "Missing authentication",
    "CWE-352": "CSRF", "CWE-416": "Use after free", "CWE-434": "Unrestricted file upload",
    "CWE-502": "Deserialization of untrusted data", "CWE-787": "Out-of-bounds write",
    "CWE-843": "Type confusion", "CWE-862": "Missing authorization", "CWE-863": "Incorrect authorization",
    "CWE-918": "SSRF", "CWE-59": "Link following", "CWE-121": "Stack-based buffer overflow",
    "CWE-122": "Heap-based buffer overflow", "CWE-288": "Authentication bypass via alternate path",
    "CWE-693": "Protection mechanism failure",
}


@st.cache_data
def load_data():
    kev = pd.read_csv(DATA / "dashboard_kev.csv")
    nonkev = pd.read_csv(DATA / "dashboard_nonkev_by_threshold.csv")
    return kev, nonkev


def epss_summary(x):
    return pd.Series({
        "KEVs": len(x),
        "Median EPSS percentile": round(x["epss_percentile"].median(), 3),
        "% in EPSS top 10%": round((x["epss_percentile"] >= 0.90).mean() * 100, 1),
        "% with EPSS >= 0.10": round((x["epss_score"] >= 0.10).mean() * 100, 1),
    })


def category_rates(d, col, min_n):
    sub = d.dropna(subset=[col])
    g = (sub.groupby(col).agg(kevs=("cve", "size"), below=("below", "sum")).reset_index())
    g = g[g["kevs"] >= min_n].copy()
    g["pct_below"] = (g["below"] / g["kevs"] * 100).round(1)
    baseline = sub["below"].mean() * 100 if len(sub) else np.nan
    return g, baseline


def rate_chart(g, baseline, label_col, cutoff):
    g = g.sort_values("pct_below")
    fig = px.bar(g, x="pct_below", y=label_col, orientation="h", text="pct_below",
                 hover_data={"kevs": True, "below": True, "pct_below": ":.1f"},
                 labels={"pct_below": f"% of KEVs scoring below {cutoff:.1f}", label_col: ""})
    fig.add_vline(x=baseline, line_dash="dash", annotation_text=f"overall {baseline:.0f}%")
    fig.update_layout(height=max(320, 28 * len(g) + 120), margin=dict(l=0, r=0, t=30, b=0))
    return fig


# ---------------------------------------------------------------- page
st.set_page_config(page_title="When Severity Does Not Equal Risk", layout="wide")
st.title("When Severity Does Not Equal Risk")
st.caption("Known-exploited vulnerabilities (CISA KEV) that a CVSS severity cutoff would miss. "
           "NVD 2020-2026, CISA KEV, EPSS snapshot of Sept 2, 2026.")

kev, nonkev = load_data()

st.sidebar.header("Controls")
cutoff = st.sidebar.slider("CVSS cutoff for 'high priority'", 4.0, 10.0, 9.0, 0.1)
years = st.sidebar.slider("Publication years", 2020, 2026, (2020, 2026))
min_n = st.sidebar.slider("Minimum KEVs per CWE / vendor", 5, 30, 10)
st.sidebar.caption("2026 is a partial year, so its KEV counts are still growing.")

d = kev[kev["publication_year"].between(years[0], years[1])].copy()
if d.empty:
    st.warning("No KEVs in the selected years.")
    st.stop()
below_lab, above_lab = f"Below {cutoff:.1f}", f"{cutoff:.1f} and above"
status_colors = {below_lab: "#EF553B", above_lab: "#636EFA"}
d["below"] = d["cvss_score"] < cutoff
d["status"] = np.where(d["below"], below_lab, above_lab)

n, n_below = len(d), int(d["below"].sum())
ctx = nonkev.iloc[(nonkev["threshold"] - cutoff).abs().argmin()]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Known-exploited vulnerabilities", f"{n:,}")
c2.metric(f"Scoring below {cutoff:.1f}", f"{n_below:,} ({n_below / n * 100:.1f}%)")
c3.metric("Median EPSS percentile of those",
          f"{d.loc[d['below'], 'epss_percentile'].median():.2f}" if n_below else "n/a")
c4.metric("Same, for non-KEVs below cutoff", f"{ctx['median_percentile']:.2f}")

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Scores", "By year", "EPSS", "Weakness & vendor", "About"])

with tab1:
    fig = px.histogram(d, x="cvss_score", color="status", nbins=40, barmode="overlay", opacity=0.75,
                       color_discrete_map=status_colors, category_orders={"status": [below_lab, above_lab]},
                       labels={"cvss_score": "CVSS score", "status": ""})
    fig.add_vline(x=cutoff, line_dash="dash")
    fig.update_layout(margin=dict(l=0, r=0, t=30, b=0))
    st.plotly_chart(fig)
    st.caption("Each bar counts known-exploited vulnerabilities. Everything left of the dashed line "
               "would fall outside a 'fix the highest scores first' policy.")

with tab2:
    by_year = (d.groupby("publication_year").agg(kevs=("cve", "size"), below=("below", "sum")).reset_index())
    by_year["pct_below"] = (by_year["below"] / by_year["kevs"] * 100).round(1)
    fig = px.bar(by_year, x="publication_year", y="pct_below", text="pct_below",
                 hover_data={"kevs": True, "below": True},
                 labels={"pct_below": f"% of KEVs below {cutoff:.1f}", "publication_year": "Publication year"})
    fig.update_yaxes(range=[0, 100]); fig.update_layout(margin=dict(l=0, r=0, t=30, b=0))
    st.plotly_chart(fig)
    st.caption("In the full analysis there is no evidence of a steady trend through 2025; "
               "the apparent drop in 2026 reflects a partial year.")

with tab3:
    summary = pd.DataFrame({lab: epss_summary(sub) for lab, sub in d.groupby("status")}).T
    summary.loc["Non-KEVs below cutoff (all CVEs)"] = [
        int(ctx["n_nonkev_below"]), round(ctx["median_percentile"], 3),
        round(ctx["pct_top10_percentile"], 1), round(ctx["pct_epss_ge_0.10"], 1)]
    st.dataframe(summary)
    fig = px.box(d, x="status", y="epss_percentile", color="status", points="outliers",
                 color_discrete_map=status_colors, category_orders={"status": [below_lab, above_lab]},
                 labels={"epss_percentile": "EPSS percentile (Sept 2, 2026 snapshot)", "status": ""})
    fig.update_layout(margin=dict(l=0, r=0, t=30, b=0), showlegend=False)
    st.plotly_chart(fig)
    st.caption("EPSS is a snapshot, not historical, and partly overlaps with KEV, so this is context, "
               "not independent validation.")

with tab4:
    cwe_g, cwe_base = category_rates(d, "cwe", min_n)
    cwe_g["label"] = [f"{c} {CWE_NAMES.get(c, '')} (n={k})".replace("  ", " ") for c, k in zip(cwe_g["cwe"], cwe_g["kevs"])]
    ven_g, ven_base = category_rates(d, "vendor", min_n)
    ven_g["label"] = [f"{v} (n={k})" for v, k in zip(ven_g["vendor"], ven_g["kevs"])]
    left, right = st.columns(2)
    with left:
        st.subheader("By weakness type (CWE)")
        if len(cwe_g):
            st.plotly_chart(rate_chart(cwe_g, cwe_base, "label", cutoff))
        else:
            st.info("No CWE has enough KEVs. Lower the minimum in the sidebar.")
    with right:
        st.subheader("By vendor")
        if len(ven_g):
            st.plotly_chart(rate_chart(ven_g, ven_base, "label", cutoff))
        else:
            st.info("No vendor has enough KEVs. Lower the minimum in the sidebar.")
    st.caption("Descriptive only; CWE and vendor overlap and are not adjusted for each other. "
               "See the paper for tests.")

with tab5:
    st.markdown(
        "**What this shows.** A KEV is a vulnerability CISA has confirmed was exploited. "
        "A *mismatch* is a KEV that scores below your chosen CVSS cutoff. Move the slider to see how many "
        "a severity-only policy would miss.\n\n"
        "**Limits.** Absence from KEV does not mean a vulnerability was never exploited. "
        "EPSS values are one snapshot (Sept 2, 2026). Results are descriptive and unadjusted. "
        "2026 is a partial year.\n\n"
        "**Data.** NVD (2020-2026), CISA KEV, EPSS. Code and full analysis: see the project repository.")