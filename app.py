import json
from pathlib import Path
import streamlit as st
import pandas as pd
from safetrace.sanitizer import Sanitizer
from safetrace.canary import run_canary_test
from safetrace.benchmark import run_benchmark
from safetrace.diagnosis import diagnose_with_ollama

st.set_page_config(page_title="SafeTrace", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.block-container{padding-top:2rem;max-width:1200px}.hero{padding:1.5rem;border-radius:18px;background:linear-gradient(120deg,#101827,#203b55);color:white}.muted{color:#64748b}.stTabs [data-baseweb="tab-list"]{gap:8px}
</style>""", unsafe_allow_html=True)
st.markdown('<div class="hero"><h1>🛡️ SafeTrace</h1><p>Existing tools hide secrets. SafeTrace measures whether what\'s left is still useful.</p><p>Local-first log sanitization · measurable privacy · retained debugging context</p></div>', unsafe_allow_html=True)
st.warning("Use synthetic logs for demos. Detection is best-effort and cannot guarantee that every secret is found.")
tabs=st.tabs(["Home", "Sanitize Logs", "Privacy Lab", "Utility Benchmark", "AI Diagnosis", "Methodology"])
with tabs[0]:
    st.subheader("Debug without casually exposing secrets")
    st.write("SafeTrace detects likely sensitive values, replaces repeated values with consistent pseudonyms, and preserves useful diagnostic structure.")
    c1,c2,c3=st.columns(3)
    c1.metric("Default processing", "Local")
    c2.metric("Evaluation", "Canary leak test")
    c3.metric("Debugging utility", "Benchmark")
    st.info("AI diagnosis is optional. The Ollama workflow receives only the sanitized text produced by this app.")
with tabs[1]:
    st.subheader("Sanitize a log")
    demo="\n".join(['ERROR: AuthenticationError: invalid credential for alice@example.com','Authorization: Bearer demo_secret_token_12345','File \"/home/alice/project/api.py\", line 42, in authenticate','HTTP 401: request failed','password=example-password-only'])
    raw=st.text_area("Paste log text", value=demo, height=230, help="Processed in this Python app; raw text is not sent to a service.")
    max_bytes=1_000_000
    if len(raw.encode('utf-8')) > max_bytes: st.error("Input exceeds the 1 MB demo limit.")
    elif st.button("Sanitize locally", type="primary"):
        sanitizer=Sanitizer()
        result=sanitizer.sanitize(raw)
        st.session_state['sanitized']=result.text
        st.session_state['stats']=result.stats
        st.session_state['detected']=result.detected_categories
    if 'sanitized' in st.session_state:
        left,right=st.columns(2)
        with left:
            st.caption("Sanitized output")
            st.code(st.session_state['sanitized'], language="text")
            st.download_button("Download sanitized log", st.session_state['sanitized'], file_name="sanitized.log", mime="text/plain")
        with right:
            stats=st.session_state.get('stats',{})
            st.metric("Replacements", stats.get('replacements',0))
            st.write("**Detected categories**")
            st.write(", ".join(st.session_state.get('detected',[])) or "No matches detected")
            st.caption("Copy the sanitized output from the code panel. Original values are not included in the report.")
with tabs[2]:
    st.subheader("Privacy Lab — canary leak test")
    st.write("Synthetic canaries are inserted into sample logs, sanitized, then checked against their original values.")
    n=st.slider("Number of synthetic canaries", 5, 40, 20)
    if st.button("Run canary test"):
        report=run_canary_test(n)
        st.session_state['canary_report']=report
    if 'canary_report' in st.session_state:
        r=st.session_state['canary_report']
        a,b,c=st.columns(3); a.metric("Privacy score", f"{r['privacy_score']:.1f}%"); b.metric("Leak rate", f"{r['leak_rate']:.1f}%"); c.metric("Leaked canaries", f"{r['leaked_canaries']}/{r['total_canaries']}")
        st.caption(f"Detected: {r['detected_canaries']} of {r['total_canaries']}. Canary leak means the full original canary value remains in sanitized output. This is a measured test result, not a guarantee.")
with tabs[3]:
    st.subheader("Privacy–utility benchmark")
    st.write("The included starter dataset is explicitly synthetic. Import verified public cases only after checking source and reuse terms.")
    if st.button("Run benchmark", type="primary"):
        report=run_benchmark()
        st.session_state['benchmark_report']=report
    if 'benchmark_report' in st.session_state:
        report=st.session_state['benchmark_report']
        df=pd.DataFrame(report['rows'])
        st.dataframe(df, use_container_width=True, hide_index=True)
        chart=df.set_index('Method')[['Privacy score (%)','Diagnosis accuracy (%)']]
        st.bar_chart(chart)
        st.caption(f"Sample size: {report['sample_size']}. Diagnosis scoring is deterministic reference-rule scoring, not human or LLM validation. Privacy values are measured using synthetic canaries in each case.")
        st.download_button("Download benchmark report (JSON)", json.dumps(report, indent=2), file_name="safetrace_benchmark.json", mime="application/json")
with tabs[4]:
    st.subheader("Optional AI diagnosis with Ollama")
    st.write("Ollama must be installed and running locally. SafeTrace passes sanitized text only from this interface.")
    model=st.text_input("Ollama model name", value="llama3.2")
    sanitized=st.session_state.get('sanitized','')
    st.caption("Sanitized text is used below. Sanitize a log first.")
    if st.button("Diagnose sanitized log"):
        if not sanitized: st.error("Sanitize a log first.")
        else:
            with st.spinner("Contacting local Ollama instance..."):
                answer, error=diagnose_with_ollama(sanitized, model)
            if error: st.error(error)
            else: st.write(answer)
with tabs[5]:
    st.subheader("How SafeTrace measures itself")
    st.markdown("""**Leak rate** = surviving full canary values ÷ injected canary values × 100.  
**Privacy score** = 100 − leak rate.  
**Diagnosis accuracy** = cases where the deterministic reference rule identifies the expected root-cause category ÷ total cases × 100.

This starter benchmark is a reproducible engineering check, not proof of real-world security or a substitute for expert diagnosis. Regexes can miss secrets; entropy can produce false positives; path pseudonymization is heuristic. Always inspect sanitized output before sharing it.""")
    st.write("Dataset provenance: bundled examples are synthetic and contain fake values. See `data/DATASET_SOURCES.md` for the public-data import checklist.")
