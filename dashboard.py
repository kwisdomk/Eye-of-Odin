import streamlit as st
import time, os
from db import get_recent_logs, get_recent_alerts, get_recent_incidents, get_stats

st.set_page_config(
    page_title='CyberSentinel AI',
    page_icon='🛡️',
    layout='wide'
)

# ── Header ────────────────────────────────────────────────
st.markdown('# 🛡️  CyberSentinel AI')
st.markdown('**Autonomous Threat Detection** · Powered by ✨ Google Gemini + 🔵 IBM watsonx')
st.divider()

# ── Metric cards ──────────────────────────────────────────
try:
    s = get_stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric('📋 Logs Analysed',    s['total_logs'])
    c2.metric('⚡ Total Alerts',      s['total_alerts'])
    c3.metric('🚨 Critical Threats',  s['critical'])
    c4.metric('📝 Reports Generated', s['total_incidents'])
except:
    pass

st.divider()

# ── Three columns ─────────────────────────────────────────
col1, col2, col3 = st.columns([1.2, 1.5, 1.3])

with col1:
    st.subheader('📋 Live Logs')
    try:
        logs = get_recent_logs(20)
        log_text = '\n'.join([f'[{r[2]}] {r[3]}' for r in logs])
        st.code(log_text, language=None)
    except:
        st.info('Waiting for logs...')

with col2:
    st.subheader('✨ Gemini Reasoning')
    try:
        with open('logs/agent_output.txt') as f:
            content = f.read()[-3000:]
        st.text_area('', content, height=420, label_visibility='hidden')
    except:
        st.info('Agent not running yet...')

with col3:
    st.subheader('🚨 Active Alerts')
    try:
        alerts = get_recent_alerts(10)
        if alerts:
            for a in alerts:
                col = 'red' if a[2] == 'CRITICAL' else 'orange' if a[2] == 'HIGH' else 'yellow'
                st.markdown(f':{col}[**[{a[2]}]** {a[3]} | {a[4][:60]}]')
        else:
            st.info('No alerts yet.')
    except:
        st.info('No alerts yet.')

st.divider()

# ── Incidents table ───────────────────────────────────────
st.subheader('📊 Confirmed Incidents')
try:
    incidents = get_recent_incidents(10)
    if incidents:
        import pandas as pd
        df = pd.DataFrame(incidents,
             columns=['ID','Time','IP','Severity','Summary','Action','Analysis'])
        st.dataframe(
            df[['Time','IP','Severity','Summary','Action']],
            use_container_width=True
        )
    else:
        st.info('No incidents yet.')
except Exception as e:
    st.error(str(e))

# ── Auto refresh ──────────────────────────────────────────
time.sleep(3)
st.rerun()