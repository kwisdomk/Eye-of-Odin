from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage
from tools import check_local_threat_db, check_virustotal, check_shodan, send_alert
from db import init_db, insert_incident
from dotenv import load_dotenv
import os, re

load_dotenv()
init_db()

# ── Gemini 2.0 Flash — reasoning engine ───────────────────
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    google_api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0.1,
    max_tokens=1024,
)

tools  = [check_local_threat_db, check_virustotal, check_shodan, send_alert]
agent  = create_react_agent(llm, tools)

SYSTEM_PROMPT = '''
You are CyberSentinel, an autonomous cybersecurity AI agent.
Your job: analyse security events and protect systems.

RULES — follow in order:
1. If you see an IP, ALWAYS call check_local_threat_db first.
2. If local DB misses, call check_virustotal.
3. If malicious > 0 on VirusTotal, call check_shodan for intel.
4. If threat confirmed by ANY source, call send_alert immediately.
   Format: SEVERITY|IP|THREAT_TYPE|one sentence description
5. Conclude with: severity level, what happened, what you did.

Severity: CRITICAL = active attack, HIGH = confirmed threat, MEDIUM = suspicious.
Be decisive. Be concise. Every decision must be justified.
'''

def analyse_event(event: dict) -> dict:
    prompt = f'''{SYSTEM_PROMPT}

Analyse this security event:
IP: {event.get('ip', 'unknown')}
Activity: {event.get('activity', 'unknown')}
'''
    result   = agent.invoke({'messages': [HumanMessage(content=prompt)]})
    analysis = result['messages'][-1].content

    os.makedirs('logs', exist_ok=True)
    with open('logs/agent_output.txt', 'a') as f:
        f.write(f"\n[EVENT] IP:{event.get('ip')} | {event.get('activity')}\n")
        f.write(f"[GEMINI] {analysis}\n{'='*60}\n")

    sev = 'LOW'
    for s in ['CRITICAL', 'HIGH', 'MEDIUM']:
        if s in analysis.upper():
            sev = s; break

    insert_incident(
        ip           = event.get('ip', 'unknown'),
        severity     = sev,
        summary      = analysis[:500],
        action_taken = 'Alert sent' if 'alert' in analysis.lower() else 'Logged',
        raw_analysis = analysis
    )

    return {'analysis': analysis, 'severity': sev, 'ip': event.get('ip')}
def generate_report() -> str:
    from db import get_recent_alerts
    alerts = get_recent_alerts(10)
    if not alerts:
        return 'No alerts to report.'

    alert_lines = '\n'.join([f'[{a[1]}] {a[2]} | {a[3]} | {a[4]}' for a in alerts])
    prompt = f'''
    You are a senior cybersecurity analyst. Write a formal incident report.
    Sections: Executive Summary, Timeline, Threat Analysis,
    Impact Assessment, Recommended Actions.

    Alerts:\n{alert_lines}
    '''
    content = llm.invoke(prompt).content
    return str(content)  # ← fixes the type mismatch

if __name__ == '__main__':
    test = {'ip': '185.23.44.2', 'activity': '500 failed logins in 60 seconds'}
    result = analyse_event(test)
    print(result['analysis'])