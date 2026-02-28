from langchain.tools import tool
from db import insert_alert
from dotenv import load_dotenv
import requests, os

load_dotenv()

THREAT_DB = {
    '185.23.44.2':   ('BruteForce',   'CRITICAL', 'Known botnet C2'),
    '192.168.1.100': ('BruteForce',   'CRITICAL', 'Internal attack source'),
    '10.0.0.55':     ('PortScan',     'HIGH',     'Automated scanner'),
    '172.16.0.99':   ('SQLInjection', 'HIGH',     'Web attack origin'),
}

@tool
def check_local_threat_db(ip_address: str) -> str:
    '''Check IP against local threat database. Call this FIRST for any IP.'''
    if ip_address in THREAT_DB:
        t, s, n = THREAT_DB[ip_address]
        return f'LOCAL HIT: {ip_address} | Type: {t} | Severity: {s} | Note: {n}'
    return f'CLEAN: {ip_address} not in local database.'

@tool
def check_virustotal(ip_address: str) -> str:
    '''Check IP reputation on VirusTotal. Use after local DB check.'''
    key = os.getenv('VIRUSTOTAL_API_KEY')
    if not key:
        return f'VirusTotal unavailable — no API key.'
    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        r   = requests.get(url, headers={'x-apikey': key}, timeout=8)
        if r.status_code == 200:
            d       = r.json()['data']['attributes']
            stats   = d['last_analysis_stats']
            mal     = stats.get('malicious', 0)
            sus     = stats.get('suspicious', 0)
            country = d.get('country', 'Unknown')
            return f'VT: {ip_address} | Country: {country} | Malicious: {mal} | Suspicious: {sus}'
        return f'VT: No data for {ip_address}'
    except Exception as e:
        return f'VT error: {e}'

@tool
def check_shodan(ip_address: str) -> str:
    '''Get network profile for an IP. Use to enrich threat context.'''
    key = os.getenv('SHODAN_API_KEY')
    if not key:
        return f'Shodan unavailable — no API key.'
    try:
        url = f'https://api.shodan.io/shodan/host/{ip_address}?key={key}'
        r   = requests.get(url, timeout=8)
        if r.status_code == 200:
            d = r.json()
            return f'Shodan: {ip_address} | Org: {d.get("org","?")} | Country: {d.get("country_name","?")} | Ports: {d.get("ports",[])}'
        return f'Shodan: No record for {ip_address}'
    except Exception as e:
        return f'Shodan error: {e}'

@tool
def send_alert(payload: str) -> str:
    '''
    Send a confirmed security alert.
    Format: SEVERITY|IP|THREAT_TYPE|description
    Example: CRITICAL|185.23.44.2|BruteForce|500 failed logins detected
    '''
    try:
        parts    = payload.split('|', 3)
        severity = parts[0].strip() if len(parts) > 0 else 'HIGH'
        ip       = parts[1].strip() if len(parts) > 1 else 'unknown'
        ttype    = parts[2].strip() if len(parts) > 2 else 'Unknown'
        message  = parts[3].strip() if len(parts) > 3 else payload
    except:
        severity, ip, ttype, message = 'HIGH', 'unknown', 'Unknown', payload

    insert_alert(severity, ip, message)

    os.makedirs('logs', exist_ok=True)
    from datetime import datetime
    with open('logs/alerts.txt', 'a') as f:
        f.write(f'[{datetime.now().strftime("%H:%M:%S")}] [{severity}] {ip} | {ttype} | {message}\n')

    webhook = os.getenv('SLACK_WEBHOOK_URL')
    if webhook:
        e = ':rotating_light:' if severity == 'CRITICAL' else ':warning:'
        requests.post(webhook, json={'text': f'{e} *{severity}* | {ip} | {ttype}\n>{message}'}, timeout=5)

    return f'Alert fired: [{severity}] {message}'