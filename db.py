import sqlite3
from datetime import datetime

DB = 'cybersentinel.db'

def get_conn():
    return sqlite3.connect(DB, timeout=10)

def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT    NOT NULL,
        ip        TEXT,
        activity  TEXT    NOT NULL,
        processed INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    TEXT NOT NULL,
        ip           TEXT,
        severity     TEXT NOT NULL,
        summary      TEXT NOT NULL,
        action_taken TEXT,
        raw_analysis TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        severity  TEXT,
        ip        TEXT,
        message   TEXT NOT NULL
    )''')

    conn.commit()
    conn.close()
    print('DB ready: cybersentinel.db')

# ── Write helpers ──────────────────────────────────────────
def insert_log(ip, activity):
    conn = get_conn()
    conn.execute('INSERT INTO logs (timestamp,ip,activity) VALUES (?,?,?)',
                 (datetime.now().isoformat(), ip, activity))
    conn.commit(); conn.close()

def insert_incident(ip, severity, summary, action_taken, raw_analysis=''):
    conn = get_conn()
    conn.execute(
        'INSERT INTO incidents (timestamp,ip,severity,summary,action_taken,raw_analysis) VALUES (?,?,?,?,?,?)',
        (datetime.now().isoformat(), ip, severity, summary, action_taken, raw_analysis)
    )
    conn.commit(); conn.close()

def insert_alert(severity, ip, message):
    conn = get_conn()
    conn.execute('INSERT INTO alerts (timestamp,severity,ip,message) VALUES (?,?,?,?)',
                 (datetime.now().isoformat(), severity, ip, message))
    conn.commit(); conn.close()

# ── Read helpers ───────────────────────────────────────────
def get_unprocessed_logs():
    conn = get_conn()
    rows = conn.execute('SELECT * FROM logs WHERE processed=0 ORDER BY id').fetchall()
    conn.close()
    return rows

def mark_log_processed(log_id):
    conn = get_conn()
    conn.execute('UPDATE logs SET processed=1 WHERE id=?', (log_id,))
    conn.commit(); conn.close()

def get_recent_logs(n=20):
    conn = get_conn()
    rows = conn.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (n,)).fetchall()
    conn.close(); return rows

def get_recent_incidents(n=10):
    conn = get_conn()
    rows = conn.execute('SELECT * FROM incidents ORDER BY id DESC LIMIT ?', (n,)).fetchall()
    conn.close(); return rows

def get_recent_alerts(n=10):
    conn = get_conn()
    rows = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (n,)).fetchall()
    conn.close(); return rows

def get_stats():
    conn = get_conn()
    stats = {
        'total_logs':      conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0],
        'total_incidents': conn.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],
        'total_alerts':    conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],
        'critical':        conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0],
    }
    conn.close(); return stats

if __name__ == '__main__':
    init_db()