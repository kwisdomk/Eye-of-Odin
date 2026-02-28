import time, random
from db import insert_log

NORMAL = [
    {'ip': '10.0.0.1',  'activity': 'User admin logged in successfully'},
    {'ip': '10.0.0.2',  'activity': 'GET /api/users 200 OK'},
    {'ip': '10.0.0.3',  'activity': 'Database backup completed'},
    {'ip': '10.0.0.4',  'activity': 'Scheduled job ran: cleanup'},
    {'ip': '10.0.0.5',  'activity': 'User john.doe logged out'},
]

ATTACK = [
    {'ip': '185.23.44.2', 'activity': 'Failed login attempt 1 of 500'},
    {'ip': '185.23.44.2', 'activity': 'Failed login attempt 50 of 500'},
    {'ip': '10.0.0.55',   'activity': 'Port scan detected — ports 1 to 1024'},
    {'ip': '185.23.44.2', 'activity': 'Failed login attempt 200 of 500'},
    {'ip': '172.16.0.99', 'activity': 'SQL injection attempt: SELECT * FROM users WHERE 1=1--'},
    {'ip': '185.23.44.2', 'activity': 'CRITICAL: 500 failed logins in 60 seconds'},
]

def simulate(attack_after=8):
    print('Log simulator running...')
    count = 0
    attack_idx = 0

    while True:
        if count < attack_after:
            e = random.choice(NORMAL)
        elif attack_idx < len(ATTACK):
            e = ATTACK[attack_idx]
            attack_idx += 1
            if attack_idx == 1:
                print('--- ATTACK SEQUENCE STARTING ---')
        else:
            e = random.choice(NORMAL)

        insert_log(e['ip'], e['activity'])
        print(f'  LOG: [{e["ip"]}] {e["activity"]}')
        count += 1
        time.sleep(4)

if __name__ == '__main__':
    simulate()