from db import get_unprocessed_logs, mark_log_processed
from agent import analyse_event, generate_report
import time, os

REPORT_THRESHOLD = 3  # generate report after this many critical/high alerts

alert_count = 0

print('CyberSentinel AI — main loop starting')
print('Waiting for events...')

while True:
    logs = get_unprocessed_logs()

    for log in logs:
        log_id   = log[0]
        ip       = log[2]
        activity = log[3]

        print(f'\nProcessing: [{ip}] {activity}')
        event  = {'ip': ip, 'activity': activity}
        result = analyse_event(event)

        print(f'Gemini: [{result["severity"]}] {result["analysis"][:150]}...')

        if result['severity'] in ('CRITICAL', 'HIGH'):
            alert_count += 1

        if alert_count >= REPORT_THRESHOLD:
            print('\nGenerating incident report...')
            report = generate_report()
            os.makedirs('reports', exist_ok=True)
            from datetime import datetime
            fname = f'reports/report_{datetime.now().strftime("%H%M%S")}.txt'
            with open(fname, 'w') as f:
                f.write(report)
            print(f'Report saved: {fname}')
            alert_count = 0

        mark_log_processed(log_id)

    time.sleep(3)