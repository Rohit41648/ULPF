import urllib.request
import json

test_logs = [
    '2026-10-04 14:10:00|PROXY-01|principal=alice|src=10.0.1.42|dst=198.51.100.2|verb=POST|uri=/api/v2/payment|code=201',
    '2026/10/04 14:12:30 AUTH-SRV LOGIN_SUCCESS user=jsmith src=10.50.2.14 app=portal status=allowed session=s_9843',
    '[2026-10-04 14:15:00] [AUDIT-US-EAST] tenant_id=t_7821 client_ip=192.168.10.88 method=GET resource=/admin/audit outcome=success',
    'timestamp="2026-10-04T14:16:00Z"; service="billing"; event="invoice_created"; client_ip="172.16.5.9"; target_ip="10.0.2.5"; port=8443; duration=45ms; status="OK"',
    '2026-10-04 14:18:22 DB-GATEWAY-02: txn_id=tx_9981 db_user=app_srv client=10.100.1.5 query_type=SELECT table=customers rows_affected=15 exec_time=12ms'
]

for log in test_logs:
    req = urllib.request.Request(
        'http://127.0.0.1:8000/api/v1/analyzer/analyze',
        data=json.dumps({'raw_log': log}).encode(),
        headers={'Content-Type': 'application/json'}
    )
    res = json.loads(urllib.request.urlopen(req).read())
    print('Format Status:', res.get('format_status'), '| Confidence:', res.get('confidence'), '| Fields:', len(res.get('fields', [])))
