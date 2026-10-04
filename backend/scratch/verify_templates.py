import urllib.request
import json

templates = [
    '2026-10-04 14:42:15|GW-INGRESS-03|req_id=rq_9182|client=10.14.8.99|server=198.51.100.45|method=POST|endpoint=/api/v3/orders|status_code=201|latency=38ms',
    '[2026-10-04 14:42:15] [AUDIT-SERVICE] tenant=tenant_402 actor=sreya_dev client_ip=172.24.12.8 action=MODIFY_ROLE target=role_admin status=SUCCESS',
    'timestamp="2026-10-04T14:42:15Z"; service="payment-engine"; event="charge_attempt"; customer_id="cust_9812"; amount=149.99; currency="USD"; client_ip="192.168.4.15"; status="approved"',
    '2026/10/04 14:42:15 DB-PROXY-01: txn_id=tx_8819 db_user=app_backend source_ip=10.100.4.12 operation=UPDATE table=account_balances rows=1 latency_ms=4.2',
    '2026-10-04 14:42:15.821 AUTH-GATEWAY session_id=sess_47192 user_id=jdoe_admin origin=10.20.5.88 auth_type=MFA_CHALLENGE result=VERIFIED provider=Okta',
    '2026-10-04T14:42:15.102Z pod="order-processor-7f89d" namespace="production" trace_id="tr_4421b" remote_ip="10.42.1.20" rpc_method="ProcessPayment" status_code="OK" elapsed="14ms"',
    '2026-10-04 14:42:15 NET-FLOW-AGENT: src_ip=192.168.1.105 src_port=54812 dst_ip=10.0.12.55 dst_port=9200 proto=TCP bytes_in=1024 bytes_out=4096 flow_state=CLOSED'
]

for idx, log in enumerate(templates):
    req = urllib.request.Request(
        'http://127.0.0.1:8000/api/v1/analyzer/analyze',
        data=json.dumps({'raw_log': log}).encode(),
        headers={'Content-Type': 'application/json'}
    )
    res = json.loads(urllib.request.urlopen(req).read())
    print(f"Format {idx+1}: status={res.get('format_status')} | confidence={res.get('confidence')} | fields={len(res.get('fields', []))}")
