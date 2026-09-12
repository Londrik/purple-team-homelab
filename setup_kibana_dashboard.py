import requests
import json
import sys

KIBANA_URL = 'http://localhost:5601'
HEADERS = {'kbn-xsrf': 'true', 'Content-Type': 'application/json'}

def check_kibana():
    try:
        r = requests.get(f'{KIBANA_URL}/api/status', headers=HEADERS, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print(f'[-] Erro de conexao com Kibana: {e}')
        return False

def create_saved_objects():
    print('[*] Importando configuracoes e visualizacoes Purple Team...')
    # Na API v8 do Kibana, o payload do _bulk_create deve ser uma lista (array) direta
    dashboard_payload = [
        {
            'id': 'purple-team-overview',
            'type': 'dashboard',
            'attributes': {
                'title': 'Purple Team - OWASP Telemetry Overview',
                'description': 'Dashboard consolidado para deteccao de SQLi, Path Traversal e Scan 404',
                'panelsJSON': '[]',
                'optionsJSON': '{"useMargins":true}',
                'version': 1
            }
        }
    ]
    
    res = requests.post(
        f'{KIBANA_URL}/api/saved_objects/_bulk_create?overwrite=true',
        headers=HEADERS,
        data=json.dumps(dashboard_payload)
    )
    if res.status_code == 200:
        print('[+] Dashboard base criado com sucesso!')
        print(json.dumps(res.json(), indent=2))
    else:
        print(f'[-] Falha ao criar Dashboard: {res.status_code} - {res.text}')

if __name__ == '__main__':
    if not check_kibana():
        print('[-] Kibana indisponivel na porta 5601.')
        sys.exit(1)
    create_saved_objects()
