import requests
import json
import sys

KIBANA_URL = 'http://localhost:5601'
HEADERS = {'kbn-xsrf': 'true', 'Content-Type': 'application/json'}

def get_data_view_id():
    res = requests.get(f'{KIBANA_URL}/api/data_views', headers=HEADERS)
    if res.status_code == 200:
        dvs = res.json().get('data_view', [])
        for dv in dvs:
            if dv.get('title') == 'filebeat-*':
                return dv.get('id')
    return None

def build_and_deploy_dashboard(data_view_id):
    print(f'[*] Utilizando Data View ID: {data_view_id}')
    
    # 1. Visualizacao Lens: Metricas de Ataques por Categoria
    lens_category_payload = {
        'id': 'purple-lens-categories',
        'type': 'lens',
        'attributes': {
            'title': 'Eventos por Categoria de Ameaça',
            'visualizationType': 'lnsPie',
            'state': {
                'datasourceStates': {
                    'formBased': {
                        'layers': {
                            'layer1': {
                                'columns': {
                                    'col1': {
                                        'dataType': 'string',
                                        'isBucketed': True,
                                        'operationType': 'terms',
                                        'params': {'size': 5, 'orderBy': {'type': 'column', 'columnId': 'col2'}, 'orderDirection': 'desc'},
                                        'sourceField': 'rule.category'
                                    },
                                    'col2': {
                                        'dataType': 'number',
                                        'isBucketed': False,
                                        'operationType': 'count'
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        'references': [{'id': data_view_id, 'name': 'indexpattern-datasource-layer-layer1', 'type': 'index-pattern'}]
    }

    # 2. Visualizacao Lens: Status Code Distribution (404/403 vs 200)
    lens_status_payload = {
        'id': 'purple-lens-status',
        'type': 'lens',
        'attributes': {
            'title': 'Distribuicao de Codigos HTTP',
            'visualizationType': 'lnsBar',
            'state': {
                'datasourceStates': {
                    'formBased': {
                        'layers': {
                            'layer1': {
                                'columns': {
                                    'col1': {
                                        'dataType': 'number',
                                        'isBucketed': True,
                                        'operationType': 'terms',
                                        'params': {'size': 10, 'orderBy': {'type': 'column', 'columnId': 'col2'}, 'orderDirection': 'desc'},
                                        'sourceField': 'http.response.status_code'
                                    },
                                    'col2': {
                                        'dataType': 'number',
                                        'isBucketed': False,
                                        'operationType': 'count'
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        'references': [{'id': data_view_id, 'name': 'indexpattern-datasource-layer-layer1', 'type': 'index-pattern'}]
    }

    # 3. Dashboard Atualizado integrando os paineis
    panels = [
        {
            'type': 'lens',
            'gridData': {'x': 0, 'y': 0, 'w': 24, 'h': 15, 'i': '1'},
            'panelIndex': '1',
            'panelRefName': 'panel_0'
        },
        {
            'type': 'lens',
            'gridData': {'x': 24, 'y': 0, 'w': 24, 'h': 15, 'i': '2'},
            'panelIndex': '2',
            'panelRefName': 'panel_1'
        }
    ]

    dashboard_payload = {
        'id': 'purple-team-overview',
        'type': 'dashboard',
        'attributes': {
            'title': 'Purple Team - OWASP Telemetry Overview',
            'description': 'Painel executivo de alertas e telemetria HTTP Juice Shop',
            'panelsJSON': json.dumps(panels),
            'optionsJSON': '{"useMargins":true}',
            'version': 1
        },
        'references': [
            {'id': 'purple-lens-categories', 'name': 'panel_0', 'type': 'lens'},
            {'id': 'purple-lens-status', 'name': 'panel_1', 'type': 'lens'}
        ]
    }

    bulk_payload = [lens_category_payload, lens_status_payload, dashboard_payload]

    res = requests.post(
        f'{KIBANA_URL}/api/saved_objects/_bulk_create?overwrite=true',
        headers=HEADERS,
        data=json.dumps(bulk_payload)
    )

    if res.status_code == 200:
        print('[+] Paineis e Dashboard Lens provisionados com sucesso!')
    else:
        print(f'[-] Falha no provisionamento: {res.status_code} - {res.text}')

if __name__ == '__main__':
    dv_id = get_data_view_id()
    if not dv_id:
        print('[-] Data View filebeat-* nao encontrado. Execute curl de criacao antes.')
        sys.exit(1)
    build_and_deploy_dashboard(dv_id)
