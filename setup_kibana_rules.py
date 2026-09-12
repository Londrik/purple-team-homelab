import json
import requests
import sys

KIBANA_URL = "http://localhost:5601"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

RULES = [
    {
        "rule_id": "purple_sqli_detection",
        "name": "Threat - SQL Injection Detected",
        "type": "query",
        "index": ["filebeat-*"],
        "query": "url.path: (*%27* or *%20OR%20* or *--* or *UNION* or *1%3D1*) or rule.category: \"threat/sql-injection\"",
        "from": "now-360s",
        "interval": "1m",
        "severity": "high",
        "risk_score": 73,
        "description": "Detecta tentativas de SQL Injection no Juice Shop via logs HTTP.",
        "tags": ["purple-team", "sqli", "owasp"],
        "enabled": True
    },
    {
        "rule_id": "purple_path_traversal_detection",
        "name": "Threat - Path Traversal Attempt",
        "type": "query",
        "index": ["filebeat-*"],
        "query": "url.path: (*..%2F* or *../* or *etc*passwd*) or rule.category: \"threat/path-traversal\"",
        "from": "now-360s",
        "interval": "1m",
        "severity": "high",
        "risk_score": 73,
        "description": "Detecta sequencias de Directory Traversal buscando arquivos sensiveis.",
        "tags": ["purple-team", "traversal", "owasp"],
        "enabled": True
    },
    {
        "rule_id": "purple_recon_404_burst",
        "name": "Anomaly - High Rate of 404/403 (Recon Burst)",
        "type": "threshold",
        "index": ["filebeat-*"],
        "query": "http.response.status_code: (403 or 404)",
        "threshold": {
            "field": ["http.response.status_code"],
            "value": 2
        },
        "from": "now-360s",
        "interval": "1m",
        "severity": "medium",
        "risk_score": 47,
        "description": "Detecta picos de erros 403 e 404 de fuzzing e scanners web.",
        "tags": ["purple-team", "recon", "scanner"],
        "enabled": True
    },
    {
        "rule_id": "purple_xss_detection",
        "name": "Threat - Reflected XSS Attempt",
        "type": "query",
        "index": ["filebeat-*"],
        "query": "url.path: (*%3Cscript* or *%3Ciframe* or *javascript%3A* or *onerror%3D* or *alert%28*) or rule.category: \"threat/xss\"",
        "from": "now-360s",
        "interval": "1m",
        "severity": "high",
        "risk_score": 73,
        "description": "Detecta tentativas de injecao Cross-Site Scripting (XSS) via parametros URL.",
        "tags": ["purple-team", "xss", "owasp"],
        "enabled": True
    },
    {
        "rule_id": "purple_sensitive_enumeration",
        "name": "Threat - Sensitive Endpoint Enumeration",
        "type": "query",
        "index": ["filebeat-*"],
        "query": "url.path: (*admin* or *%2F.env* or *backup* or *%2F.git*) or rule.category: \"threat/enumeration\"",
        "from": "now-360s",
        "interval": "1m",
        "severity": "medium",
        "risk_score": 55,
        "description": "Detecta requisicoes direcionadas a caminhos administrativos, arquivos de ambiente e repositorios expostos.",
        "tags": ["purple-team", "enumeration", "owasp"],
        "enabled": True
    },
    {
        "rule_id": "purple_bola_idor_detection",
        "name": "Threat - Broken Object Level Authorization (BOLA)",
        "type": "query",
        "index": ["filebeat-*"],
        "query": "url.path: /rest/basket/* or rule.category: \"threat/bola\"",
        "from": "now-360s",
        "interval": "1m",
        "severity": "high",
        "risk_score": 70,
        "description": "Detecta tentativas de acesso a cestas e objetos de outros usuarios (BOLA/IDOR) via API REST.",
        "tags": ["purple-team", "bola", "idor", "owasp"],
        "enabled": True
    }
]

def deploy_rules():
    print("[*] Provisionando Detection Rules no Kibana...")
    for rule in RULES:
        res = requests.post(f"{KIBANA_URL}/api/detection_engine/rules", headers=HEADERS, data=json.dumps(rule))
        if res.status_code == 200:
            print(f"[+] Regra '{rule['name']}': Criada")
        elif res.status_code == 409:
            print(f"[!] Regra '{rule['name']}': Ja existente")
        else:
            print(f"[-] Erro em '{rule['name']}': {res.status_code} - {res.text}")

if __name__ == "__main__":
    deploy_rules()
