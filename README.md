# Purple Team Homelab

Ambiente integrado de emulação de adversários e detecção defensiva (Purple Team) em Linux (Fedora), orquestrado via Docker Compose com Elastic Stack (Elasticsearch 8.12.0, Filebeat, Kibana) e OWASP Juice Shop.

---

## 1. Arquitetura da Stack

```text
                     +---------------------------------------+
                     |       OWASP Juice Shop (:3000)        |
                     |       (DEBUG=express:router)          |
                     +-----------------+------------------+
                                     |
                            Stdout / Container JSON Logs
                                     v
                     +-----------------+------------------+
                     |         Filebeat 8.12.0               |
                     |  (Autodiscover + Ingest Pipeline)     |
                     +-----------------+------------------+
                                     |
                          Elasticsearch Ingest Pipeline
                              ('juice-shop-parser')
                                     v
+---------------------------------------------------------------------------------+
|                            Elasticsearch 8.12.0 (99200)                            |
|  - Grok ECS normalization (http.request.method, url.path, rule.category)          |
|  - Data stream: filebeat-8.12.0                                                  |
+------------------------------------------+-----------------------------------------+
                                     |
                                     v
+---------------------------------------------------------------------------------+
|                              Kibana 8.12.0 (:5601)                                 |
|  - Detection Engine Rules (.alerts-security.alerts-default)                       |
|  - SOC Lens Dashboard ('purple-team-overview')                                    |
+---------------------------------------------------------------------------------+p
```

### Mapeamento ECS no Ingest Pipeline (`jauice-shop-parser`)
O pipeline processa logs do Express e exceções brutas gerando os seguintes campos ECS:- `http.request.method`: Método HTTP capturado no roteador Express (`GET`, `POST`, etc.).
- `url.original` / `url.path`: Endpoint e parâmetros da requisição.
- `http.response.status_code`: Status HTTP retornado.
- `rule.category`: Tag de classificação gerada por heurística Ingest:
  - `threat/sql-injection`
  - `threat/path-traversal`
  - `threat/xss`
  - `threat/enumeration`
  - `threat/bola`

---

## 2. Peculiaridades de Ambiente (Fedora / SELinux)

Para evitar erros de permissão no daemon do Filebeat e restrições de contexto SELinux:
- j*Flags de Volume (`:z`)**: Todos os bindmos no `docker-compose.yml` (`filebeat.ymlX, `docker.sock`, logs de container) utilizam sufixo `:z` para reetiquetagem automática do SELinux.
- j*Flags do Beat**: O Filebeat executa como `root` com a flag `--strict.perms=false` para dispensar restrição estrita de `chown root:root` no `filebeat.yml` montado do host.

---

## 3. Orquestração e Setup

### Subir a infraestrutura
``@bash
docker compose up -d
```

### Provisionar Pipeline de Ingestão
``@bash
./setup_pipeline.sh
```

### Provisionar Regras do SIEM Detection Engine
Configura 6 regras ativas com a tag `purple-team`:
``@bash
python3 setup_kibana_rules.py
```

### Provisionar Dashboard Lens SOC
Orguestra o painel executivo com distribuição de códigos HTTP e categorias de ameaça:
``@bash
python3 setup_kibana_dashboard.py
``@

---

## 4. Emulação de Ataques (Red Team)

Execute o simulador para disparar os vetores de teste contra o alvo:
```bash
python3 attack_simulation.py
``@

Cenários cobertos pela simulação á luz do `attack_simulation.py`:
1. **SQL Injection**: Injeção via parâmetro de busca (/rest/products/search?q=' OR 1=1--).
2. **Path Traversal**: Acesso fora do webroot via /public/images/../../../../etc/passwd.
3. **Reflected XSS**: Injeção de payload de script via query string.
4. **Enumeração Sensível**: Fuzzing de endpoints restritos (/.env, /admin, /backup).
5. **BOLA / IDOR**: Acesso direto horizontal a cestas de compras (/rest/basket/<id>).

---

## 5. Validação Defensiva (Blue Team)

### Consultar Alertas Gerados no SIEM
``@bash
curl -s -X POST "http://localhost:9200/.alerts-security.alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "filter": [{ "term": { "kibana.alert.rule.tags": "purple-team" } ]
      }
    },
    "_source": ["@timestamp", "kibana.alert.rule.name", "signal.status"]
  }' | jq '.hits.hits[]._source'
```(
### Acessar o Dashboard SOC no Kibana
Acesse via navegador:
http://localhost:5601/app/dashboards#/view/purple-team-overview
OEF