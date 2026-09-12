# Regras de Detecção e Análise Blue Team

## 1. Ciclo de Detecção Purple Team

```mermaid
graph TD
    A[attack_simulation.py] -->|HTTP Request| B[Juice Shop Target]
    B -->|stdout ndjson| C[Filebeat Collector]
    C -->|Pipeline: juice-shop-parser| D[Elasticsearch Ingest Node]
    D -->|Mapeamento ECS| E[(filebeat-* Data Stream)]
    E -->|KQL / ES|QL Queries| F[Kibana SIEM / Detection Rules]
```

---

## 2. Regras de Detecção por Vetor de Ataque

### A. SQL Injection (T1190)

* **KQL (Kibana Query Language)**:
  ```kql
  url.path: (*%27* OR *--* OR *OR%201%3D1* OR *select* OR *union*)
  ```

* **ES|QL (Elasticsearch Query Language)**:
  ```esql
  FROM filebeat-*
  | WHERE url.path LIKE "*%27*" OR url.path LIKE "*--*" OR url.path LIKE "*1=1*"
  | STATS count = COUNT(*) BY http.request.method, url.path, http.response.status_code
  | SORT count DESC
  | LIMIT 20
  ```

* **Objetivo Analítico**: Identificar tentativas de subversão booleana e comentários inline em URIs de consulta e autenticação.

---

### B. Path Traversal / Arbitrary File Read (T1083)

* **KQL (Kibana Query Language)**:
  ```kql
  url.path: (*..%2F* OR *../* OR *etc/passwd* OR *boot.ini*)
  ```

* **ES|QL (Elasticsearch Query Language)**:
  ```esql
  FROM filebeat-*
  | WHERE url.path LIKE "*../*" OR url.path LIKE "*..%2F*" OR url.path LIKE "*etc/passwd*"
  | KEEP @timestamp, http.request.method, url.path, http.response.status_code
  | SORT @timestamp DESC
  | LIMIT 50
  ```

* **Objetivo Analítico**: Flaggear padrões de escape de diretório codificados ou literais apontando para arquivos do sistema host ou container.

---

### C. Enumeração Web / Força Bruta de Rotas (T1595)

* **KQL (Kibana Query Language)**:
  ```kql
  http.response.status_code: (404 OR 403) AND url.path: (*/admin* OR */.env* OR */backup* OR */.git*)
  ```

* **ES|QL (Elasticsearch Query Language - Threshold de Anomalia)**:
  ```esql
  FROM filebeat-*
  | WHERE http.response.status_code == 404 OR http.response.status_code == 403
  | STATS total_erros = COUNT(*) BY http.response.status_code
  | WHERE total_erros > 5
  ```

* **Objetivo Analítico**: Rastrear picos anômalos de respostas `404/403` em uma janela curta, caracterizando varreduras automatizadas por wordlist.

---

## 3. Validação de Regras via Elasticsearch API

Executar consulta ES|QL diretamente no cluster:

```bash
curl -s -X POST "http://localhost:9200/_query?format=txt" \
  -H "Content-Type: application/json" -d '\
{
  "query": "FROM filebeat-* | KEEP @timestamp, http.request.method, url.path, http.response.status_code | LIMIT 10"
}'
```
