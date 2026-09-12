# Engenharia do Ingest Pipeline e Mapeamento ECS

## 1. Fluxo de Parsing e Pipeline Grok

```mermaid
flowchart TD
    RAW[Raw Container Log JSON: campo message] --> TRIM[Processor: Trim Whitespace]
    TRIM --> GROK[Processor: Grok Pattern Matching]
    GROK --> COND1{Match HTTP Access?}
    COND1 -->|Sim| ECS_HTTP[Popula http.request.method, url.path, http.response.status_code]
    COND1 -->|Não| COND2{Match Exception/Error?}
    COND2 -->|Sim| ECS_ERR[Popula error.type, error.message]
    COND2 -->|Não| ORIG[Popula event.original]
    ECS_HTTP --> ENRICH[Processors Condicionais Painless: rule.category]
    ECS_ERR --> ENRICH
    ORIG --> ENRICH
    ENRICH --> OUT[(Data Stream: filebeat-8.12.0)]
    GROK -.->|Exception| ON_FAILURE[Processor: Set error.message fallback]
    ON_FAILURE --> OUT
```

---

## 2. Mapeamento Formal Elastic Common Schema (ECS)

| Campo Bruto (Juice Shop / Docker) | Destino ECS | Tipo ES | Expressão / Regex Grok |
| :--- | :--- | :--- | :--- |
| Método HTTP (`GET`, `POST`) | `http.request.method` | `keyword` | `%{WORD:http.request.method}` |
| URI / Parâmetros (`/rest/products/search?q=`) | `url.path` | `wildcard` / `keyword` | `%{URIPATHPARAM:url.path}` |
| Código de Retorno (`200`, `404`) | `http.response.status_code` | `long` | `%{NUMBER:http.response.status_code:int}` |
| Classe de Exceção (`SQLITE_ERROR`) | `error.type` | `keyword` | `Error: %{WORD:error.type}` |
| Detalhe do Erro | `error.message` | `text` | `%{GREEDYDATA:error.message}` |
| Categoria Purple Team | `rule.category` | `keyword` | Condicional Painless (`threat/*`) |

---

## 3. Algoritmo de Categorização Condicional (Ingest Node)

A classificação categórica ocorre em nível de pipeline no cluster Elasticsearch sem overhead de agentes externos:

* **SQL Injection (`threat/sql-injection`)**:
  ```text
  (ctx.error?.type == "SQLITE_ERROR") || (ctx.message != null && ctx.message.contains("SQLITE_ERROR")) || (ctx.url?.path != null && (ctx.url.path.contains("%27") || ctx.url.path.contains("--") || ctx.url.path.contains("1=1")))
  ```
* **Path Traversal (`threat/path-traversal`)**:
  ```text
  (ctx.url?.path != null && (ctx.url.path.contains("..") || ctx.url.path.contains("/etc/passwd") || ctx.url.path.contains("%2e%2e")))
  ```
* **Cross-Site Scripting (`threat/xss`)**:
  ```text
  (ctx.url?.path != null && (ctx.url.path.contains("<script>") || ctx.url.path.contains("%3Cscript%3E") || ctx.url.path.contains("javascript:") || ctx.url.path.contains("onerror")))
  ```
* **Web Enumeration (`threat/enumeration`)**:
  ```text
  (ctx.http?.response?.status_code != null && (ctx.http.response.status_code == 404 || ctx.http.response.status_code == 403) && ctx.url?.path != null && (ctx.url.path.contains("admin") || ctx.url.path.contains("/.env") || ctx.url.path.contains("backup") || ctx.url.path.contains("/.git")))
  ```
* **BOLA / IDOR (`threat/bola`)**:
  ```text
  (ctx.url?.path != null && ctx.url.path.startsWith("/rest/basket/") && ctx.http?.request?.method == "GET")
  ```

---

## 4. Teste de Bancada via Simulate API

```bash
curl -s -X POST "http://localhost:9200/_ingest/pipeline/juice-shop-parser/_simulate" \
  -H "Content-Type: application/json" -d '\
{
  "docs": [
    {
      "_source": {
        "message": "GET /rest/products/search?q=%27%20OR%201=1-- 200"
      }
    },
    {
      "_source": {
        "message": "GET /rest/basket/1 200"
      }
    }
  ]
}'
```
