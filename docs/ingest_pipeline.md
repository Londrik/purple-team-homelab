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
2. Mapeamento Formal Elastic Common Schema (ECS)Campo Bruto (Juice Shop / Docker)Destino ECSTipo ESExpressão / Regex GrokMétodo HTTP (GET, POST)http.request.methodkeyword%{WORD:http.request.method}URI / Parâmetros (/rest/products/search?q=)url.pathwildcard / keyword%{URIPATHPARAM:url.path}Código de Retorno (200, 404)http.response.status_codelong%{NUMBER:http.response.status_code:int}Classe de Exceção (SQLITE_ERROR)error.typekeywordError: %{WORD:error.type}Detalhe do Erroerror.messagetext%{GREEDYDATA:error.message}Categoria Purple Teamrule.categorykeywordCondicional Painless (threat/*)3. Algoritmo de Categorização Condicional (Ingest Node)A classificação categórica ocorre em nível de pipeline no cluster Elasticsearch sem overhead de agentes externos:SQL Injection (threat/sql-injection): error.type == "SQLITE_ERROR" ou url.path contém [', --, 1=1]Path Traversal (threat/path-traversal): url.path contém [.., /etc/passwd, %2e%2e]Cross-Site Scripting (threat/xss): url.path contém [<script>, %3Cscript%3E, javascript:, onerror]Web Enumeration (threat/enumeration): status_code em {403, 404} e url.path contém [admin, .env, backup, /.git]BOLA / IDOR (threat/bola): method == "GET" e url.path corresponde a /^\/rest\/basket\/[0-9]+/4. Teste de Bancada via Simulate APIBashcurl -s -X POST "http://localhost:9200/_ingest/pipeline/juice-shop-parser/_simulate" \
  -H "Content-Type: application/json" -d '{
  "docs": [
    {
      "_source": {
        "message": "GET /rest/products/search?q=%27%20OR%201=1-- 200"
      }
    }
  ]
}'
