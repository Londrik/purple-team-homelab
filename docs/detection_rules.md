# Purple Team Detection Rules - OWASP Juice Shop

Este documento consolida as regras analiticas em KQL e ES|QL mapeadas sobre o schema ECS extraidas pelo pipeline juice-shop-parser.

---

## 1. SQL Injection (URI Search & Login Bypass)

### Descricao Tecnica
Detecta tentativas de injecao SQL explorando operadores booleanos (' OR 1=1), caracteres de comentario (--) e UNION SELECT via parametros de URL.

### KQL
url.path: (*%27* or *%20OR%20* or *--* or *UNION* or *1%3D1*) or rule.category: "threat/sql-injection"

### ES|QL
FROM filebeat-*
| WHERE url.path LIKE "*'" OR url.path LIKE "* OR *" OR url.path LIKE "*--*" OR url.path LIKE "*1=1*" OR rule.category == "threat/sql-injection"
| STATS count = COUNT(*) BY url.path, http.response.status_code, http.request.method
| SORT count DESC

---

## 2. Path Traversal / Arbitrary File Read

### Descricao Tecnica
Monitora requisicoes com padroes de navegacao reversa de diretorio (../, %2F..) ou exfiltracao de arquivos como /etc/passwd.

### KQL
url.path: (*..%2F* or *../* or *etc*passwd*) or rule.category: "threat/path-traversal"

### ES|QL
FROM filebeat-*
| WHERE url.path LIKE "*../*" OR url.path LIKE "*..%2F*" OR url.path LIKE "*etc/passwd*" OR rule.category == "threat/path-traversal"
| KEEP @timestamp, http.request.method, url.path, http.response.status_code
| SORT @timestamp DESC

---

## 3. Directory & Endpoint Enumeration (Scanner Spike 404/403)

### Descricao Tecnica
Identifica scanning ativo e fuzzing (.env, .git, backups) por picos de status HTTP 403 e 404.

### KQL
http.response.status_code: (403 or 404)

### ES|QL
FROM filebeat-*
| WHERE http.response.status_code IN (403, 404)
| STATS requests_count = COUNT(*) BY http.response.status_code, url.path
| WHERE requests_count >= 2
| SORT requests_count DESC
