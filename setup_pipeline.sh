#!/usr/bin/env bash
set -e

ELASTIC_URL="http://localhost:9200"

echo "[*] Configurando Ingest Pipeline: juice-shop-parser..."

curl -s -f -X PUT "${ELASTIC_URL}/_ingest/pipeline/juice-shop-parser" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Parse Juice Shop Logs, HTTP access and Security Exceptions to ECS",
    "processors": [
      {
        "trim": {
          "field": "message",
          "ignore_missing": true
        }
      },
      {
        "grok": {
          "field": "message",
          "patterns": [
            "%{WORD:http.request.method} %{URIPATHPARAM:url.path} %{NUMBER:http.response.status_code:int}",
            "Error: %{WORD:error.type}: %{GREEDYDATA:error.message}",
            "%{GREEDYDATA:event.original}"
          ],
          "ignore_missing": true
        }
      },
      {
        "set": {
          "if": "ctx.error?.type == '\''SQLITE_ERROR'\'' || (ctx.message != null && ctx.message.contains('\''SQLITE_ERROR'\'')) || (ctx.url?.path != null && (ctx.url.path.contains('\''%27'\'') || ctx.url.path.contains('\''--'\'') || ctx.url.path.contains('\''1=1'\'')))",
          "field": "rule.category",
          "value": "threat/sql-injection"
        }
      },
      {
        "set": {
          "if": "ctx.url?.path != null && (ctx.url.path.contains('\''..'\'' ) || ctx.url.path.contains('\''/etc/passwd'\''))",
          "field": "rule.category",
          "value": "threat/path-traversal"
        }
      },
      {
        "set": {
          "if": "ctx.url?.path != null && (ctx.url.path.contains('\''<script>'\'' ) || ctx.url.path.contains('\''%3Cscript%3E'\'') || ctx.url.path.contains('\''javascript:'\'') || ctx.url.path.contains('\''onerror'\''))",
          "field": "rule.category",
          "value": "threat/xss"
        }
      },
      {
        "set": {
          "if": "ctx.http?.response?.status_code != null && (ctx.http.response.status_code == 404 || ctx.http.response.status_code == 403) && ctx.url?.path != null && (ctx.url.path.contains('\''admin'\'') || ctx.url.path.contains('\''/.env'\'') || ctx.url.path.contains('\''backup'\'') || ctx.url.path.contains('\''/.git'\''))",
          "field": "rule.category",
          "value": "threat/enumeration"
        }
      },
      {
        "set": {
          "if": "ctx.url?.path != null && ctx.url.path.matches('\''^/rest/basket/.*'\'') && ctx.http?.request?.method == '\''GET'\''",
          "field": "rule.category",
          "value": "threat/bola"
        }
      }
    ],
    "on_failure": [
      {
        "set": {
          "field": "error.message",
          "value": "{{ _ingest.on_failure_message }}"
        }
      }
    ]
  }'

echo -e "\n[+] Pipeline atualizado com sucesso no Elasticsearch."
