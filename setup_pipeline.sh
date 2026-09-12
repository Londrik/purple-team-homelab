#!/usr/bin/env bash
set -e

ELASTIC_URL="${ELASTIC_URL:-http://localhost:9200}"

echo "[*] Aguardando Elasticsearch em ${ELASTIC_URL}..."
until curl -s -f "${ELASTIC_URL}/_cluster/health" > /dev/null 2>&1; do
  sleep 2
done

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
            "(?:%{IPORHOST:client.ip}\\s+-\\s+-\\s+\\[[^\\]]+\\]\\s+\")?%{WORD:http.request.method}\\s+%{NOTSPACE:url.original}\\s+(?:HTTP/%{NUMBER})?\"?\\s+%{NUMBER:http.response.status_code:int}",
            "%{WORD:http.request.method}\\s+%{NOTSPACE:url.original}\\s+%{NUMBER:http.response.status_code:int}",
            "Error:\\s+%{WORD:error.type}:\\s+%{GREEDYDATA:error.message}",
            "%{GREEDYDATA:event.original}"
          ],
          "ignore_missing": true
        }
      },
      {
        "set": {
          "field": "url.path",
          "copy_from": "url.original",
          "if": "ctx.url?.original != null && ctx.url?.path == null"
        }
      },
      {
        "set": {
          "if": "ctx.error?.type == '\''SQLITE_ERROR'\'' || (ctx.message != null && ctx.message.contains('\''SQLITE_ERROR'\'')) || (ctx.url?.original != null && (ctx.url.original.toLowerCase().contains('\''%27'\'') || ctx.url.original.toLowerCase().contains('\''--'\'') || ctx.url.original.toLowerCase().contains('\''1=1'\'') || ctx.url.original.toLowerCase().contains('\''union'\'') || ctx.url.original.toLowerCase().contains('\''select'\'')))",
          "field": "rule.category",
          "value": "threat/sql-injection"
        }
      },
      {
        "set": {
          "if": "ctx.url?.original != null && (ctx.url.original.contains('\''..'\'') || ctx.url.original.toLowerCase().contains('\''%2e%2e'\'') || ctx.url.original.contains('\''/etc/passwd'\''))",
          "field": "rule.category",
          "value": "threat/path-traversal"
        }
      },
      {
        "set": {
          "if": "ctx.url?.original != null && (ctx.url.original.toLowerCase().contains('\''<script>'\'') || ctx.url.original.toLowerCase().contains('\''%3cscript%3e'\'') || ctx.url.original.toLowerCase().contains('\''javascript:'\'') || ctx.url.original.toLowerCase().contains('\''onerror'\''))",
          "field": "rule.category",
          "value": "threat/xss"
        }
      },
      {
        "set": {
          "if": "ctx.http?.response?.status_code != null && (ctx.http.response.status_code == 404 || ctx.http.response.status_code == 403) && ctx.url?.original != null && (ctx.url.original.toLowerCase().contains('\''admin'\'') || ctx.url.original.toLowerCase().contains('\''/.env'\'') || ctx.url.original.toLowerCase().contains('\''backup'\'') || ctx.url.original.toLowerCase().contains('\''/.git'\''))",
          "field": "rule.category",
          "value": "threat/enumeration"
        }
      },
      {
        "set": {
          "if": "ctx.url?.original != null && ctx.url.original.startsWith('\''/rest/basket/'\'') && ctx.http?.request?.method == '\''GET'\''",
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

echo -e "\n[+] Pipeline juice-shop-parser configurado com sucesso."
