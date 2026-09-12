#!/usr/bin/env bash
set -e

echo "[*] Registrando pipeline Ingest 'juice-shop-parser'..."
curl -s -X PUT "http://localhost:9200/_ingest/pipeline/juice-shop-parser" \
  -H 'Content-Type: application/json' \
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
        "if": "ctx.error?.type == '\''SQLITE_ERROR'\'' || (ctx.message != null && ctx.message.contains('\''SQLITE_ERROR'\''))",
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
}' | jq .
