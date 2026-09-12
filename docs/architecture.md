# Arquitetura e Engenharia do Homelab (Purple Team)

## 1. Topologia da Infraestrutura

Ambiente conteinerizado via Docker Compose em host Fedora Linux nativo.

```text
+-------------------------------------------------------------------------------+
| HOST: Fedora Linux (SELinux Enforcing)                                        |
|                                                                               |
|  [ attack_simulation.py ]                                                     |
|           │                                                                   |
|           ▼ (HTTP Port 3000)                                                  |
|  +─────────────────+         +──────────────────────────────+                 |
|  | OWASP Juice     |         | Filebeat 8.12.0              |                 |
|  | Shop            |         | - Run as: root               |                 |
|  | (Target)        |         | - strict.perms: false        |                 |
|  +────────┬────────+         +──────────────┬───────────────+                 |
|           │ stdout                          ▲                                 |
|           ▼                                 │ Read JSON Logs                  |
|  /var/lib/docker/containers/<id>/<id>-json.log (:ro,z)                        |
|                                             │                                 |
|                                             ▼ (HTTP Bulk Ingest Port 9200)    |
|                              +──────────────────────────────+                 |
|                              | Elasticsearch 8.12.0         |                 |
|                              | - Ingest: juice-shop-parser  |                 |
|                              | - Data Stream: filebeat-*    |                 |
|                              +──────────────┬───────────────+                 |
|                                             │                                 |
|                                             ▼ (Query Port 5601)               |
|                              +──────────────────────────────+                 |
|                              | Kibana 8.12.0 (SIEM/Analytics)                 |
|                              +──────────────────────────────+                 |
+-------------------------------------------------------------------------------+
```

---

## 2. Componentes e Parâmetros Operacionais

| Serviço | Contêiner / Imagem | Portas | Configurações Críticas |
| :--- | :--- | :--- | :--- |
| **Juice Shop** | `bkimminich/juice-shop:latest` | `3000:3000` | Alvo vulnerável (Node.js/Express). Emite logs de acesso via `stdout`. |
| **Filebeat** | `docker.elastic.co/beats/filebeat:8.12.0` | N/A | `user: root`, flag `--strict.perms=false`. Coleta `/var/lib/docker/containers/*/*.log` com parser `ndjson`. |
| **Elasticsearch**| `docker.elastic.co/elasticsearch/elasticsearch:8.12.0` | `9200:9200` | `discovery.type=single-node`, `xpack.security.enabled=false`. Executa Ingest Pipeline `juice-shop-parser`. |
| **Kibana** | `docker.elastic.co/kibana/kibana:8.12.0` | `5601:5601` | Interface analítica conectada via `http://elasticsearch:9200`. |

---

## 3. Peculiaridades de Host (Fedora Linux & SELinux)

1. **SELinux Volume Relabeling (`:z` / `:ro,z`)**:
   - As montagens bind do host (`/var/run/docker.sock`, `/var/lib/docker/containers` e `./filebeat.yml`) exigem o sufixo `:z` para compartilhamento de contexto `container_file_t`. Sem isso, o contêiner do Filebeat recebe `Permission Denied` em SELinux enforcing.
2. **Filebeat Permissions**:
   - No Fedora nativo, os arquivos pertencem ao UID/GID do usuário comum (`henry`). O Filebeat exige `chmod 644` no host e o parâmetro `--strict.perms=false` no comando do `docker-compose.yml` para evitar bloqueios no boot.

---

## 4. Pipeline de Ingestão e Mapeamento ECS

O parsing ocorre no nó de ingestão antes da escrita no disco via pipeline `juice-shop-parser`:

* **Input Log**: Capturado do campo `log` gerado pelo driver json-file do Docker.
* **Processador Grok**:
  - Extrai verbo HTTP -> `http.request.method`
  - Extrai URI solicitada -> `url.path`
  - Extrai código de status -> `http.response.status_code` (cast para inteiro)
* **Tratamento de Erros**:
  - Cláusula `on_failure` direciona exceções de parsing para o campo `error.message`, mantendo o documento indexado para auditoria de falha.
