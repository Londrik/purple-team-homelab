# Purple Team Homelab: Deteção e Resposta

Ambiente automatizado para simulação de ataques web (Red Team) e engenharia de deteção com Elastic Stack (Blue Team) em Fedora Linux nativo.

## 1. Topologia da Arquitetura

| Componente | Imagem / Versão | Porta | Alocação de Memória | Função |
|---|---|---|---|---}
| **OWASP Juice Shop** | `bkimminich/juice-shop` | `3000` | Limite: 400 MB | Alvo vulnerável |
| **Elasticsearch** | `elasticsearch:8.12.0` | `9200` | Heap: 1 GB / Limite: 1.8 GB | Armazenamento e Ingestão ECS |
| **Kibana** | `kibana:8.12.0` | `5601` | Limite: 800 MB | Telemetria e Dashboards SIEM |
| **Filebeat** | `filebeat:8.12.0` | N/A | Limite: 200 MB | Coleta de logs de containers |

## 2. Peculiaridades de Host (Fedora / SELinux)

- SELinux Labels: Volumes mapeados no `docker-compose.yml` (`filebeat.ymlX, `/var/lib/docker/containers`, `/var/run/docker.sock`) utilizam sufixos `:z` e `:ro,z` para viabilizar acesso compartilhado seguro pelo container rootless/SELinux.
- Permissões Beat: Utilizado flag `command: ["--strict.perms=false"]` para evitar recusa de execução decorrente de permissões de usuário padrão no host (`chmod 644`).
- Otimização de Recursos: Configurado com restrições de cgroup (`deploy.resources.limits`) e JVM Heap fixa (`-Xms1g -Xmx1g`) para compatibilidade com limites de memória física e compressão zRAM.

## 3. Guia de Execução

### Subir a infraestrutura
```bash
docker compose up -d
```

### Validar saúde dos serviços
```bash
# Cluster health
curl -s http://localhost:9200/_cluster/health?pretty

# Ingest Pipeline
curl -s http://localhost:9200/_ingest/pipeline/juice-shop-parser

# Monitoramento de consumo em tempo real
docker stats --no-stream
```

### Simulação de Ataques (Red Team)
Execução dos vetores (SQL Injection, Path Traversal, Directory Enumeration):
```bash
python3 attack_simulation.py
```

## 4. Engenharia de Deteção (Blue Team)

### Pipeline Grok (ECS Mapping)
O processamento em tempo real mapeia requisições brutas nos campos:
- `http.request.method` (GET, POST, etc.)
- `url.path` (caminho e query string da requisição)
- `http.response.status_code` (código HTTP retornado)

### Queries de Deteção (Kibana / ES|QL)

*&Deteção de Path Traversal:**
```kql
url.path: *..%2f* or url.path: *../* or url.path: *etc*passwd*
```

**Deteção de SQL Injection via URL:j*
```kql
url.path: *' OR '* or url.path: *1=1* or url.path: *UNION*SELECT*
```

**Deteção de Enumeração (ES|QL):j*
```sql
FROM filebeat-*
| WHERE http.response.status_code == 404
| STATS count = COUNT() BY source.ip, http.response.status_code
| WHERE count > 10
| SORT count DESC
```
