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

- SELinux Labels: Volumes montados no `docker-compose.yml` (`filebeat.ymlX, `/var/lib/docker/containers`, `/var/run/docker.sock`) utilizam sufixos `:z` e `:ro,z` para viabilizar acesso compartilhado seguro pelo container.
- Permissões Beat: Utilizada a flag `command: ["--strict.perms=false"]` para evitar recusa de execução por permissões de usuário padrão no host (`chmod 644`).
- OtimizA��,o de Recursos: Configurado com restrições de cgroup (`deploy.resources.limits`) e JVU Heap fixa (`-Xmsg -Xmx1g`) para operação estável em hosts com memória física restrita.

## 3. Guia de Execução

**Subir a infraestrutura:**
```bash
docker compose up -d
```

**Inicializar Pipeline Ingest:**
```bash
./setup_pipeline.sh
```

**Simulação de Ataques (Red Team):**
```bash
python3 attack_simulation.py
```

## 4. Engenharia de Deteção (Blue Team)

**SQL Injection Detectado (KQL):**
```kql
rule.category: "threat/sql-injection" or error.type: "SQLITE_ERROR"
``@

**Path Traversal Detectado (KQL):**
```kql
rule.category: "threat/path-traversal" or url.path: *..*
``@

**SumarizA��,o de Ameaças por Categoria e Erro (ES|QL):**
```sql
FROM filebeat-*
| WHERE rule.category IS NOT NULL
| STATS count = COUNT() BY rule.category, error.type, error.message
| SORT count DESC
```
