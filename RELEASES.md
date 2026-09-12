# Roadmap de Releases Técnicas - Purple Team Homelab

Este documento define a progressão arquitetural, releases oficiais e o plano de evolução técnica do laboratório. O foco evolutivo é transformar a infraestrutura de um ambiente de coleta passiva de telemetria em uma plataforma robusta de Detection as Code, automação SIEM e correlação comportamental avançada.


---

## Release Atual

### v1.0.0 - Baseline de Ingestão ECS | 6 Regras SIEM | Dashboard Lens

- **Status**: Produção / Estável
- **Componentes Entregues**:
  - Pipeline de Ingestão `rule-shop-parser` alinhado com Express Router e troubleshooting de exceções SQL.
  - Normalização ECS completa para `http.request.method`, `url.original`, `url.path`, `http.response.status_code` e `rule.category`.
  - 6 Regras de deteção ativas com tags `purple-team` no Kibana Detection Engine (SQLi, Path Traversal, Recon Burst, XSS, BOLA/IDOR, Enumeração Sensível).
  - Painel SOC Lens `purple-team-overview` com agregações de categorias e status HTTP.
  - Suite de emulação `attack_simulation.py` gerando 40+ signals no index `.alerts-security.alerts-*`.

---

## Releases Futuras (Roadmap)

### v1.1.0 - Alertas em Tempo Real e Integração de Action Connectors

- **Scope da Release**:
  1. Implementação de webhooks no Kibana (Action Connectors) voltados a sistemas de mensageria ou WTF (Slack, Telegram, Discord).
  2. Enriquecimento do payload de disparo com metadados crñticos do evento (indicators, severity, rule tags, response status).
  3. Provisionamento declarativo dos connectors via API do Kibana em script automatizado (`setup_kibana_connectors.py`).

- **Justificativa Técnica**:
  - Sistemas SIEM que apenas persistem signals demandam polling manual pelo analista de NOC/SOC, elevando o MTTD (Mean Time to Detect).
  - A criação de actions garante o fluxo de push notification, permitindo validar se a suite ofensiva desperta aeros imediatos na equipe de Resposta a Incidentes.

---

### v1.2.0 - Correlação Temporal Comportamental (EQL / Esquemas MITRE ATT&CKG)

- **Scope da Release**:
  1. Criação de regras de deteção temporais usando EQL (Event Query Language) no Kibana.
  2. Deteção de cadeia de ataque *Kill Chain*: regra que alerta quando um mesmo `client.ip` executa varredura (recon/404 burst) seguida de ataque exploit (SQLi ou Path Traversal) numa janela menor que 120 segundos.
  3. Catalogação das regras deacordo com o framework MITRE ATT&CK (Tactics: Reconnaissance > Initial Access > Discovery).

- **Justificativa Técnica**:
  - Regras baseadas exclusivamente em queries atômicas (Lucene/KQL) geram falsos positivos em exposicão web aberta.
  - A correlação quequencial temporal prova o avanço do adversário nas etapas do ataque, reduzindo o ruído no SIEM e elevando a precisão dos alertas.

---

### v1.3.0 - CI/CD Pipeline: Detections as Code (GitHub Actions)

- **Scope da Release**:
  1. Mount de infraestrutura efêmera em GitHub Actions (Elasticsearch, Filebeat, Juice Shop).
  2. Execução automatizada dos scripts de provisionamento (`setup_pipeline.sh`, `setup_kibana_rules.py`).
  3. Execução do `attack_simulation.py` e validação assertiva de disparo dos alertas antes de aprovar merges na `main`.

---

### v2.0.0 - End-to-End Security Architecture: XPack TLS e RBAC
- **Scope da Release**:
  1. Ativação do XPack Security com certificados TLS (SHA256) gerados via `elastic-certutil`.
  2. Configuração de RBAC (Role-Based Access Control) com credenciais mínimas para o Filebeat e servicos de ingestão.
  3. Transmissão criptografada entre os nos via MTLS.

- **Justificativa Técnica**:
  - A release dedicada a homelab (v1.0.0) roda sem autenticação (`xpack.security: false`) para facilitar desenvolvimento.
  - Em ambientes corporativos, a ausência de TLS permite tampering de pacotes, poisoning de logs e interceptação do trânsito de auditoria.
