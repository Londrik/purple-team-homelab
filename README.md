# Purple Team Homelab

Laboratório prático para simulação de ataques (Red Team) e análise/monitoramento de logs de segurança em tempo real (Blue Team).

## Arquitetura
* **OWASP Juice Shop**: Aplicação web intencionalmente vulnerável.
* **Filebeat**: Agente coletor de logs dos containers Docker.
* **Elasticsearch**: Motor de busca e indexação de eventos.
* **Kibana**: Interface visual para análise de logs e Dashboards.

## Como Executar
1. Subir os containers:
   ```bash
   docker compose up -d

    Executar a simulação de ataque:
    Bash

    python3 attack_simulation.py

    Acessar o Kibana em http://localhost:5601 e verificar os logs no Discover.
