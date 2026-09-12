# Purple Team Homelab 🛡️⚔️

Ambiente de simulação de adversários e engenharia de detecção conteinerizado com **OWASP Juice Shop**, **Elasticsearch**, **Filebeat** e **Kibana**, executado sobre Fedora Linux nativo.

## 📚 Documentação Técnica

A documentação completa de engenharia está centralizada no diretório `docs/`:

- [Arquitetura e Topologia do Homelab](docs/architecture.md): Especificação de contêineres, volumes SELinux (`:z`), permissões do Filebeat e fluxo de telemetria.
- [Pipeline de Ingestão e Mapeamento ECS](docs/ingest_pipeline.md): Configuração do Ingest Pipeline (`juice-shop-parser`), regex Grok e normalização para Elastic Common Schema.
- [Simulação de Ameaças (Red Team)](docs/threat_simulation.md): Mapeamento MITRE ATT&CK (`T1190`, `T1083`, `T1595`), vetores e payloads do script `attack_simulation.py`.
- [Regras de Detecção e Análise Blue Team](docs/detection_rules.md): Regras analíticas em **KQL** e **ES|QL**, thresholds de anomalia e validação de consultas via API.

---

## 🚀 Inicialização Rápida

### 1. Subir a Infraestrutura
```bash
docker compose up -d
```

### 2. Configurar o Ingest Pipeline no Elasticsearch
```bash
chmod +x setup_pipeline.sh
./setup_pipeline.sh
```

### 3. Executar a Simulação de Ataques
```bash
python3 -m venv venv
source venv/bin/activate
pip install requests
python3 attack_simulation.py
```

### 4. Validar Logs no Kibana
Acesse `http://localhost:5601` e consulte o Data Stream `filebeat-*` via **Discover** ou **ES|QL**.
