# Purple Team Homelab

Laboratório integrado de simulação de ameaças, coleta de telemetria conteinerizada e engenharia de detecção em ambiente Fedora Linux nativo.

## Documentação Técnica

- [docs/architecture.md](docs/architecture.md): Topologia de rede, bind mounts, contexto de segurança SELinux (`:z`) e cálculo de latência de ingestão.
- [docs/ingest_pipeline.md](docs/ingest_pipeline.md): Especificação do Ingest Pipeline (`juice-shop-parser`), mappings ECS e condicionais Grok/Painless.
- [docs/threat_simulation.md](docs/threat_simulation.md): Mapeamento MITRE ATT&CK (`T1190`, `T1083`, `T1059.007`, `T1595.003`), vetores e taxas de requisição.
- [docs/detection_rules.md](docs/detection_rules.md): Consultas analíticas KQL/ES|QL, regras de anomalia e formulação matemática de cobertura ($C_{detection}$).

## Inicialização Operacional

```bash
docker compose up -d
./setup_pipeline.sh
python3 attack_simulation.py
```
