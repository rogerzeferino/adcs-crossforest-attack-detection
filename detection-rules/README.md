# Regras de detecção

Regras prontas para os dois backends usados no estudo. São ponto de partida, ajuste nomes de campo, allowlists e IDs ao seu ambiente antes de colocar em produção.

## Estrutura

```
detection-rules/
├── elastic/
│   ├── esc8.eql        # sequencias EQL para ESC8
│   └── queries.kql     # consultas KQL de triagem (ESC8, DCSync, cross-forest)
└── wazuh/
    ├── esc8.xml        # regras ESC8 (4886, 4887, 5145, 4768 PKINIT)
    ├── dcsync.xml      # regras DCSync (4662 com GUIDs de replicacao)
    └── cross-forest.xml# regras de abuso de trust via FSP (4624, 4672)
```

## Pré-requisitos de telemetria

Nenhuma regra funciona sem o evento chegar ao SIEM. Antes de tudo, habilite.

| Fonte | Auditoria | Eventos |
|---|---|---|
| CA (AD CS) | AuditFilter 127 + subcategoria Certification Services | 4886, 4887 |
| DCs | Directory Service Access | 4662 |
| DCs | Logon / Logoff e Special Logon | 4624, 4672 |
| DCs | Detailed File Share | 5145 |
| KDC | Kerberos Authentication Service | 4768 |

## Wazuh

Copiar os XML para `/var/ossec/etc/rules/local_rules.xml` (ou incluir como arquivos de regra), validar com `wazuh-logtest` e reiniciar o manager. Confira que a faixa de IDs (100809 em diante) não colide com regras locais existentes.

## Elastic

As consultas KQL servem para dashboards e detection rules do tipo query. O arquivo EQL serve para regras do tipo EQL sequence. Valide os nomes de campo contra o seu mapping (Winlogbeat, Elastic Agent ou Sysmon via integração), pois variam conforme a integração usada.

## Nota de uso

Os valores `DC01$`, `DC02$` e `FLORESTA_ORIGEM` são placeholders. Substitua pelo inventário real. As allowlists (contas de DC, Azure AD Connect, ferramentas de backup) são o que separa alerta útil de ruído.
