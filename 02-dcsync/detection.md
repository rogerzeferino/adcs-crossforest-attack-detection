# DCSync, detecção

DCSync é uma replicação de diretório. A detecção se baseia em identificar replicação (`DRSUAPI DsGetNCChanges`) vinda de um principal que não é um Domain Controller legítimo.

## O sinal central

Evento **4662** no DC, operação sobre o objeto do domínio com acesso às permissões estendidas de replicação. Os GUIDs que importam.

| GUID | Permissão |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

A regra de ouro, um 4662 com esses GUIDs cujo `SubjectUserName` **não** seja uma conta de máquina de DC conhecida é DCSync suspeito.

## Telemetria necessária

- Auditoria de Directory Service Access ligada nos DCs (gera 4662).
- SACL no objeto do domínio incluindo as permissões de replicação (sem isso o 4662 não dispara para esses GUIDs).

```
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

## Regra Elastic, KQL

```
event.code:"4662" and
  winlog.event_data.Properties:(*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* or
                                *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*) and
  not winlog.event_data.SubjectUserName:(DC01$ or DC02$)
```

Mantenha a lista de contas de DC atualizada conforme o inventário. Contas fora dessa lista acessando replicação são o alerta.

## Regra Elastic, EQL com foco em conta de usuário

```
any where event.code == "4662" and
  winlog.event_data.Properties : "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" and
  not winlog.event_data.SubjectUserName : "*$"
```

Essa variante foca em contas de usuário (sem `$`) exercendo replicação, cenário quase sempre malicioso, já que replicação legítima parte de contas de máquina de DC.

## Regra Wazuh

Arquivo completo em [../detection-rules/wazuh/dcsync.xml](../detection-rules/wazuh/dcsync.xml). Trecho.

```xml
<group name="windows,dcsync,">

  <rule id="100820" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4662$</field>
    <field name="win.eventdata.properties">1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</field>
    <description>Replicação de diretório solicitada (DS-Replication-Get-Changes-All), possível DCSync</description>
    <mitre>
      <id>T1003.006</id>
    </mitre>
  </rule>

  <!-- Eleva quando o solicitante não é conta de máquina -->
  <rule id="100821" level="14">
    <if_sid>100820</if_sid>
    <field name="win.eventdata.subjectUserName">^(?!.*\$).*$</field>
    <description>DCSync por conta de usuário (não conta de máquina de DC), alta suspeita</description>
    <mitre>
      <id>T1003.006</id>
    </mitre>
  </rule>

</group>
```

## Caça

- Baseline das contas que legitimamente replicam (apenas contas de máquina de DC e, em casos específicos, Azure AD Connect). Qualquer principal fora dessa baseline é candidato a investigação.
- Correlacione um 4662 de replicação suspeito com a origem de rede. Replicação legítima ocorre entre DCs; uma origem que não é DC é forte indício.
- Fluxo de rede, tráfego DRSUAPI (RPC) de um host que não é DC para um DC.

## Limitações e falso positivo

- Azure AD Connect (conta MSOL_) replica legitimamente. Inclua-a na allowlist.
- Ferramentas de backup ou migração podem exercer replicação. Documente-as.
- Sem a SACL correta no objeto do domínio, o 4662 não captura o acesso de replicação. Validar a SACL é parte do hardening em [mitigation.md](mitigation.md).
