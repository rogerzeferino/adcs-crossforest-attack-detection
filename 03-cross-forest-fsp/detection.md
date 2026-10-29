# Cross-forest via FSP, detecção

O abuso é um logon administrativo entre florestas. A detecção foca em dois momentos, a enumeração do trust e dos FSPs, e o uso (logon e Pass the Hash) da conta estrangeira contra o DC alvo.

## Sinais de enumeração

- Consultas LDAP ao container `CN=ForeignSecurityPrincipals` a partir de uma origem incomum. Visível em logs de LDAP do DC (evento 1644 com diagnostics ligado, ou telemetria de LDAP via Sysmon/ETW).
- Enumeração de trusts (acesso a atributos de `trustedDomain`), correlacionável com ferramentas de descoberta.

## Sinais de uso, o mais confiável

- **4624 tipo 3 (logon de rede) no DC alvo, com domínio de origem igual à floresta confiável, para uma conta que raramente acessa aquele DC.** Um FSP estrangeiro logando como administrador no DC é o evento central.
- **4672 (Special privileges assigned to new logon) para essa conta estrangeira no DC alvo.** Indica logon com privilégios administrativos.
- **Pass the Hash**, indícios de logon NTLM (4624 com `AuthenticationPackageName` NTLM) para conta que deveria usar Kerberos, especialmente partindo de host não confiável.

## Regra Elastic, KQL

Logon administrativo de conta de outra floresta no DC alvo.

```
event.code:"4624" and winlog.event_data.LogonType:"3" and
  winlog.event_data.TargetDomainName:"<FLORESTA_ORIGEM>" and
  winlog.event_data.AuthenticationPackageName:"NTLM" and
  winlog.computer_name:"<DC_FLORESTA_ALVO>*"
```

Combine com 4672 para confirmar privilégio administrativo.

```
event.code:"4672" and winlog.event_data.SubjectDomainName:"<FLORESTA_ORIGEM>"
```

## Regra Elastic, EQL correlacionada

```
sequence by winlog.event_data.TargetUserName with maxspan=1m
  [ authentication where event.code == "4624" and
      winlog.event_data.LogonType == "3" and
      winlog.event_data.AuthenticationPackageName == "NTLM" ]
  [ any where event.code == "4672" ]
```

Logon de rede NTLM seguido de atribuição de privilégio especial, para o mesmo alvo, em janela curta, é PtH privilegiado.

## Regra Wazuh

Arquivo completo em [../detection-rules/wazuh/cross-forest.xml](../detection-rules/wazuh/cross-forest.xml). Trecho.

```xml
<group name="windows,trust,cross_forest,">

  <rule id="100830" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4624$</field>
    <field name="win.eventdata.logonType">^3$</field>
    <field name="win.eventdata.authenticationPackageName">NTLM</field>
    <field name="win.eventdata.targetDomainName">FLORESTA_ORIGEM</field>
    <description>Logon de rede NTLM de conta de floresta confiável no DC alvo</description>
    <mitre>
      <id>T1550.002</id>
    </mitre>
  </rule>

  <rule id="100831" level="13" if_sid="100830">
    <field name="win.system.eventID">^4672$</field>
    <description>Privilégio administrativo atribuído a conta cross-forest, possível abuso de FSP</description>
    <mitre>
      <id>T1550.002</id>
      <id>T1482</id>
    </mitre>
  </rule>

</group>
```

Ajuste `FLORESTA_ORIGEM` e os nomes de DC ao ambiente.

## Caça

- Levante os FSPs de cada floresta e cruze com a associação a grupos privilegiados (`Builtin\Administrators`, `Domain Admins`, `Enterprise Admins`). Um FSP em grupo privilegiado é achado de hunting por si só, mesmo sem alerta de logon.
- Baseline de quais contas estrangeiras acessam cada DC. Fora da baseline, investigar.

## Limitações

- Confianças legítimas geram logons cross-forest normais. A chave é o contexto, conta estrangeira com privilégio administrativo em um DC, o que quase nunca é legítimo.
- Sem auditoria de logon detalhada (4624/4672) e sem identificar o domínio de origem, o sinal enfraquece. Logon auditing é pré-requisito.
