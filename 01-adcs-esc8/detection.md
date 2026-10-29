# ESC8, detecção

ESC8 deixa rastro em três lugares. Na CA (pedido e emissão de certificado), no DC vítima (coerção e logon de volta) e no uso posterior do certificado (autenticação PKINIT). A detecção mais confiável correlaciona a emissão de certificado para uma conta de máquina com uma solicitação vinda de um IP que não é a própria máquina.

## Telemetria necessária

| Fonte | O que habilitar |
|---|---|
| CA (AD CS) | Auditoria de "Issue and manage certificate requests". Gera 4886 (requisição recebida) e 4887 (certificado emitido) |
| DC vítima | Logon de rede 4624 tipo 3, e acesso a named pipe 5145 (pipe `efsrpc`, `lsarpc`, `samr`) |
| DC (KDC) | 4768 (TGT) com pré-autenticação por certificado (PKINIT) |
| IIS da CA | Logs de acesso a `/certsrv/certfnsh.asp` |

## Sinais de alto valor

1. **4887 na CA, certificado emitido para uma conta de máquina, requester vindo de um IP diferente do host da própria máquina.** Numa inscrição legítima, o DC solicita o próprio certificado a partir do IP do DC. No ESC8, o `Requester` é a conta de máquina, mas a conexão HTTP vem do IP do operador.
2. **Autenticação PKINIT (4768 com Certificate Information preenchido) para uma conta de máquina logo após a emissão.** Conta de máquina raramente autentica por certificado.
3. **Coerção, 5145 no DC para o pipe `efsrpc` (ou `lsarpc`) a partir de um host interno não esperado, com sessão anônima.**

## Regra Elastic, EQL

Certificado emitido logo após logon de rede anômalo na CA. Ajuste os nomes de campo ao seu ECS mapping.

```
sequence by winlog.computer_name with maxspan=2m
  [ authentication where event.code == "4624" and
      winlog.event_data.LogonType == "3" and
      winlog.event_data.TargetUserName : "*$" ]
  [ any where event.code == "4887" and
      winlog.event_data.Requester : "*$" ]
```

Versão KQL para alerta simples na emissão a conta de máquina, para triagem.

```
event.code:"4887" and winlog.event_data.Requester:*$ and
  not winlog.event_data.Requester:(DC01$ or DC02$)
```

A exclusão dos próprios DCs reduz falso positivo de renovação legítima. Refine a lista conforme o inventário.

## Regra Elastic para PKINIT de conta de máquina

```
authentication where event.code == "4768" and
  winlog.event_data.TargetUserName : "*$" and
  winlog.event_data.CertificatethumbPrint != null
```

Um TGT emitido com certificado para uma conta de máquina é raro em operação normal e merece investigação.

## Regra Wazuh, coerção e emissão suspeita

Arquivo completo em [../detection-rules/wazuh/esc8.xml](../detection-rules/wazuh/esc8.xml). Trecho principal.

```xml
<group name="windows,adcs,esc8,">

  <!-- Certificado emitido pela CA para uma conta de máquina -->
  <rule id="100810" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4887$</field>
    <field name="win.eventdata.requester">\$$</field>
    <description>AD CS, certificado emitido para conta de máquina (possível ESC8)</description>
    <mitre>
      <id>T1649</id>
    </mitre>
  </rule>

  <!-- Acesso ao pipe EFSRPC no DC, indício de coerção MS-EFSR -->
  <rule id="100811" level="8">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^5145$</field>
    <field name="win.eventdata.shareName">\\\\\*\\IPC\$</field>
    <field name="win.eventdata.relativeTargetName">efsrpc</field>
    <description>Acesso ao named pipe efsrpc no DC, possível coerção MS-EFSR</description>
    <mitre>
      <id>T1557</id>
    </mitre>
  </rule>

  <!-- Correlação, coerção seguida de emissão em janela curta -->
  <rule id="100812" level="13" frequency="2" timeframe="120">
    <if_matched_group>adcs</if_matched_group>
    <description>Cadeia ESC8 provável, coerção e emissão de certificado correlacionadas</description>
    <mitre>
      <id>T1649</id>
      <id>T1557</id>
    </mitre>
  </rule>

</group>
```

## Caça (threat hunting)

Procure no histórico da CA por certificados emitidos a contas de máquina cujo IP de origem da requisição HTTP não corresponda ao IP da máquina. No IIS da CA, correlacione os acessos a `/certsrv/certfnsh.asp` com o `c-ip` e cruze com o inventário de DNS.

```
# pseudo-consulta no log do IIS da CA
cs-uri-stem = /certsrv/certfnsh.asp
  AND c-ip NOT IN (lista de IPs de DCs e servidores autorizados)
```

## Limitações

A detecção por 4887 depende de a auditoria da CA estar ligada, o que muitas vezes não está por padrão. Sem ela, o sinal mais robusto que sobra é o PKINIT de conta de máquina (4768 com certificado) e a coerção (5145 no pipe efsrpc). Ligar a auditoria da CA é o primeiro passo defensivo, detalhado em [mitigation.md](mitigation.md).
