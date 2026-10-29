# 01. AD CS ESC8, NTLM Relay para Web Enrollment

> Tática MITRE ATT&CK, T1649 (Steal or Forge Authentication Certificates) e T1557 (Adversary-in-the-Middle)

## O que é

ESC8 é o abuso da interface de Web Enrollment do Active Directory Certificate Services (AD CS) quando ela está exposta por HTTP. A interface de inscrição por web (os endpoints `/certsrv/` e `/certsrv/certfnsh.asp`) aceita autenticação NTLM. Quando essa autenticação não é protegida (sem HTTPS, sem Extended Protection for Authentication), um atacante pode fazer relay de uma autenticação NTLM coagida diretamente para a CA e solicitar um certificado em nome da vítima.

Quando a vítima coagida é a conta de máquina de um Domain Controller, o certificado emitido representa o próprio DC. Isso dá ao atacante uma credencial válida de um objeto com direito de replicação de diretório, abrindo caminho direto para o DCSync (módulo [02](../02-dcsync/)).

## Por que funciona

A falha nasce de uma combinação de três fraquezas, todas de configuração.

1. **Web Enrollment por HTTP.** O endpoint aceita NTLM sobre um canal sem TLS. Sem TLS, não há channel binding, então a autenticação pode ser repassada.
2. **Sem Extended Protection for Authentication (EPA).** Mesmo com HTTPS, se o EPA não estiver ativo, o relay continua viável. O EPA amarra o token NTLM ao canal TLS.
3. **Autenticação de conta de máquina é coagível.** Protocolos como MS-EFSR e MS-RPRN permitem forçar uma conta de máquina (inclusive um DC) a autenticar contra um host arbitrário. A conta de máquina do DC é privilegiada, e o certificado emitido em nome dela herda esse privilégio.

O atacante não precisa de credencial inicial. A coerção MS-EFSR pode ser disparada por uma sessão nula quando o alvo permite, e o relay HTTP não depende de SMB signing (ao contrário do relay SMB).

## Pré-condições

| Pré-condição | Como verificar |
|---|---|
| Endpoint Web Enrollment acessível | `/certsrv/` e `/certsrv/certfnsh.asp` respondem |
| Web Enrollment sem HTTPS, ou HTTPS sem EPA | página serve por `http://` ou EPA desabilitado no IIS |
| Template que o atacante pode solicitar em nome da máquina | `DomainController`, `Machine` ou similar com enrollment permitido |
| Conta de máquina coagível | coerção MS-EFSR/MS-RPRN responde na vítima |
| Caminho de rede da vítima ao listener do atacante | a vítima consegue autenticar de volta no operador |

## Diagrama da técnica

```
 Atacante (listener)            CA / Web Enrollment (HTTP)        DC (vítima)
       │                                 │                            │
       │  1. coage autenticação (MS-EFSR via EfsRpcOpenFileRaw)       │
       │─────────────────────────────────────────────────────────────►
       │                                 │                            │
       │  2. DC autentica de volta no listener (NTLM)                 │
       │◄─────────────────────────────────────────────────────────────
       │                                 │                            │
       │  3. relay do NTLM para /certsrv/certfnsh.asp                 │
       │────────────────────────────────►│                            │
       │                                 │                            │
       │  4. CA emite certificado em nome do DC (template Machine/DC) │
       │◄────────────────────────────────│                            │
       │                                 │                            │
       │  5. atacante tem PFX válido da conta de máquina do DC        │
       ▼                                                               
```

## O que ganhar com isso

Um certificado (arquivo PFX) válido da conta de máquina coagida. Como a conta é de um DC, o próximo passo é converter esse certificado em hash NT via PKINIT e usar a identidade do DC para DCSync.

Detalhes de execução em [attack.md](attack.md). Como detectar em [detection.md](detection.md). Como mitigar em [mitigation.md](mitigation.md).
