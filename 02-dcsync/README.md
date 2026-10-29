# 02. DCSync

> Tática MITRE ATT&CK, T1003.006 (OS Credential Dumping, DCSync)

## O que é

DCSync abusa do protocolo de replicação do Active Directory (MS-DRSR, Directory Replication Service). Um principal com direito de replicação pode pedir a um Domain Controller que replique os segredos do domínio, exatamente como um DC faz com outro DC. O resultado é o dump dos hashes de todas as contas, incluindo Administrator (RID 500) e krbtgt.

Não é exploração de vulnerabilidade. É o uso legítimo de um direito, por quem não deveria tê-lo. Por isso a defesa mora no controle de quem tem o direito e na detecção de replicação a partir de origens não autorizadas.

## Por que funciona

A replicação de diretório é uma função central do AD. O direito que a habilita é expresso por duas permissões estendidas no objeto do domínio.

- `DS-Replication-Get-Changes` (GUID 1131f6aa-...)
- `DS-Replication-Get-Changes-All` (GUID 1131f6ad-...)

Qualquer principal que acumule essas permissões pode executar DCSync. Por padrão, as têm Domain Admins, Enterprise Admins e as contas de máquina dos próprios DCs. É exatamente por isso que uma identidade de conta de máquina de DC, obtida no módulo [01](../01-adcs-esc8/), habilita o ataque.

## Pré-condição no encadeamento

Vem do ESC8. Com o hash NT da conta de máquina do DC em mãos, o atacante tem uma identidade com direito de replicação. O DCSync é a monetização desse acesso.

```
hash NT da conta de máquina do DC  ──►  DCSync  ──►  hashes do domínio
```

## O que ganhar com isso

- Hash NTLM da conta Administrator (RID 500), para Pass the Hash imediato.
- Hash da conta krbtgt, para forja de Golden Ticket e persistência de longo prazo.
- Hashes de contas de trust (por exemplo a conta de confiança entre florestas), insumo para o pivô cross-forest do módulo [03](../03-cross-forest-fsp/).

Execução em [attack.md](attack.md). Detecção em [detection.md](detection.md). Mitigação em [mitigation.md](mitigation.md).
