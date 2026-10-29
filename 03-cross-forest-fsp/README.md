# 03. Abuso de confiança entre florestas via Foreign Security Principal

> Tática MITRE ATT&CK, T1482 (Domain Trust Discovery) e T1550.002 (Use Alternate Authentication Material, Pass the Hash)

## O que é

Quando duas florestas Active Directory têm uma relação de confiança (trust), um principal de uma floresta pode ser adicionado a grupos da outra. Esse principal aparece na floresta vizinha como um Foreign Security Principal (FSP), um objeto que referencia o SID original por meio da confiança.

O abuso acontece quando um FSP originado da floresta A é membro de um grupo privilegiado na floresta B, por exemplo `Builtin\Administrators`. Nesse caso, comprometer a conta correspondente na floresta A dá controle administrativo direto na floresta B, sem forja de ticket e sem explorar o trust em si. É configuração indevida de associação de grupo entre florestas.

## Por que funciona

- O trust permite que SIDs de uma floresta sejam reconhecidos na outra.
- Grupos locais de domínio (como `Builtin\Administrators`) podem conter membros de florestas confiáveis.
- O FSP é o mecanismo pelo qual o AD materializa essa associação. Ele guarda o SID estrangeiro.

Se a conta estrangeira já foi comprometida (por exemplo via DCSync no módulo [02](../02-dcsync/), que entrega o hash dessa conta), a associação ao grupo privilegiado da outra floresta é imediatamente utilizável.

## Pré-condição no encadeamento

- Domain Admin consolidado na primeira floresta (dos módulos 01 e 02).
- Hash de uma conta que, na segunda floresta, é FSP membro de grupo privilegiado.
- Trust entre as florestas (bidirecional e transitiva amplia o caminho, mas não é estritamente necessária, basta o reconhecimento do SID).

```
Domain Admin na floresta A + hash da conta FSP
   │  FSP é membro de Builtin\Administrators na floresta B
   ▼
Pass the Hash na conta FSP contra o DC da floresta B  ──►  admin na floresta B
```

## O que ganhar com isso

Acesso administrativo ao Domain Controller da segunda floresta, e com ele o comprometimento daquele domínio. É o estágio final da cadeia estudada aqui.

Enumeração e execução em [attack.md](attack.md). Detecção em [detection.md](detection.md). Mitigação em [mitigation.md](mitigation.md).
