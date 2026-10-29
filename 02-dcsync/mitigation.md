# DCSync, mitigação e hardening

DCSync não tem patch, é um direito sendo usado. A defesa é controlar quem tem o direito, detectar o uso indevido e cortar as credenciais que levam até ele.

## 1. Auditar e restringir o direito de replicação

Levante todos os principais com `DS-Replication-Get-Changes` e `DS-Replication-Get-Changes-All` no objeto do domínio.

```powershell
# listar ACEs de replicação no objeto do domínio
$root = (Get-ADDomain).DistinguishedName
(Get-Acl "AD:$root").Access |
  Where-Object { $_.ObjectType -in @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') } |
  Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
```

Esperado, apenas Domain Admins, Enterprise Admins, Administrators e as contas de DC (mais, se existir, a conta do Azure AD Connect). Qualquer outro principal deve ser removido.

## 2. Proteger as contas que podem replicar

A via de entrada aqui foi o comprometimento de uma conta de máquina de DC via ESC8. Portanto o hardening do módulo [01](../01-adcs-esc8/mitigation.md) é também mitigação de DCSync. Além disso.

- Tier 0, isolar DCs e contas privilegiadas em um tier administrativo próprio.
- Proteger a conta krbtgt, rotacionar a senha periodicamente (duas vezes, respeitando o intervalo de replicação) reduz a janela de um Golden Ticket já forjado.
- Contas administrativas sem delegação desnecessária, marcar como Sensitive and cannot be delegated.

## 3. Ligar a auditoria que detecta

Pré-requisito da detecção. Sem isso, o ataque é silencioso.

```
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

Garantir a SACL no objeto do domínio para que o acesso às permissões de replicação gere 4662.

## 4. Monitorar continuamente

- Alertar em qualquer 4662 de replicação fora da allowlist de DCs (regras em [detection.md](detection.md)).
- Revisar periodicamente as ACEs do objeto do domínio, mudanças aqui são de alto impacto.

## Checklist rápido

- [ ] ACEs de replicação no domínio auditadas e restritas
- [ ] Modelo de tiers aplicado a DCs e contas privilegiadas
- [ ] krbtgt com rotação definida
- [ ] Directory Service Access auditado nos DCs
- [ ] SACL de replicação presente no objeto do domínio
- [ ] Alerta ativo para 4662 de replicação fora da allowlist
- [ ] Azure AD Connect e ferramentas legítimas documentadas na allowlist
