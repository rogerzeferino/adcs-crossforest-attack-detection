# Cross-forest via FSP, mitigação e hardening

O abuso vem de uma associação de grupo indevida entre florestas somada a credenciais já comprometidas. A defesa é higienizar as associações cross-forest, endurecer o trust e cortar a cadeia que entrega os hashes.

## 1. Auditar Foreign Security Principals em grupos privilegiados

A causa raiz. Nenhuma conta estrangeira deveria estar em `Builtin\Administrators`, `Domain Admins` ou `Enterprise Admins` da outra floresta sem justificativa forte e documentada.

```powershell
# listar FSPs e onde eles são membros
Get-ADObject -Filter 'objectClass -eq "foreignSecurityPrincipal"' -Properties memberOf |
  Select-Object Name, memberOf
```

Remova qualquer FSP de grupos privilegiados. Se o acesso cross-forest for necessário, use um grupo dedicado de menor privilégio, não os grupos built-in administrativos.

## 2. Endurecer o trust

- **SID Filtering (Quarantine)**, impede que SIDs não nativos atravessem o trust, barra abuso de SID history e reduz o risco de pivô. Avaliar caso a caso, pois pode afetar cenários legítimos.
- **Selective Authentication**, em vez de permitir que qualquer principal da floresta confiável autentique em qualquer recurso, exige concessão explícita (`Allowed to authenticate`) por recurso. Fecha o acesso amplo.
- Revisar se o trust precisa mesmo ser bidirecional e transitivo. Reduzir para o mínimo necessário diminui a superfície.

## 3. Cortar a cadeia que leva até aqui

Este estágio só é alcançável porque os módulos 01 e 02 entregaram Domain Admin e os hashes. Portanto.

- Mitigar o ESC8 (módulo [01](../01-adcs-esc8/mitigation.md)) remove a entrada sem credencial.
- Mitigar o DCSync (módulo [02](../02-dcsync/mitigation.md)) remove a extração de hashes, inclusive o da conta FSP.

Hardening em profundidade, cada elo quebrado derruba o seguinte.

## 4. Monitorar a associação e o uso

- Alertar em mudanças de membership de grupos privilegiados, especialmente adição de FSP.
- Alertar em logon administrativo cross-forest em DCs (regras em [detection.md](detection.md)).

## Checklist rápido

- [ ] FSPs auditados, nenhum em grupo administrativo built-in sem justificativa
- [ ] SID Filtering avaliado e aplicado onde couber
- [ ] Selective Authentication em trusts sensíveis
- [ ] Direção e transitividade do trust reduzidas ao mínimo
- [ ] ESC8 e DCSync mitigados (elos anteriores da cadeia)
- [ ] Alerta em mudança de membership de grupos privilegiados
- [ ] Alerta em logon administrativo cross-forest nos DCs

## Mapeamento defensivo

| Mitigação | Referência |
|---|---|
| SID Filtering | Microsoft, securing SID history e quarantine em trusts |
| Selective Authentication | Microsoft, authentication scope em forest trusts |
| Higiene de FSP | revisão de membership de grupos built-in privilegiados |
