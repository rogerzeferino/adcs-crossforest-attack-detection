# ESC8, mitigação e hardening

O ESC8 é eliminado fechando a possibilidade de relay para o Web Enrollment e removendo a coerção que o alimenta. As medidas abaixo estão em ordem de prioridade.

## 1. Forçar HTTPS com Extended Protection for Authentication (EPA)

A correção direta. Com EPA ativo, o token NTLM fica amarrado ao canal TLS e o relay deixa de funcionar.

- No IIS da CA, em cada aplicação de inscrição (`CertSrv`, `CertEnroll`), configurar Authentication, Windows Authentication, Advanced Settings, Extended Protection como **Required**.
- Exigir SSL no site de inscrição e desabilitar o acesso por HTTP.

Referência Microsoft, KB5005413 (mitigação de NTLM relay contra AD CS).

## 2. Desabilitar o Web Enrollment se não for necessário

Muitos ambientes têm o Web Enrollment ligado sem precisar. Se a inscrição é feita por auto-enrollment via Group Policy, remova o role de Web Enrollment (Certification Authority Web Enrollment) da CA.

## 3. Reduzir a coerção

O ESC8 depende de forçar a conta de máquina a autenticar. Sem a coerção, o atacante sem credencial perde o gatilho.

- Aplicar os patches que endurecem MS-EFSR e MS-RPRN (PetitPotam e PrinterBug).
- Desabilitar o serviço Print Spooler em DCs e servidores que não imprimem (fecha MS-RPRN).
- Restringir RPC remoto para EFSRPC onde possível.

## 4. Habilitar Enforcement de signing e EPA no LDAP dos DCs

Fecha vetores de relay vizinhos observados no mesmo ambiente.

- LDAP signing requerido (`LDAPServerIntegrity = 2`).
- LDAP channel binding em When Supported ou Always.

## 5. Ligar a auditoria da CA

Pré-requisito para detectar o ataque. Sem isso, a emissão de certificado passa silenciosa.

```
certutil -setreg CA\AuditFilter 127
net stop certsvc && net start certsvc
```

Em seguida, ligar a subcategoria de auditoria "Certification Services" via Group Policy ou `auditpol`.

```
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
```

## 6. Princípio de menor privilégio nos templates

- Revisar quem pode solicitar certificados com templates que permitem autenticação (por exemplo `Machine`, `DomainController`).
- Remover permissões de enrollment amplas (grupos como Authenticated Users ou Domain Computers em templates sensíveis).
- Habilitar Manager Approval em templates de alto impacto, para que a emissão não seja automática.

## Checklist rápido

- [ ] Web Enrollment só por HTTPS com EPA Required
- [ ] Web Enrollment removido se não usado
- [ ] Patches PetitPotam e PrinterBug aplicados
- [ ] Print Spooler desabilitado em DCs
- [ ] LDAP signing e channel binding em enforcement
- [ ] Auditoria da CA habilitada (AuditFilter)
- [ ] Templates revisados, enrollment restrito, approval em templates críticos

## Mapeamento defensivo

| Mitigação | Referência |
|---|---|
| EPA no Web Enrollment | Microsoft KB5005413 |
| Patches de coerção | CVE associadas a PetitPotam, MS-EFSR hardening |
| Auditoria da CA | AuditFilter 127, subcategoria Certification Services |
| LDAP hardening | ADV190023, LDAP channel binding e signing |
