# Referências

Material público usado como base para o estudo das técnicas e da detecção.

## AD CS e ESC8

- SpecterOps, "Certified Pre-Owned, Abusing Active Directory Certificate Services" (Will Schroeder, Lee Christensen). O paper original que catalogou ESC1 a ESC8.
- Certipy (Oliver Lyak, ly4k), documentação e código. [github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
- Microsoft KB5005413, mitigação de NTLM relay contra AD CS (EPA e Require SSL).
- HackTricks, seção AD CS / ESC8.

## Coerção

- Coercer (p0dalirius), ferramenta de coerção multi-protocolo. [github.com/p0dalirius/Coercer](https://github.com/p0dalirius/Coercer)
- PetitPotam (MS-EFSR) e PrinterBug (MS-RPRN), técnicas de coerção de autenticação.

## DCSync

- MITRE ATT&CK, T1003.006 (OS Credential Dumping, DCSync).
- Impacket, secretsdump. [github.com/fortra/impacket](https://github.com/fortra/impacket)
- Microsoft, permissões DS-Replication-Get-Changes e DS-Replication-Get-Changes-All.

## Confiança entre florestas e FSP

- MITRE ATT&CK, T1482 (Domain Trust Discovery) e T1550.002 (Pass the Hash).
- Microsoft, Security considerations for trusts, SID Filtering e Selective Authentication.
- harmj0y, "A Guide to Attacking Domain Trusts".

## Ferramentas gerais

- NetExec (nxc). [github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)
- nmap, gobuster.

## Detecção

- MITRE ATT&CK, mapeamento de detecção por técnica.
- The DFIR Report, casos de uso de ESC8 e DCSync em incidentes reais.
- Elastic, detection rules para AD (repositório público de regras).
- Wazuh, documentação de regras e decoders para eventos do Windows.

## Certificação

- CyberWarFare Labs, Certified Red Team Specialist v2 (CRTSv2). [cyberwarfare.live](https://cyberwarfare.live)
