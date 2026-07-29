# Sample App (alvo de teste)

Aplicação mínima **propositalmente insegura** para exercitar o Gitleaks + triagem por IA.

## O que há aqui (de propósito)

| Tipo | Onde | Objetivo |
|------|------|----------|
| Verdadeiro positivo | `app/config.py`, `app/aws_client.py` | Secrets hardcoded realistas — a esteira deve falhar |
| Falso positivo | `tests/test_auth.py` | Mocks de teste |
| Falso positivo | `docs/setup.md` | Exemplos em documentação |
| Falso positivo | `.env.example` | Placeholders óbvios |

> Todos os valores são **fábricas / fictícios**. Não são credenciais reais.
