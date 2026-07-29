"""Configuração da sample-app — contém secret hardcoded de propósito (TP)."""

import os

# TRUE POSITIVE (POC): API key hardcoded — NÃO faça isso em produção
STRIPE_API_KEY = "sk_live_51HqP2wK8mN3vR7tY9uJ4bL6cX1zA0eF2gH5iD8oQ3wE"

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://app:changeme@localhost:5432/sample",
)

DEBUG = True
