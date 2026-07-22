"""API mínima da sample-app."""

from .config import DEBUG, STRIPE_API_KEY


def health() -> dict:
    return {"status": "ok", "debug": DEBUG}


def charge_preview(amount_cents: int) -> dict:
    # Usa a key só para demonstrar o caminho de código (não chama API real)
    masked = STRIPE_API_KEY[:7] + "..." + STRIPE_API_KEY[-4:]
    return {"amount_cents": amount_cents, "key_used": masked}


if __name__ == "__main__":
    print(health())
    print(charge_preview(1000))
