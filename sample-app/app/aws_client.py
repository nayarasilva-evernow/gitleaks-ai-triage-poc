"""Cliente AWS mock — access key hardcoded de propósito (TP)."""

# TRUE POSITIVE (POC): credenciais AWS no código-fonte (fictícias, mas no formato real)
AWS_ACCESS_KEY_ID = "AKIA2E3F4G5H6I7J8K9L0M"
AWS_SECRET_ACCESS_KEY = "9xKp2mQ8vL4nR7tY1wE5cB0aZ3sD6fG8hJ2kM4pN"
AWS_REGION = "us-east-1"


def get_s3_client():
    """Retorna um client fictício — só para a POC ter um arquivo 'real'."""
    return {
        "access_key": AWS_ACCESS_KEY_ID,
        "secret_key": AWS_SECRET_ACCESS_KEY,
        "region": AWS_REGION,
    }
