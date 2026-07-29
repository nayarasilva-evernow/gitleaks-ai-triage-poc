"""Testes com mocks — falso positivo esperado para o Gitleaks."""

# FALSE POSITIVE (POC): chave de teste / mock, não é credencial real
MOCK_API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN_FIXTURE = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


def test_mock_key_is_placeholder():
    assert MOCK_API_KEY.startswith("sk_test_")
    assert "xxxx" in GITHUB_TOKEN_FIXTURE
