import os
import pytest

from sentrix.dual_llm.anthropic_client import LLMConfig, AnthropicClient, AuthError


class TestAnthropicClient:
    def test_missing_api_key_raises_auth_error(self):
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with pytest.raises(AuthError):
                AnthropicClient(LLMConfig(api_key=""))
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old

    def test_api_key_from_env(self):
        old = os.environ.get("ANTHROPIC_API_KEY")
        os.environ["ANTHROPIC_API_KEY"] = "sk-test-fake-key"
        try:
            client = AnthropicClient(LLMConfig())
            assert client._config.api_key == "sk-test-fake-key"
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            else:
                del os.environ["ANTHROPIC_API_KEY"]

    def test_custom_config_overrides_env(self):
        old = os.environ.get("ANTHROPIC_API_KEY")
        os.environ["ANTHROPIC_API_KEY"] = "sk-env-key"
        try:
            client = AnthropicClient(LLMConfig(api_key="sk-custom-key"))
            assert client._config.api_key == "sk-custom-key"
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            else:
                del os.environ["ANTHROPIC_API_KEY"]

    def test_classify_error_auth(self):
        client = AnthropicClient(LLMConfig(api_key="sk-test"))
        assert client._classify_error(Exception("authentication failed")) == "auth"
        assert client._classify_error(Exception("invalid API key")) == "auth"
        assert client._classify_error(Exception("unauthorized")) == "auth"

    def test_classify_error_rate_limit(self):
        client = AnthropicClient(LLMConfig(api_key="sk-test"))
        assert client._classify_error(Exception("rate limit exceeded")) == "rate_limit"
        assert client._classify_error(Exception("HTTP 429")) == "rate_limit"
        assert client._classify_error(Exception("too many requests")) == "rate_limit"

    def test_classify_error_overloaded(self):
        client = AnthropicClient(LLMConfig(api_key="sk-test"))
        assert client._classify_error(Exception("overloaded")) == "overloaded"
        assert client._classify_error(Exception("HTTP 529")) == "overloaded"
        assert client._classify_error(Exception("capacity")) == "overloaded"

    def test_classify_error_timeout(self):
        client = AnthropicClient(LLMConfig(api_key="sk-test"))
        assert client._classify_error(Exception("timeout")) == "timeout"
        assert client._classify_error(Exception("timed out")) == "timeout"

    def test_config_default_model(self):
        client = AnthropicClient(LLMConfig(api_key="sk-test"))
        assert "claude" in client._config.model
