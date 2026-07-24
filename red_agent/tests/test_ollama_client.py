from unittest.mock import MagicMock, patch

from red_agent.ollama_client import OllamaClient


def test_chat_posts_model_messages_and_tools():
    client = OllamaClient("http://localhost:11434", "qwen2.5:7b")
    fake_response = MagicMock()
    fake_response.json.return_value = {"message": {"role": "assistant", "content": "hi"}}
    fake_response.raise_for_status.return_value = None

    with patch("red_agent.ollama_client.requests.post", return_value=fake_response) as mock_post:
        result = client.chat(messages=[{"role": "user", "content": "hello"}], tools=[])

    assert result == {"message": {"role": "assistant", "content": "hi"}}
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["json"]["model"] == "qwen2.5:7b"
    assert call_kwargs["json"]["messages"] == [{"role": "user", "content": "hello"}]
    assert call_kwargs["json"]["stream"] is False


def test_chat_posts_to_correct_url():
    client = OllamaClient("http://localhost:11434", "qwen2.5:7b")
    fake_response = MagicMock()
    fake_response.json.return_value = {"message": {}}
    fake_response.raise_for_status.return_value = None

    with patch("red_agent.ollama_client.requests.post", return_value=fake_response) as mock_post:
        client.chat(messages=[], tools=[])

    assert mock_post.call_args.args[0] == "http://localhost:11434/api/chat"


def test_chat_raises_on_http_error():
    import requests

    client = OllamaClient("http://localhost:11434", "qwen2.5:7b")
    fake_response = MagicMock()
    fake_response.raise_for_status.side_effect = requests.HTTPError("500 error")

    with patch("red_agent.ollama_client.requests.post", return_value=fake_response):
        try:
            client.chat(messages=[], tools=[])
            assert False, "expected HTTPError"
        except requests.HTTPError:
            pass
