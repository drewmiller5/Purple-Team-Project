import requests


class HttpTool:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def request(self, method: str, path: str, params: dict = None, data: dict = None) -> dict:
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        try:
            resp = self.session.request(
                method.upper(), url, params=params, data=data, timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"error": str(exc)}

        body = resp.text
        truncated = len(body) > 2000
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": body[:2000],
            "body_truncated": truncated,
        }
