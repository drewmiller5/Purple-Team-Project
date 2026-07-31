from pathlib import Path

import requests


def clear_flags(state_dir: str) -> None:
    Path(state_dir, "go.flag").unlink(missing_ok=True)
    Path(state_dir, "stop.flag").unlink(missing_ok=True)


def stop_round(state_dir: str) -> dict:
    Path(state_dir, "stop.flag").touch()
    return {"stopped": True}


def restart_round(helper_url: str, internal_action_token: str) -> dict:
    try:
        response = requests.post(
            f"{helper_url}/restart-round",
            headers={"X-Internal-Action-Token": internal_action_token},
            timeout=60,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)}
    return response.json()
