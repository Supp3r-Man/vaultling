from vault.api import HOST, create_app
from vault.core import Vault


def test_api_flow(tmp_path):
    shares, root = Vault.init(tmp_path / "v", 5, 3)
    client = create_app(tmp_path / "v").test_client()
    auth = {"Authorization": f"Bearer {root}"}

    assert client.get("/v1/status").get_json()["sealed"] is True
    assert client.put("/v1/secret/app/db", json={"value": "x"}, headers=auth).status_code == 503
    for share in shares[:3]:
        last = client.post("/v1/unseal", json={"share": share})
    assert last.get_json()["sealed"] is False

    assert client.get("/v1/secret/app/db").status_code == 401  # no token
    assert client.put("/v1/secret/app/db", json={"value": "hunter2"}, headers=auth).get_json()["version"] == 1
    assert client.get("/v1/secret/app/db", headers=auth).get_json()["value"] == "hunter2"

    token = client.post("/v1/token", json={"policy": "app-read", "ttl": 60}, headers=auth).get_json()["token"]
    reader = {"Authorization": f"Bearer {token}"}
    ok = client.get("/v1/secret/app/db", headers=reader)
    assert ok.status_code == 200 and ok.headers["Cache-Control"] == "no-store"
    assert client.put("/v1/secret/app/db", json={"value": "y"}, headers=reader).status_code == 403
    assert client.get("/v1/secret/other/x", headers=reader).status_code == 403
    assert client.post("/v1/token", json={"policy": "app-read"}, headers=reader).status_code == 403

    assert client.get("/v1/audit/verify", headers=auth).get_json()["ok"] is True


def test_api_rejects_bad_input(tmp_path):
    shares, root = Vault.init(tmp_path / "v", 5, 3)
    client = create_app(tmp_path / "v").test_client()
    auth = {"Authorization": f"Bearer {root}"}
    for share in shares[:3]:
        client.post("/v1/unseal", json={"share": share})
    assert client.get("/v1/secret/app/db?version=abc", headers=auth).status_code == 400
    assert client.put("/v1/secret/app/db", data="not json", headers=auth).status_code == 400
    assert client.put("/v1/secret/Bad/Name", json={"value": "x"}, headers=auth).status_code == 400
    assert client.get("/v1/secret/app/db", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_api_binds_to_loopback_only():
    assert HOST == "127.0.0.1"
