"""HTTP behaviour: status codes, both export formats, and persistence."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netaudit import store
from netaudit.parser import MAX_BYTES


def _post(
    client: TestClient,
    fixtures_dir: Path,
    name: str,
    rulepack: str = "auto",
    fail_under: int | None = None,
):
    data = {"rulepack": rulepack}
    if fail_under is not None:
        data["fail_under"] = str(fail_under)
    with open(fixtures_dir / name, "rb") as handle:
        return client.post(
            "/api/scans",
            files={"file": ("cfg.conf", handle, "text/plain")},
            data=data,
        )


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").text == "ok"


def test_index_renders(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Run audit" in response.text


def test_openapi_documents_the_upload(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    content = schema["paths"]["/api/scans"]["post"]["requestBody"]["content"]
    assert "multipart/form-data" in content


def test_scan_returns_findings(client: TestClient, fixtures_dir: Path) -> None:
    response = _post(client, fixtures_dir, "fortigate_bad.conf")
    assert response.status_code == 200
    body = response.json()
    assert body["vendor"] == "fortigate"
    assert body["grade"] in {"D", "E", "F"}
    assert any(f["rule_id"] == "FG-001" for f in body["findings"])


def test_index_lists_recent_scans(client: TestClient, fixtures_dir: Path) -> None:
    _post(client, fixtures_dir, "cisco_bad.conf")
    page = client.get("/")
    assert page.status_code == 200
    assert "cfg.conf" in page.text
    assert client.get("/api/scans").json()["scans"][0]["vendor"] == "cisco"


def test_scan_is_persisted(client: TestClient, fixtures_dir: Path) -> None:
    scan_id = _post(client, fixtures_dir, "cisco_bad.conf").json()["id"]
    record = store.get_scan(scan_id)
    assert record is not None
    assert record["filename"] == "cfg.conf"
    assert isinstance(record["findings"], list)


def test_scan_survives_a_new_request(client: TestClient, fixtures_dir: Path) -> None:
    """The old in-memory dict lost reports between processes; SQLite does not."""

    scan_id = _post(client, fixtures_dir, "cisco_bad.conf").json()["id"]
    assert store.get_scan(scan_id) is not None


def test_fail_under_returns_422(client: TestClient, fixtures_dir: Path) -> None:
    response = _post(client, fixtures_dir, "cisco_bad.conf", fail_under=90)
    assert response.status_code == 422
    assert response.json()["score"] < 90


def test_fail_under_passes(client: TestClient, fixtures_dir: Path) -> None:
    assert _post(client, fixtures_dir, "cisco_good.conf", fail_under=90).status_code == 200


def test_unknown_vendor_returns_415(client: TestClient) -> None:
    response = client.post("/api/scans", files={"file": ("x.conf", b"hello", "text/plain")})
    assert response.status_code == 415


def test_vendor_mismatch_returns_400(client: TestClient, fixtures_dir: Path) -> None:
    response = _post(client, fixtures_dir, "cisco_bad.conf", rulepack="fortigate")
    assert response.status_code == 400
    assert "does not match detected vendor" in response.text


def test_missing_scan_returns_404(client: TestClient) -> None:
    assert client.get("/scans/doesnotexist").status_code == 404
    assert client.get("/scans/doesnotexist/report.md").status_code == 404


def test_broken_rulepack_returns_400(
    client: TestClient, fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rulepack that cannot load is a 400, not a stack trace in the browser."""

    from netaudit import rulepacks

    monkeypatch.setattr(rulepacks, "RULEPACK_DIR", tmp_path)
    response = _post(client, fixtures_dir, "fortigate_bad.conf")
    assert response.status_code == 400
    assert "unknown rulepack" in response.text


def test_html_report_and_exports(client: TestClient, fixtures_dir: Path) -> None:
    scan_id = _post(client, fixtures_dir, "cisco_bad.conf").json()["id"]
    page = client.get(f"/scans/{scan_id}")
    assert page.status_code == 200
    assert "CS-001" in page.text

    markdown = client.get(f"/scans/{scan_id}/report.md")
    assert "CS-001" in markdown.text
    assert "transport input ssh" in markdown.text

    sarif = client.get(f"/scans/{scan_id}/report.sarif")
    assert sarif.headers["content-type"].startswith("application/sarif+json")
    document = sarif.json()
    assert document["version"] == "2.1.0"
    driver = document["runs"][0]["tool"]["driver"]
    assert driver["name"] == "netaudit"
    assert document["runs"][0]["results"]
    assert {r["ruleId"] for r in document["runs"][0]["results"]} <= {
        rule["id"] for rule in driver["rules"]
    }


def test_clean_scan_export_has_no_results(client: TestClient, fixtures_dir: Path) -> None:
    scan_id = _post(client, fixtures_dir, "fortigate_good.conf").json()["id"]
    assert client.get(f"/scans/{scan_id}/report.sarif").json()["runs"][0]["results"] == []
    assert "No violations" in client.get(f"/scans/{scan_id}/report.md").text


def test_form_redirects_to_report(client: TestClient, fixtures_dir: Path) -> None:
    with open(fixtures_dir / "fortigate_good.conf", "rb") as handle:
        response = client.post(
            "/scan",
            files={"file": ("fw.conf", handle, "text/plain")},
            data={"rulepack": "auto"},
            follow_redirects=False,
        )
    assert response.status_code == 303
    redirect = response.headers["location"]
    page = client.get(redirect)
    assert page.status_code == 200
    assert "No violations against the selected rulepack" in page.text


def test_oversize_returns_413(client: TestClient) -> None:
    payload = b"config system global\n" + b"#" * MAX_BYTES
    response = client.post("/api/scans", files={"file": ("big.conf", payload, "text/plain")})
    assert response.status_code == 413


def test_failed_insert_rolls_back() -> None:
    """A partial write must not leave a row behind (see ADR 0002)."""

    store.init_db()
    with pytest.raises(KeyError):
        store.save_scan({"filename": "x.conf"})
    assert store.recent() == []
