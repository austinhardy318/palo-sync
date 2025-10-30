import os


def test_diff_fast_path_identical_xml(monkeypatch):
    # Ensure env is set before importing app modules
    os.environ.setdefault("PROD_NMS_HOST", "test-host")
    os.environ.setdefault("PROD_NMS_USERNAME", "user")
    os.environ.setdefault("PROD_NMS_PASSWORD", "pass")
    os.environ.setdefault("LAB_NMS_HOST", "test-host")
    os.environ.setdefault("LAB_NMS_USERNAME", "user")
    os.environ.setdefault("LAB_NMS_PASSWORD", "pass")

    from app.sync_service import SyncService
    svc = SyncService()

    xml = """<config> <devices><entry name=\"x\"/></devices> </config>"""

    # Return identical XML for prod and lab
    monkeypatch.setattr(svc, 'export_config', lambda host, auth, label: xml)

    res = svc.generate_diff()
    assert res.get('success') is True
    diffs = res.get('differences', {})
    assert sum(diffs.values()) == 0


def test_diff_fast_path_ignores_whitespace(monkeypatch):
    os.environ.setdefault("PROD_NMS_HOST", "test-host")
    os.environ.setdefault("PROD_NMS_USERNAME", "user")
    os.environ.setdefault("PROD_NMS_PASSWORD", "pass")
    os.environ.setdefault("LAB_NMS_HOST", "test-host")
    os.environ.setdefault("LAB_NMS_USERNAME", "user")
    os.environ.setdefault("LAB_NMS_PASSWORD", "pass")

    from app.sync_service import SyncService
    svc = SyncService()
    prod_xml = "<config>\n  <devices>\n    <entry name=\"x\"/>\n  </devices>\n</config>\n"
    lab_xml = "<config><devices><entry name=\"x\"/></devices></config>"

    seq = [prod_xml, lab_xml]

    def export_config_stub(host, auth, label):
        return seq.pop(0)

    monkeypatch.setattr(svc, 'export_config', export_config_stub)

    res = svc.generate_diff()
    assert res.get('success') is True
    diffs = res.get('differences', {})
    assert sum(diffs.values()) == 0

