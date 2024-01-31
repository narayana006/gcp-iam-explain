import json
import pathlib

from gcp_iam_explain.cli import main

EX = pathlib.Path(__file__).resolve().parent.parent / "examples"


def test_project_example_text(capsys):
    rc = main([str(EX / "project-policy.json"), "--allowed-domains", "example.com"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "version 3, etag BwYKk4l2Uq0=" in out
    assert "Only when condition 'expires-2025-12-31' is true" in out
    assert "EXTERNAL_MEMBER" in out and "user:contractor.bob@gmail.com" in out


def test_clean_example_exits_zero(capsys):
    assert main([str(EX / "clean-policy.json"), "--allowed-domains", "example.com"]) == 0
    assert "Findings: none" in capsys.readouterr().out


def test_json_output_and_fail_on(capsys):
    rc = main([str(EX / "bucket-policy.json"), "--format", "json", "--fail-on", "critical"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0  # highest finding is high (public object viewer)
    assert data["summary"]["high"] == 1
    assert data["policies"][0]["etag"] == "CAI="


def test_fail_on_never_and_findings_only(capsys):
    rc = main([str(EX / "project-policy.json"), "--fail-on", "never", "--findings-only"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "roles/owner\n  Owner" not in out
    assert "Findings (" in out


def test_stdin_and_errors(capsys, monkeypatch, tmp_path):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO('{"bindings": []}'))
    assert main([]) == 0
    assert main([str(tmp_path / "missing.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("bindings:\n- role: roles/owner\n")
    assert main([str(bad)]) == 2
    assert "use --format=json" in capsys.readouterr().err


def test_multiple_files_total(capsys):
    main([str(EX / "clean-policy.json"), str(EX / "bucket-policy.json")])
    assert "Total: 0 critical, 1 high" in capsys.readouterr().out
