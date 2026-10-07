import subprocess

from app.services.certificates import (
    _acme_env,
    _acme_error_message,
    _clean_acme_output,
    _sanitize_acme_account_conf,
)


def test_clean_acme_output_removes_noise_lines():
    raw = (
        "/root/.acme.sh/acme.sh: line 349: [: INFO: integer expression expected\n"
        "/root/.acme.sh/acme.sh: line 383: [: INFO: integer expression expected\n"
        "[Thu Aug 6 16:49:34 UTC 2026] stronghenge.com: Invalid status. "
        "Verification error details: DNS problem: NXDOMAIN looking up TXT for "
        "_acme-challenge.stronghenge.com - check that a DNS record exists for this domain\n"
        "/root/.acme.sh/acme.sh: line 349: [: INFO: integer expression expected\n"
        "[Thu Aug 6 16:49:42 UTC 2026] Please add '--debug' or '--log' to see more information.\n"
        "[Thu Aug 6 16:49:42 UTC 2026] See: https://github.com/acmesh-official/acme.sh/wiki/How-to-debug-acme.sh\n"
    )
    cleaned = _clean_acme_output(raw)
    assert "integer expression expected" not in cleaned
    assert "Please add '--debug'" not in cleaned
    assert "How-to-debug-acme.sh" not in cleaned
    assert "NXDOMAIN" in cleaned
    assert "stronghenge.com" in cleaned


def test_clean_acme_output_removes_busybox_noise():
    # Alpine's busybox sh phrases the same bad `[ "$SYS_LOG" -ge N ]` test
    # error as "sh: <operand>: out of range".
    raw = (
        "sh: INFO: out of range\n" * 5
        + "[Wed Oct  7 15:36:28 UTC 2026] dyne.systems: Invalid status. "
        "Verification error details: During secondary validation: DNS problem: "
        "NXDOMAIN looking up TXT for _acme-challenge.dyne.systems - check that "
        "a DNS record exists for this domain\n"
        + "sh: INFO: out of range\n" * 5
    )
    cleaned = _clean_acme_output(raw)
    assert "out of range" not in cleaned
    assert "NXDOMAIN" in cleaned
    assert "dyne.systems" in cleaned


def test_clean_acme_output_removes_other_test_errors():
    # Whatever the non-numeric operand ends up being, the shell diagnostic is
    # still "<prefix>: <word>: <test error>" on a line of its own.
    for line in (
        "sh: WARN: out of range",
        "sh: foo: illegal number",
        "dash: 5: DEBUG: unexpected operator",
        "acme.sh: line 291: [: INFO: integer expression expected",
        "test: INFO: bad number",
    ):
        assert _clean_acme_output(line) == line or line not in _clean_acme_output(line + "\nreal error\n")


def test_clean_acme_output_keeps_real_out_of_range_message():
    # A genuine message mentioning "out of range" must survive — the noise
    # pattern requires "<prefix>: <one-word>: <error>" as the whole line.
    raw = "ASN out of range (1-4294967295): 99999999999"
    assert _clean_acme_output(raw) == raw


def test_clean_acme_output_preserves_clean_output():
    raw = "Certificate issued successfully"
    assert _clean_acme_output(raw) == raw


def test_clean_acme_output_handles_empty():
    assert _clean_acme_output("") == ""


def test_clean_acme_output_all_noise_returns_original():
    raw = (
        "/root/.acme.sh/acme.sh: line 349: [: INFO: integer expression expected\n"
        "/root/.acme.sh/acme.sh: line 416: [: INFO: integer expression expected\n"
    )
    # If everything is noise, return the original so we don't show an empty error
    result = _clean_acme_output(raw)
    assert result == raw


def _fake_result(stderr="", stdout="", returncode=1):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_acme_error_message_prefers_cleaned_stderr():
    result = _fake_result(
        stderr="sh: INFO: out of range\n[d] example.com: Invalid status. Verification error details: NXDOMAIN\n",
        stdout="[d] Adding record\n",
    )
    msg = _acme_error_message(result)
    assert "NXDOMAIN" in msg
    assert "out of range" not in msg


def test_acme_error_message_falls_back_to_stdout_when_stderr_is_noise():
    result = _fake_result(
        stderr="sh: INFO: out of range\n" * 100,
        stdout="[d] dns plugin error: invalid token\n",
    )
    msg = _acme_error_message(result)
    assert "invalid token" in msg
    assert "out of range" not in msg


def test_acme_error_message_returns_something_when_all_noise():
    result = _fake_result(stderr="sh: INFO: out of range\n", stdout="")
    assert _acme_error_message(result)


def test_acme_env_drops_non_numeric_syslog(monkeypatch):
    monkeypatch.setenv("SYS_LOG", "INFO")
    env = _acme_env()
    assert "SYS_LOG" not in env


def test_acme_env_keeps_numeric_syslog(monkeypatch):
    monkeypatch.setenv("SYS_LOG", "6")
    assert _acme_env()["SYS_LOG"] == "6"


def test_acme_env_merges_extra(monkeypatch):
    monkeypatch.setenv("SYS_LOG", "INFO")
    env = _acme_env({"CF_Token": "abc"})
    assert env["CF_Token"] == "abc"
    assert "SYS_LOG" not in env


def test_sanitize_account_conf_removes_bad_syslog(tmp_path, monkeypatch):
    from app.services import certificates

    conf_dir = tmp_path / "acme"
    conf_dir.mkdir()
    conf = conf_dir / "account.conf"
    conf.write_text(
        "ACCOUNT_EMAIL='a@b.c'\nSYS_LOG='INFO'\nSAVED_SYS_LOG='debug'\nSAVED_OTHER='keep me'\n"
    )
    monkeypatch.setattr(certificates.settings, "ACME_SH_HOME", str(conf_dir))

    _sanitize_acme_account_conf()

    text = conf.read_text()
    assert "SYS_LOG" not in text
    assert "ACCOUNT_EMAIL='a@b.c'" in text
    assert "SAVED_OTHER='keep me'" in text


def test_sanitize_account_conf_keeps_numeric_syslog(tmp_path, monkeypatch):
    from app.services import certificates

    conf_dir = tmp_path / "acme"
    conf_dir.mkdir()
    conf = conf_dir / "account.conf"
    conf.write_text("SYS_LOG='6'\n")
    monkeypatch.setattr(certificates.settings, "ACME_SH_HOME", str(conf_dir))

    _sanitize_acme_account_conf()

    assert conf.read_text() == "SYS_LOG='6'\n"


def test_sanitize_account_conf_missing_file(tmp_path, monkeypatch):
    from app.services import certificates

    monkeypatch.setattr(certificates.settings, "ACME_SH_HOME", str(tmp_path / "nope"))
    _sanitize_acme_account_conf()  # must not raise
