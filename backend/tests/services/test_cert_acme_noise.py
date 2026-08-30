from app.services.certificates import _clean_acme_output


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
