from noctua.cli import main


def test_show_prints_the_table(capsys):
    code = main(["show", "examples/rules.yml"])
    out = capsys.readouterr().out
    assert code == 0
    assert "policy drop" in out


def test_lan_ssh_is_allowed(capsys):
    main(["test", "examples/rules.yml", "--proto", "tcp", "--port", "22",
          "--src", "192.168.1.20"])
    assert capsys.readouterr().out.strip() == "allow"


def test_missing_file_gives_error_code(capsys):
    assert main(["show", "nope.yml"]) == 2

def test_apply_without_nft_does_not_blame_the_rules(capsys, monkeypatch):
    monkeypatch.setattr("noctua.cli.run_nft", lambda args, text: 127)
    code = main(["apply", "examples/rules.yml", "--yes"])
    assert code == 127
    assert "rejected" not in capsys.readouterr().err