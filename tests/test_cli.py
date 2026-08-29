import pytest

from netprobe.cli import build_parser, main


def test_scan_args_parse():
    args = build_parser().parse_args(["scan", "example.com", "-p", "80,443"])
    assert args.command == "scan"
    assert args.host == "example.com"
    assert args.ports == "80,443"


def test_sweep_args_parse():
    args = build_parser().parse_args(["sweep", "10.0.0.0/30", "-p", "22"])
    assert args.command == "sweep"
    assert args.network == "10.0.0.0/30"
    assert args.port == 22


def test_missing_command_exits():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_scan_rejects_bad_port_spec(capsys):
    exit_code = main(["scan", "127.0.0.1", "-p", "not-a-port"])
    assert exit_code == 2
    assert "error:" in capsys.readouterr().err
