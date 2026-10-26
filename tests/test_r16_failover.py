"""R16 - Automatic failover (hot standby behind nginx).

These tests check the CONFIGURATION files, because the switch-over itself needs Docker. To see it work:
  docker compose -f docker-compose.yml -f docker-compose.failover.yml up --build -d
  ./scripts/failover_demo.sh
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NGINX = (ROOT / "nginx" / "nginx.conf").read_text()
COMPOSE = (ROOT / "docker-compose.failover.yml").read_text()


def test_nginx_has_a_main_server_and_a_backup_server():
    assert "upstream evp_app" in NGINX
    assert "server app:5000" in NGINX
    assert "server app-standby:5000 backup;" in NGINX


def test_nginx_retries_a_failed_request_on_the_other_server():
    assert "proxy_next_upstream error timeout http_502 http_503 http_504;" in NGINX
    assert "proxy_connect_timeout 2s;" in NGINX                       # a dead server is given up on quickly


def test_nginx_shows_which_copy_answered():
    assert "add_header X-Upstream $upstream_addr always;" in NGINX


def test_standby_is_a_second_running_copy_of_the_same_app():
    assert "app-standby:" in COMPOSE
    standby = COMPOSE.split("app-standby:")[1].split("nginx:")[0]
    assert "build: ." in standby and "env_file: .env" in standby      # same image, same settings, same database
    assert "ports:" not in standby                                     # only reachable through nginx


def test_nginx_container_waits_for_both_copies_and_uses_the_config_file():
    nginx = COMPOSE.split("  nginx:")[1]
    assert "./nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro" in nginx
    assert "- app\n" in nginx and "- app-standby" in nginx


def test_the_shared_compose_file_is_not_changed_by_r16():
    original = (ROOT / "docker-compose.yml").read_text()
    assert "nginx" not in original and "app-standby" not in original   # R16 only ADDS a separate file
