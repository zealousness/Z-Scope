import socketserver

from zscope.web.dashboard_server import DashboardHttpServer


def test_dashboard_server_display_url_for_all_interfaces(tmp_path) -> None:
    server = DashboardHttpServer(
        handler_class=socketserver.BaseRequestHandler,
        web_dir=tmp_path,
        host="0.0.0.0",
        port=9000,
    )

    assert server.display_url() == "http://localhost:9000 (bound to all interfaces)"


def test_dashboard_server_display_url_for_explicit_host(tmp_path) -> None:
    server = DashboardHttpServer(
        handler_class=socketserver.BaseRequestHandler,
        web_dir=tmp_path,
        host="127.0.0.1",
        port=9001,
    )

    assert server.display_url() == "http://127.0.0.1:9001"
