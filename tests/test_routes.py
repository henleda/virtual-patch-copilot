"""Route-context collection: OpenAPI paths + framework registrations, None when neither exists."""
from vpcopilot.routes import collect_route_context


def test_openapi_paths_extracted(tmp_path):
    (tmp_path / "openapi.yaml").write_text(
        "paths:\n"
        "  /users/v1/register:\n    post: {}\n"
        "  /books/v1/{title}:\n    get: {}\n    delete: {}\n"
    )
    ctx = collect_route_context(str(tmp_path))
    assert ctx is not None
    assert "POST /users/v1/register" in ctx
    assert "/books/v1/{title}" in ctx and "DELETE GET /books/v1/{title}" in ctx


def test_swagger_basepath_prefixed(tmp_path):
    (tmp_path / "swagger.json").write_text('{"basePath": "/api/v2", "paths": {"/pay": {"post": {}}}}')
    ctx = collect_route_context(str(tmp_path))
    assert ctx is not None and "POST /api/v2/pay" in ctx


def test_route_registrations_extracted(tmp_path):
    (tmp_path / "app.py").write_text("app.register_blueprint(users, url_prefix='/users/v1')\n")
    ctx = collect_route_context(str(tmp_path))
    assert ctx is not None and "url_prefix='/users/v1'" in ctx


def test_none_when_no_route_context(tmp_path):
    (tmp_path / "x.py").write_text("print('hello')\n")
    assert collect_route_context(str(tmp_path)) is None
