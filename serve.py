"""Server entrypoint: ``python serve.py``.

Exists so the launch scripts don't run ``python api.py``. ``api.serve()`` hands
uvicorn the import string ``"api:app"`` (``reload`` requires one), which makes
uvicorn import ``api`` as a module — while ``python api.py`` has already
executed that same file as ``__main__``. The module body would then run twice
per process: a second FastAPI app built with every middleware and router,
immediately discarded, and every module-level boot line logged twice. Under
``--reload`` the reloader adds a third.

This file has no module body to duplicate.
"""

if __name__ == "__main__":
    from api import serve

    serve()
