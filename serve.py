"""Server entrypoint: ``python serve.py``.

``api.serve()`` hands uvicorn ``"api:app"``, so ``python api.py`` would run the module body twice (three times under
``--reload``). This file has no body to duplicate.
"""

if __name__ == "__main__":
    from api import serve

    serve()
