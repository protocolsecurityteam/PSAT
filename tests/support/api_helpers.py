from unittest.mock import MagicMock


def _mock_session_ctx(mock_session_cls, mock_session):
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)


def _admin_headers() -> dict[str, str]:
    from routers import deps

    return {"X-PSAT-Admin-Key": deps.ADMIN_KEY or ""}
