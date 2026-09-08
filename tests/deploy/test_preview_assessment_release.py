"""Preview releases import old Assessment rows only before contraction."""

from deploy.preview import assessment_release


def test_revision_ancestry_detects_the_contraction():
    assert assessment_release._contains_contraction("e27a490bc381") is False
    assert assessment_release._contains_contraction(assessment_release.CONTRACTION) is True


def test_pre_cutover_release_expands_imports_and_contracts(monkeypatch):
    calls = []
    monkeypatch.setattr(assessment_release, "_current_revision", lambda: "e27a490bc381")
    monkeypatch.setattr(assessment_release, "_contains_contraction", lambda _revision: False)
    monkeypatch.setattr(assessment_release, "_run", lambda *args: calls.append(args))

    assessment_release.release()

    assert calls == [
        ("alembic", "upgrade", assessment_release.EXPANSION),
        ("services.assessment.migrate",),
        ("alembic", "-x", "assessment_cutover=stopped", "upgrade", "head"),
    ]


def test_post_cutover_release_uses_normal_upgrade(monkeypatch):
    calls = []
    monkeypatch.setattr(assessment_release, "_current_revision", lambda: assessment_release.CONTRACTION)
    monkeypatch.setattr(assessment_release, "_contains_contraction", lambda _revision: True)
    monkeypatch.setattr(assessment_release, "_run", lambda *args: calls.append(args))

    assessment_release.release()

    assert calls == [("alembic", "upgrade", "head")]
