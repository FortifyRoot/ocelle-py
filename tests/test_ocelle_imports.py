"""Tests for the Ocelle public import surfaces."""


def test_canonical_fortifyroot_ocelle_import_exports_public_api():
    import fortifyroot.ocelle as ocelle

    assert callable(ocelle.init)
    assert callable(ocelle.configure)
    assert ocelle.OcelleConfig is ocelle.FortifyRootConfig
    assert ocelle.Instruments.OPENAI is not None
    assert isinstance(ocelle.__version__, str)


def test_top_level_ocelle_import_exports_public_api():
    import ocelle

    assert callable(ocelle.init)
    assert callable(ocelle.configure)
    assert ocelle.OcelleConfig is ocelle.FortifyRootConfig
    assert ocelle.Instruments.OPENAI is not None
    assert isinstance(ocelle.__version__, str)
