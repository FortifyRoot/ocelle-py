"""Internal FortifyRoot namespace for Ocelle.

The public SDK API is intentionally not exported from this package root.
Use one of the supported public import surfaces instead:

    import fortifyroot.ocelle as ocelle
    import ocelle

The ``fortifyroot`` package root remains so internal modules such as
``fortifyroot._vendor`` and ``fortifyroot._internal`` can keep stable import
paths.
"""

__all__: list[str] = []
