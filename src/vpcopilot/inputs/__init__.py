"""Input adapters: an external artifact in, `Finding` objects out.

Every module here answers the same question in a different dialect — *what is wrong with this
thing, expressed the way the rest of the pipeline already understands?* H1 reads a security
advisory, H2 a dependency manifest, H3 an OpenAPI spec. They share the OSV client and the
advisory→`Finding` mapping, which is why this is a package rather than three `input_*.py` files
importing each other sideways.

**One-directional rule:** modules here may import `schemas`, `harness` and `agents.*`. Nothing here
may import `pipeline` — `pipeline` imports *us*, lazily, inside the branch that needs it.
"""
