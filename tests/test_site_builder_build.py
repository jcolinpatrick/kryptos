from __future__ import annotations

from ops.site_builder.build import _prepare_output_dir


def test_prepare_output_dir_rotates_unwritable_tree(monkeypatch, tmp_path):
    output_dir = tmp_path / "site"
    output_dir.mkdir()
    (output_dir / "index.html").write_text("old")
    stats_dir = output_dir / "stats"
    stats_dir.mkdir()
    (stats_dir / "index.html").write_text("stats")

    def boom(path):
        raise PermissionError("simulated")

    monkeypatch.setattr("ops.site_builder.build.os.remove", boom)

    _prepare_output_dir(str(output_dir))

    rotated = [p for p in tmp_path.iterdir() if p.name.startswith("site.stale-")]
    assert rotated, "expected stale site directory to be rotated aside"
    assert output_dir.exists()
    assert (output_dir / "stats" / "index.html").read_text() == "stats"
    assert not (output_dir / "index.html").exists()
