from pathlib import Path


def test_cipher_catalog_avoids_blanket_do_not_retest_language():
    path = Path("docs/crypto_field_manual/20_cipher_catalog.md")
    text = path.read_text(encoding="utf-8")
    assert "Already proven impossible; do not re-test." not in text


def test_high_visibility_plans_avoid_globalized_periodic_impossibility_language():
    paths = [
        Path("docs/superpowers/plans/2026-03-19-polybius-coordinate-exploit.md"),
        Path("docs/superpowers/specs/2026-03-22-ckm-exhaustive-design.md"),
        Path("docs/superpowers/specs/2026-03-19-rosetta-running-key-design.md"),
        Path("docs/research_questions.md"),
    ]
    banned = (
        "Periodic model proven impossible",
        "ALL periodic keys are proven impossible",
        "periodic keywords are proven impossible",
        "It is non-periodic (proven under direct correspondence)",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for phrase in banned:
            assert phrase not in text, f"{phrase!r} still present in {path}"


def test_retired_null_mask_campaign_is_quarantined():
    paths = [
        Path("scripts/campaigns/f_null_beaufort_exhaustive_v1.py"),
        Path("scripts/campaigns/f_palette_exhaustive_v1.py"),
        Path("scripts/campaigns/f_consensus_null_v1.py"),
        Path("scripts/campaigns/f_argenti_null_rule_v1.py"),
        Path("scripts/campaigns/f_composition_k4_v2.py"),
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "--allow-retired-construct" in text, f"missing guard flag in {path}"
        assert (
            "historical artifact" in text
            or "historical / reproducibility" in text
        ), f"missing historical warning in {path}"
