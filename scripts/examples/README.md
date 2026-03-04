# Example Scripts — Standard Contract

These scripts demonstrate the standardized attack script interface.

## Standard Header

Every script begins with a parseable docstring:

```python
"""
Cipher: Caesar (ROT-N)
Family: substitution
Status: exhausted
Keyspace: 0-25
Last run: 2026-03-04
Best score: 3.0 (crib_score)
"""
```

## Standard `attack()` Contract

```python
def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """
    Returns: [(score, plaintext, method_description), ...]
    Sorted by score descending.
    """
```

## Files

- `e_caesar_standard.py` — Migrated version of `disprove_caesar_rot.py`

## Migration Workflow

1. Add the standard header above the existing docstring
2. Extract the core logic into `attack(ciphertext, **params)`
3. Keep `main()` for backwards-compatible standalone use
4. Update `exhaustion_log.json` with status/best score
