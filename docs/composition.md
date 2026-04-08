# Composition Search Framework

Multi-layer composition orchestration for Kryptos K4 cryptanalysis.

## Why This Exists

K4 uses two confirmed encryption systems. Every single-layer classical cipher has been exhaustively tested and eliminated (Tier 2). But Tier 2 eliminations explicitly note: **"OPEN as one layer of multi-layer."**

The solution lives in the composition space — ordered combinations of two or more cipher layers. Before this framework, multi-layer testing was done ad hoc via scripts in `scripts/multi_layer/`, each hardcoding a specific pair. There was no systematic way to:

- Track which compositions have been tested
- Apply constraint-based pruning across the space
- Handle both peel orders
- Record coverage for reproducibility

This framework provides disciplined, reproducible composition search.

## Architecture

```
src/kryptos/composition/
├── __init__.py         # Package documentation
├── models.py           # Core dataclasses: LayerDef, LayerInstance, CompositionStack
├── registry.py         # Layer family registry with initial families
├── constraints.py      # Constraint propagation and pruning engine
├── ledger.py           # SQLite campaign/coverage ledger
├── orchestrator.py     # Campaign execution and parallel dispatch
├── scoring_bridge.py   # Bridge to canonical scoring pipeline
└── cli.py              # CLI subcommands
```

### How It Differs From `scripts/multi_layer/`

| Aspect | Ad hoc scripts | Composition framework |
|--------|---------------|----------------------|
| Coverage tracking | None | SQLite ledger |
| Pruning | IC threshold only | Constraint propagation (exact + heuristic) |
| Peel orders | BFS explores all permutations | Explicit outer_first / inner_first |
| Reproducibility | Script-specific | Deterministic hashes, serialized configs |
| Scoring | IC + crib only | Full canonical pipeline (anchored + free) |
| Resume | None | Checkpoint-based resume |
| Parallelism | Single-threaded | multiprocessing.Pool |

The existing scripts remain for provenance and specialized searches (e.g., depth-4 BFS). The composition framework handles systematic two-layer search.

## Core Concepts

### Layers

A **LayerDef** describes a family of transforms (e.g., "additive mask") with semantic metadata:

- `preserves_positions` — does output[i] correspond to input[i]?
- `preserves_unigram_frequencies` — is letter distribution unchanged?
- `changes_effective_key` — does it shift key values?
- etc.

A **LayerInstance** is a specific parameterization (e.g., additive mask with keyword "KRYPTOS").

### Composition Stacks

A **CompositionStack** is an ordered tuple of layers. `layers[0]` is the outermost (applied last during encryption). The stack supports two **peel orders**:

- `outer_first` — invert the outer layer, then the inner
- `inner_first` — invert the inner layer, then the outer

### Constraint Propagation

The pruning engine checks whether a composition can possibly produce valid plaintext *before* expensive evaluation:

**Exact pruning** (mathematically proven):
- Bean equality under additive mask: if `mask[27 % L] != mask[65 % L]`, the composition is impossible
- Length incompatibility

**Heuristic pruning** (statistically motivated):
- IC anomalies in intermediate text
- (More rules can be added as research progresses)

**Not modeled** (cannot determine without testing):
- Complex multi-layer constraint interactions

The distinction is explicit in code and ledger entries.

### Scoring Modes

The framework automatically selects the right scoring path based on layer semantics:

- **Anchored** (all layers preserve positions): `score_candidate()` with fixed crib positions 21-33, 63-73
- **Free** (any transposition layer): `score_candidate_free()` searching anywhere
- **Both** (mixed): run both and take the best

## Supported Layer Families

| Family | Preserves Positions | Preserves Frequencies | Changes Key | Params |
|--------|:------------------:|:--------------------:|:-----------:|--------|
| identity | Yes | Yes | No | (none) |
| additive_mask | Yes | No | Yes | keyword |
| transposition_columnar | No | Yes | No | keyword, width |
| transposition_myszkowski | No | Yes | No | keyword |
| transposition_rail_fence | No | Yes | No | depth |
| transposition_route | No | Yes | No | rows, cols, route_type |
| block_transposition | No | Yes | No | perm, cycle_boustro |

## Running a Campaign

### Preview (dry run)
```bash
PYTHONPATH=src python3 -m kryptos composition preview \
  --name "additive_sweep" \
  --outer additive_mask \
  --inner identity \
  --peel-orders outer_first
```

### Run
```bash
PYTHONPATH=src python3 -m kryptos composition run \
  --name "additive_sweep" \
  --outer additive_mask \
  --inner identity \
  --workers 8 \
  --threshold 10
```

### Report
```bash
PYTHONPATH=src python3 -m kryptos composition report \
  --min-score 10
```

### Coverage
```bash
PYTHONPATH=src python3 -m kryptos composition coverage
```

### Policy file (advanced)
```bash
PYTHONPATH=src python3 -m kryptos composition run \
  --policy-file campaigns/additive_columnar.json
```

Policy JSON example:
```json
{
  "name": "additive_then_columnar",
  "outer_families": ["additive_mask"],
  "inner_families": ["transposition_columnar"],
  "peel_orders": ["outer_first", "inner_first"],
  "outer_params": {"keywords": ["KRYPTOS", "PALIMPSEST"]},
  "inner_params": {"keywords": ["BERLIN", "CLOCK"]},
  "workers": 16,
  "score_threshold": 10,
  "aggressive_pruning": false,
  "db_path": "db/composition_ledger.sqlite"
}
```

## Interpreting Ledger Entries

The SQLite ledger at `db/composition_ledger.sqlite` has four tables:

- **campaigns** — metadata, status, summary stats
- **branches** — individual composition instances with status (open/tested/pruned)
- **composition_results** — scored results for storable branches
- **checkpoints** — resume support

Query examples:
```sql
-- What compositions scored highest?
SELECT score, plaintext, stack_json
FROM composition_results ORDER BY score DESC LIMIT 10;

-- Which families have been tested?
SELECT campaign_key, status, COUNT(*)
FROM branches GROUP BY campaign_key, status;

-- Which branches were pruned and why?
SELECT campaign_key, prune_type, prune_reason, COUNT(*)
FROM branches WHERE status='pruned'
GROUP BY campaign_key, prune_type;
```

## Known Limitations

1. **Two-layer only** — the current orchestrator generates pairs. Extending to 3+ layers requires changes to `enumerate_stacks()`.
2. **Inner layer is passive** — the inner layer is applied but not independently optimized. Future work could add inner-layer parameter search.
3. **No SA/hill-climbing** — the framework does exhaustive enumeration within parameter bounds, not metaheuristic search.
4. **Bean inequalities not yet propagated** — only Bean equality is checked under additive masks. The full 242 inequality set could be propagated but requires more complex logic.
5. **Block transposition parameter space** — the Mengenlehreuhr routes generate ~720 variants per call; may need beam limiting.

## Adding a New Layer Family

1. Write a factory function in `registry.py` following the existing pattern:
   - Return `(forward_fn, inverse_fn)` given a params dict
   - Both must be pure functions `str -> str`
2. Define `LayerSemantics` accurately — wrong semantics cause wrong pruning
3. Register with `register_layer()`
4. Optionally add a parameter generator
5. Add roundtrip tests in `test_composition.py`
6. Update this document

## Migration from `scripts/multi_layer/`

| Script | Framework equivalent |
|--------|---------------------|
| `e_layer_peel_01_cod_method.py` | Composition campaign with additive + transposition families, but framework tests 2 layers while script tests up to depth 4 |
| `e_layer_peel_02_cod_v2.py` | Similar — extended keyword set and route types now available as layer families |
| `e_stego_oracle_01.py` | Not replaced — stego mask discrimination is a different problem than composition search |

The existing scripts are NOT deprecated. They provide complementary capabilities:
- **Scripts**: depth-4 BFS, null extraction, IC-based pruning
- **Framework**: systematic 2-layer coverage, constraint propagation, ledger tracking
