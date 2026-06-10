import json, dataclasses
from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
from kryptosbot.job_dispatcher import check_admissibility, execute

IDX = "h19"
OUTDIR = "results/workflows/k4_dynamic_solve/20260528T222343Z/dispatched_specs"
SPEC = json.load(open(f"{OUTDIR}/spec_{IDX}.json"))

out = {"idx": IDX}
pr = validate_hypothesis_spec(SPEC)
out["valid"] = pr.is_valid
out["validation_errors"] = list(pr.errors)
if pr.is_valid:
    spec = pr.value
    out["spec_hash"] = spec.spec_hash
    adm, reasons = check_admissibility(spec)
    out["admissible"] = bool(adm)
    out["admissibility_reasons"] = list(reasons)
    if adm:
        jr = execute(spec, workers=2)
        d = dataclasses.asdict(jr)
        with open(f"{OUTDIR}/jobresult_{IDX}.json", "w") as fh:
            json.dump(d, fh, indent=2, default=str)
        for k in ("universe_hash","total_tested","total_stored","best_score","best_p_value_vs_null","best_candidate","admissibility_verdict","best_config_bindings"):
            out[k] = d.get(k)
print(json.dumps(out, default=str))
