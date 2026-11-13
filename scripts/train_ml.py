"""Train the RandomForest second-opinion model on the synthetic TRAIN split.

python scripts/train_ml.py
(The app also does this automatically on first start if no compatible model exists.)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.model_selection import StratifiedKFold, cross_val_score  # noqa: E402

from rewa import config  # noqa: E402
from rewa.features import FEATURE_NAMES  # noqa: E402
from rewa.training import train_default_model  # noqa: E402


def main():
    _, imp, tr = train_default_model()
    cv = cross_val_score(RandomForestClassifier(n_estimators=300, max_depth=5, min_samples_leaf=2, class_weight="balanced", random_state=7),
                         tr[FEATURE_NAMES], tr["is_ransomware"], cv=StratifiedKFold(5, shuffle=True, random_state=7), scoring="f1")
    out = {"train_hosts": len(tr), "cv_f1_mean": round(float(cv.mean()), 4), "cv_f1_std": round(float(cv.std()), 4), "feature_importance": imp}
    (config.MODEL_DIR / "rf_training_summary.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
