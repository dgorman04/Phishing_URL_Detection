"""Run the whole pipeline: collect -> integrate -> features -> analysis -> train/evaluate.

    python run_all.py              # everything
    python run_all.py --no-collect # reuse the files already in data/raw
"""
import sys
import time

from src import analysis, collect, features, integrate, train_eval

steps = [("Collect URLs", collect.main), ("Integrate sources", integrate.main),
         ("Extract features", features.main), ("Analyse features", analysis.main),
         ("Train and evaluate", train_eval.main)]
if "--no-collect" in sys.argv:
    steps = steps[1:]

for name, fn in steps:
    print(f"\n=== {name} ===")
    t = time.time()
    fn()
    print(f"({time.time() - t:.0f}s)")
