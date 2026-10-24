#!/usr/bin/env python3
"""
Lints every Sigma rule in sigma/: valid YAML, required fields present, unique UUIDs,
an allowed level/status, and at least one MITRE ATT&CK technique tag.
Runs in CI on every push (.github/workflows/validate.yml).

Usage:  pip install pyyaml && python3 validate_rules.py
"""
import glob
import re
import sys
import uuid

import yaml

REQUIRED = ["title", "id", "status", "description", "author", "date", "logsource", "detection", "level", "tags"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}

errors, ids = [], {}
files = sorted(glob.glob("sigma/**/*.yml", recursive=True))
for path in files:
    try:
        rule = yaml.safe_load(open(path))
    except yaml.YAMLError as e:
        errors.append(f"{path}: invalid YAML: {e}")
        continue
    for field in REQUIRED:
        if field not in rule:
            errors.append(f"{path}: missing '{field}'")
    try:
        uuid.UUID(str(rule.get("id")))
    except ValueError:
        errors.append(f"{path}: id is not a UUID")
    if rule.get("id") in ids:
        errors.append(f"{path}: duplicate id (also in {ids[rule['id']]})")
    ids[rule.get("id")] = path
    if rule.get("level") not in LEVELS:
        errors.append(f"{path}: bad level '{rule.get('level')}'")
    if rule.get("status") not in STATUSES:
        errors.append(f"{path}: bad status '{rule.get('status')}'")
    if not any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in rule.get("tags", [])):
        errors.append(f"{path}: no ATT&CK technique tag (e.g. attack.t1110)")
    det = rule.get("detection", {})
    if "condition" not in det:
        errors.append(f"{path}: detection has no condition")
    else:
        for name in re.findall(r"[A-Za-z_]\w*", str(det["condition"])):
            if name not in ("and", "or", "not", "of", "them", "all") and name not in det:
                errors.append(f"{path}: condition references undefined selection '{name}'")

for e in errors:
    print(f"[FAIL] {e}")
print(f"\n{len(files)} rule(s) checked, {len(errors)} problem(s)")
sys.exit(1 if errors else 0)
