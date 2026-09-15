#!/usr/bin/env python3
"""Validate Karna rule files against the published JSON Schema.

A Karna rule is a JSON object. Three shapes are accepted:

  * one rule                -> a JSON object          (one `rules_request` entry)
  * a rules pack            -> a JSON array of rules  (a global rules pack file,
                               or the `json` payload published to Redis)
  * a file of rule objects  -> JSON Lines, one rule per line

Usage:
    scripts/validate-rules.py rules/*.json
    scripts/validate-rules.py --schema-dir docs/schema my-rule.json
    cat rule.json | scripts/validate-rules.py -

Requires `jsonschema` (pip install jsonschema). The schemas live in
docs/schema/ and are resolved locally: this runs offline.
"""

import argparse
import json
import pathlib
import sys

RULE_SCHEMA = "karna-rule.schema.json"
PACK_SCHEMA = "karna-rules.schema.json"


def die(msg, code=2):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_validators(schema_dir):
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except ImportError:
        die("the `jsonschema` package is required: pip install jsonschema")

    try:
        rule = json.loads((schema_dir / RULE_SCHEMA).read_text())
        pack = json.loads((schema_dir / PACK_SCHEMA).read_text())
    except FileNotFoundError as exc:
        die(f"schema not found: {exc.filename}")
    except json.JSONDecodeError as exc:
        die(f"schema is not valid JSON: {exc}")

    Draft202012Validator.check_schema(rule)
    Draft202012Validator.check_schema(pack)

    registry = Registry().with_resource(rule["$id"], Resource.from_contents(rule))
    return (
        Draft202012Validator(rule, registry=registry),
        Draft202012Validator(pack, registry=registry),
    )


def pointer(path):
    """Render a jsonschema error path as something you can find in the file."""
    if not path:
        return "<root>"
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else f".{part}"
    return out.lstrip(".")


def render(errors, verbose):
    shown = errors if verbose else errors[:5]
    lines = [f"  {pointer(e.absolute_path)}: {e.message}" for e in shown]
    hidden = len(errors) - len(shown)
    if hidden > 0:
        lines.append(f"  ... and {hidden} more (use -v to see them all)")
    return lines


def validate_document(doc, rule_v, pack_v, verbose):
    """Returns (rules checked, list of printable error lines)."""
    if isinstance(doc, list):
        errors = sorted(pack_v.iter_errors(doc), key=lambda e: list(e.absolute_path))
        return len(doc), render(errors, verbose)

    if isinstance(doc, dict):
        errors = sorted(rule_v.iter_errors(doc), key=lambda e: list(e.absolute_path))
        return 1, render(errors, verbose)

    return 0, ["  <root>: expected a rule object or an array of rules"]


def read_source(path):
    if path == "-":
        return "<stdin>", sys.stdin.read()
    p = pathlib.Path(path)
    if not p.is_file():
        die(f"not a file: {path}")
    return str(p), p.read_text()


def main():
    here = pathlib.Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(
        description="Validate Karna rule files against the published JSON Schema."
    )
    ap.add_argument("files", nargs="+", metavar="FILE",
                    help="rule file, rules pack, or JSON Lines file ('-' for stdin)")
    ap.add_argument("--schema-dir", type=pathlib.Path,
                    default=here.parent / "docs" / "schema",
                    help="directory holding the schema files (default: docs/schema)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print every error instead of the first five per document")
    args = ap.parse_args()

    rule_v, pack_v = load_validators(args.schema_dir)

    total_rules = 0
    failed_files = 0

    for path in args.files:
        label, text = read_source(path)
        stripped = text.strip()
        if not stripped:
            print(f"FAIL {label}")
            print("  <root>: file is empty")
            failed_files += 1
            continue

        docs = []
        try:
            docs.append(json.loads(stripped))
        except json.JSONDecodeError as whole_err:
            # Fall back to JSON Lines: one rule per line.
            try:
                docs = [json.loads(ln) for ln in stripped.splitlines() if ln.strip()]
            except json.JSONDecodeError:
                print(f"FAIL {label}")
                print(f"  <root>: not valid JSON: {whole_err}")
                failed_files += 1
                continue

        n_rules = 0
        problems = []
        for doc in docs:
            checked, errs = validate_document(doc, rule_v, pack_v, args.verbose)
            n_rules += checked
            problems += errs

        total_rules += n_rules
        if problems:
            failed_files += 1
            print(f"FAIL {label} ({n_rules} rule(s))")
            for line in problems:
                print(line)
        else:
            print(f"ok   {label} ({n_rules} rule(s))")

    print()
    if failed_files:
        print(f"{failed_files} file(s) failed, {total_rules} rule(s) checked")
        return 1
    print(f"all good: {total_rules} rule(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
