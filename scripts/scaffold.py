"""Scaffold new Analyzer/Responder/Detector from templates.

Usage (generic):
  poe new -- --kind analyzer --name Shodan

Convenience tasks:
  poe new-analyzer -- --name Shodan
  poe new-responder -- --name BlockIp
  poe new-detector -- --name MyType
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "examples" / "_templates"


def to_snake(name: str) -> str:
    s = re.sub(r"[^0-9A-Za-z]+", " ", name).strip()
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return "_".join(s.lower().split())


def to_pascal(name: str) -> str:
    parts = re.sub(r"[^0-9A-Za-z]+", " ", name).strip().split()
    return "".join(p.capitalize() for p in parts)


def read_template(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def write_file(path: pathlib.Path, content: str, *, force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise SystemExit(f"Refusing to overwrite existing file: {path}. Use --force to override.")
    path.write_text(content, encoding="utf-8")


def scaffold_analyzer(name: str, *, force: bool) -> list[pathlib.Path]:
    base = re.sub(r"Analyzer$", "", to_pascal(name))
    class_name = f"{base}Analyzer"
    snake = to_snake(base)

    code_tmpl = read_template(TEMPLATES / "analyzer.py.tmpl")
    ex_tmpl = read_template(TEMPLATES / "analyzer_example.py.tmpl")

    code = code_tmpl.format(CLASS_NAME=class_name, SNAKE_NAME=snake)
    example = ex_tmpl.format(CLASS_NAME=class_name, SNAKE_NAME=snake)

    code_path = ROOT / "src" / "sentineliqsdk" / "analyzers" / f"{snake}.py"
    example_path = ROOT / "examples" / "analyzers" / f"{snake}_example.py"

    write_file(code_path, code, force=force)
    write_file(example_path, example, force=force)
    return [code_path, example_path]


def scaffold_responder(name: str, *, force: bool) -> list[pathlib.Path]:
    base = re.sub(r"Responder$", "", to_pascal(name))
    class_name = f"{base}Responder"
    snake = to_snake(base)

    code_tmpl = read_template(TEMPLATES / "responder.py.tmpl")
    ex_tmpl = read_template(TEMPLATES / "responder_example.py.tmpl")

    code = code_tmpl.format(CLASS_NAME=class_name, SNAKE_NAME=snake)
    example = ex_tmpl.format(CLASS_NAME=class_name, SNAKE_NAME=snake)

    code_path = ROOT / "src" / "sentineliqsdk" / "responders" / f"{snake}.py"
    example_path = ROOT / "examples" / "responders" / f"{snake}_example.py"

    write_file(code_path, code, force=force)
    write_file(example_path, example, force=force)
    return [code_path, example_path]


def scaffold_detector(name: str, *, force: bool) -> list[pathlib.Path]:
    base = re.sub(r"Detector$", "", to_pascal(name))
    class_name = f"{base}Detector"
    snake = to_snake(base)

    code_tmpl = read_template(TEMPLATES / "detector.py.tmpl")
    ex_tmpl = read_template(TEMPLATES / "detector_example.py.tmpl")

    code = code_tmpl.format(CLASS_NAME=class_name, SNAKE_NAME=snake)
    example = ex_tmpl.format(CLASS_NAME=class_name, SNAKE_NAME=snake)

    code_path = ROOT / "src" / "sentineliqsdk" / "extractors" / "custom" / f"{snake}_detector.py"
    init_path = ROOT / "src" / "sentineliqsdk" / "extractors" / "custom" / "__init__.py"
    init_path.parent.mkdir(parents=True, exist_ok=True)
    if not init_path.exists():
        init_path.write_text("\n", encoding="utf-8")

    example_path = ROOT / "examples" / "detectors" / f"{snake}_example.py"

    write_file(code_path, code, force=force)
    write_file(example_path, example, force=force)
    return [code_path, init_path, example_path]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Scaffold Analyzer/Responder/Detector")
    ap.add_argument("--kind", choices=["analyzer", "responder", "detector"], required=True)
    ap.add_argument("--name", required=True, help="Base name, e.g. 'Shodan' or 'BlockIp'")
    ap.add_argument("--force", action="store_true", help="Overwrite existing files if present")
    args = ap.parse_args(argv)

    created: list[pathlib.Path]
    if args.kind == "analyzer":
        created = scaffold_analyzer(args.name, force=args.force)
    elif args.kind == "responder":
        created = scaffold_responder(args.name, force=args.force)
    else:
        created = scaffold_detector(args.name, force=args.force)

    for p in created:
        print(f"created: {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
