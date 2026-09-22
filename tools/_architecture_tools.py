"""One-shot branch tooling; not included in the resulting refactor commit."""
import ast
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGED: set[str] = set()


def read(path):
    return (ROOT / path).read_text()


def write(path, text):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(text).strip() + "\n")
    CHANGED.add(path)


def node_at(source, name):
    body = ast.parse(source).body
    for part in name.split("."):
        node = next(node for node in body if getattr(node, "name", None) == part)
        body = getattr(node, "body", [])
    return node


def extract(source, name):
    return textwrap.dedent(ast.get_source_segment(source, node_at(source, name)))


def replace(path, name, code):
    source = read(path)
    node = node_at(source, name)
    lines = source.splitlines(keepends=True)
    start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])]) - 1
    replacement = textwrap.indent(textwrap.dedent(code).strip(), " " * node.col_offset) + "\n"
    lines[start:node.end_lineno] = [replacement]
    write(path, "".join(lines))


def append(path, code):
    write(path, read(path) + "\n\n" + textwrap.dedent(code))


def add_imports(path, text):
    source = read(path)
    tree = ast.parse(source)
    doc = tree.body[0]
    at = doc.end_lineno if isinstance(doc, ast.Expr) and isinstance(doc.value, ast.Constant) else 0
    lines = source.splitlines(keepends=True)
    lines.insert(at, "\n" + textwrap.dedent(text).strip() + "\n")
    write(path, "".join(lines))


def imports(source):
    return "\n".join(ast.get_source_segment(source, node) for node in ast.parse(source).body
                     if isinstance(node, (ast.Import, ast.ImportFrom)))
