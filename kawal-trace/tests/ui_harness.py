"""Headless stand-in for Flet used by the dashboard render-contract tests.

This is NOT Flet and draws no pixels. It records the control tree that main.py builds so tests can
(1) run the real dashboard-construction code, (2) click every sidebar entry and (3) lint the mounted
tree for layout patterns that make the real Flutter client replace a region with a grey error surface.
Passing the linter is necessary, not sufficient: a run on a real Windows/Android device is still required.
"""
from __future__ import annotations

import asyncio
import sys
import types
from typing import Any, Iterator

CONTAINER_ATTRS = ("controls", "content")


class Struct:
    def __init__(self, name: str, *args: Any, **kwargs: Any) -> None:
        self._name, self._args, self._kwargs = name, args, kwargs

    def __repr__(self) -> str:  # pragma: no cover
        return f"{self._name}{self._args}{self._kwargs}"


class Namespace:
    """Enum-like namespace: any attribute resolves to a dotted string; callables build Structs."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("__"):
            raise AttributeError(attr)
        return _Leaf(f"{self._name}.{attr}")

    def __call__(self, *args: Any, **kwargs: Any) -> Struct:
        return Struct(self._name, *args, **kwargs)


class _Leaf(str):
    def __new__(cls, text: str):
        return str.__new__(cls, text)

    def __call__(self, *args: Any, **kwargs: Any) -> Struct:
        return Struct(str(self), *args, **kwargs)

    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("__"):
            raise AttributeError(attr)
        return _Leaf(f"{self}.{attr}")


class Control:
    kind = "Control"
    _positional: tuple[str, ...] = ()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        for key, value in zip(self._positional, args):
            kwargs.setdefault(key, value)
        self.__dict__.update(kwargs)
        self.controls = list(kwargs.get("controls") or [])
        self.parent: Control | None = None

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.kind}>"

    def __getattr__(self, name: str) -> Any:
        # Real Flet controls expose every property with a default (None/False); mimic that.
        if name.startswith("_"):
            raise AttributeError(name)
        return True if name == "visible" else None

    def children(self) -> Iterator["Control"]:
        for item in list(getattr(self, "controls", None) or []):
            if isinstance(item, Control):
                yield item
        content = getattr(self, "content", None)
        if isinstance(content, Control):
            yield content

    def walk(self) -> Iterator["Control"]:
        yield self
        for child in self.children():
            yield from child.walk()


def _make_class(name: str, positional: tuple[str, ...] = ()) -> type:
    return type(name, (Control,), {"kind": name, "_positional": positional})


CONTROL_POSITIONAL = {"Text": ("value",), "Icon": ("icon",), "Container": ("content",), "Checkbox": ("label",)}
CONTROL_NAMES = [
    "Text", "Container", "TextField", "Row", "Column", "OutlinedButton", "FilledButton", "TextButton", "Icon", "Divider",
    "ResponsiveRow", "Dropdown", "DropdownOption", "SafeArea", "Checkbox", "Image", "FilePicker", "Switch", "ListView",
    "DataTable", "ProgressBar", "ProgressRing", "Stack", "Tabs", "Tab", "Card", "IconButton", "VerticalDivider",
    "AlertDialog", "SnackBar", "Chip", "Slider", "Audio",
]


class FakePage:
    def __init__(self, width: float = 1280, height: float = 800, platform: str = "windows") -> None:
        self.controls: list[Control] = []
        self.services: list[Any] = []
        self.width, self.height = width, height
        self.platform = platform
        self.web = False
        self.window = types.SimpleNamespace(width=width, height=height, min_width=0, min_height=0)
        self.on_resize = None
        self.update_count = 0
        self.tasks: list[Any] = []
        self.title = ""
        self.theme_mode = self.theme = self.bgcolor = self.padding = self.spacing = self.scroll = None

    def add(self, *controls: Control) -> None:
        self.controls.extend(controls)

    def update(self, *_: Any) -> None:
        self.update_count += 1

    def run_task(self, handler: Any, *args: Any, **kwargs: Any) -> Any:
        self.tasks.append((handler, args, kwargs))   # background loops are recorded, never started
        return None

    def run_thread(self, handler: Any, *args: Any, **kwargs: Any) -> None:
        self.tasks.append((handler, args, kwargs))


def install_fake_flet() -> types.ModuleType:
    module = types.ModuleType("flet")
    for name in CONTROL_NAMES:
        setattr(module, name, _make_class(name, CONTROL_POSITIONAL.get(name, ())))
    for name in ("Icons", "Colors", "ScrollMode", "MainAxisAlignment", "CrossAxisAlignment", "FontWeight", "ThemeMode",
                 "TextCapitalization", "KeyboardType", "BoxFit", "FilePickerFileType", "ControlState", "TextAlign",
                 "ButtonStyle", "Theme", "Padding", "Border", "BorderSide", "Alignment", "OutlineInputBorder", "TextStyle",
                 "BorderRadius", "Margin", "ImageFit", "TextOverflow", "MouseCursor", "VisualDensity", "ClipBehavior"):
        setattr(module, name, Namespace(f"ft.{name}"))
    module.Page = FakePage
    module.Control = Control
    module.ControlEvent = object
    module.run = lambda *a, **k: None
    sys.modules["flet"] = module
    return module


# ---------------------------------------------------------------------------------------- linter
def _is(ctrl: Control, *names: str) -> bool:
    return ctrl.kind in names


def lint_tree(root: Control) -> list[str]:
    """Return human-readable layout problems for the subtree below `root`."""
    problems: list[str] = []

    def mark_parents(node: Control, parent: Control | None) -> None:
        node.parent = parent
        for child in node.children():
            mark_parents(child, node)

    mark_parents(root, None)

    def where(node: Control) -> str:
        chain, cur = [], node
        while cur is not None and len(chain) < 5:
            chain.append(cur.kind)
            cur = cur.parent
        label = getattr(node, "label", None) or getattr(node, "value", None) or ""
        if not label:
            for inner in node.walk():
                text = getattr(inner, "value", None)
                if isinstance(text, str) and text.strip():
                    label = text
                    break
        if not label and cur is not None:
            for inner in cur.walk():
                text = getattr(inner, "value", None)
                if isinstance(text, str) and text.strip():
                    label = "(ancestor text) " + text
                    break
        return f"{' < '.join(chain)} {str(label)[:60]!r}"

    for node in root.walk():
        parent = node.parent
        expand = getattr(node, "expand", None)
        if expand not in (None, False, 0):
            if parent is not None and not _is(parent, "Row", "Column"):
                problems.append(f"expand inside non-flex parent ({parent.kind}): {where(node)}")
            if parent is not None and _is(parent, "Row", "Column") and getattr(parent, "wrap", False):
                problems.append(f"expand child inside wrapping {parent.kind}: {where(node)}")
            if parent is not None and _is(parent, "Column", "Row") and getattr(parent, "scroll", None) is not None and \
                    ((_is(parent, "Column") and True) or (_is(parent, "Row"))) and not getattr(parent, "expand", None) is None and False:
                pass
        # a scrolling Column gives its children unbounded height: any direct expand child is an error
        if parent is not None and _is(parent, "Column") and getattr(parent, "scroll", None) is not None and expand not in (None, False, 0):
            problems.append(f"expand child inside scrolling Column (unbounded height): {where(node)}")
        if parent is not None and _is(parent, "Row") and getattr(parent, "scroll", None) is not None and expand not in (None, False, 0):
            problems.append(f"expand child inside scrolling Row (unbounded width): {where(node)}")
        # TextField / Dropdown need a bounded width: a plain (non-wrapping) Row gives them infinity
        if _is(node, "TextField", "Dropdown") and parent is not None and _is(parent, "Row") and not getattr(parent, "wrap", False):
            if getattr(node, "width", None) is None and expand in (None, False, 0) and getattr(node, "visible", True) is not False:
                problems.append(f"{node.kind} without width/expand directly in non-wrapping Row (unbounded width): {where(node)}")
        # ResponsiveRow needs bounded width as well
        if _is(node, "ResponsiveRow") and parent is not None and _is(parent, "Row") and not getattr(parent, "wrap", False) \
                and getattr(node, "width", None) is None and expand in (None, False, 0):
            problems.append(f"ResponsiveRow inside Row without width/expand: {where(node)}")
        if _is(node, "ListView", "DataTable") and parent is not None and _is(parent, "Column") and getattr(parent, "scroll", None) is not None \
                and getattr(node, "height", None) is None:
            problems.append(f"{node.kind} with unbounded height in scrolling Column: {where(node)}")
    return problems


def find(root: Control, kind: str | None = None, **match: Any) -> list[Control]:
    out = []
    for node in root.walk():
        if kind and node.kind != kind:
            continue
        if all(getattr(node, k, None) == v for k, v in match.items()):
            out.append(node)
    return out
