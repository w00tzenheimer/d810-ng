"""Pure model behind the ``[?]`` About dialog (ticket d81-zijs).

Deliberately free of Qt and IDA imports so the About content is unit-testable
without a decompiler; :mod:`d810.ui.about_dialog` is a thin renderer on top.

``d810.__version__`` is the single source of truth for the version -- both
``pyproject.toml`` and ``ida-plugin.json`` derive from it (the latter via
``tools/sync_plugin_version.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: User-facing product name. Labels say ``d810-ng``; only ACTION_IDs use the
#: ``d810ng:`` form.
PRODUCT_NAME = "d810-ng"

#: Shown when the package version cannot be determined. About must degrade
#: rather than raise inside a Qt slot.
UNKNOWN_VERSION = "unknown"

REPOSITORY_URL = "https://github.com/w00tzenheimer/d810-ng"
ISSUES_URL = "https://github.com/w00tzenheimer/d810-ng/issues"
HELP_URL = "https://github.com/w00tzenheimer/d810-ng#readme"

#: ``(display name, profile URL)``.
AUTHORS: tuple[tuple[str, str], ...] = (
    ("w00tzenheimer", "https://github.com/w00tzenheimer"),
    ("mahmoudimus", "https://github.com/mahmoudimus"),
)

#: Kept verbatim from the README's Acknowledgement section so the two cannot
#: drift into saying different things:
#: https://github.com/w00tzenheimer/d810-ng#acknowledgement
#:
#: Written once in markdown-link form; :func:`render_html` and
#: :func:`render_plain` derive both display forms from this single source.
ACKNOWLEDGEMENTS: tuple[str, ...] = (
    "Rolf Rolles for the huge work he has done with his "
    "[HexRaysDeob plugin](https://github.com/RolfRolles/HexRaysDeob) and all the "
    "information about Hex-Rays microcode internals described in his "
    "[blog post](https://www.hex-rays.com/blog/hex-rays-microcode-api-vs-obfuscating-compiler/). "
    "We are still using some part of his plugin in D-810.",
    "Dennis Elser for the [genmc plugin](https://github.com/patois/genmc) which "
    "was very helpful for debugging D-810 errors.",
    "A special thank you to [Boris Batteux](https://gitlab.com/borisbatteux) for "
    "this great plugin!",
)

#: ``[text](url)``
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def render_plain(markdown: str) -> str:
    """Drop the link syntax, keeping the anchor text."""
    return _MARKDOWN_LINK.sub(r"\1", markdown)


def render_html(markdown: str) -> str:
    """Turn ``[text](url)`` into an anchor, escaping everything else."""
    parts: list[str] = []
    cursor = 0
    for match in _MARKDOWN_LINK.finditer(markdown):
        parts.append(_escape(markdown[cursor : match.start()]))
        text, url = match.group(1), match.group(2)
        parts.append(f'<a href="{_escape(url)}">{_escape(text)}</a>')
        cursor = match.end()
    parts.append(_escape(markdown[cursor:]))
    return "".join(parts)


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def package_version() -> str:
    """Return ``d810.__version__``, or :data:`UNKNOWN_VERSION`.

    Never raises: a missing, blank, or non-string attribute degrades to
    ``"unknown"`` so the caller (a Qt slot) cannot be taken down by it.
    """
    try:
        import d810

        version = getattr(d810, "__version__", None)
    except Exception:  # noqa: BLE001 - About must not raise
        return UNKNOWN_VERSION
    if not isinstance(version, str) or not version.strip():
        return UNKNOWN_VERSION
    return version.strip()


@dataclass(frozen=True, slots=True)
class AboutModel:
    """Everything the About dialog renders, resolved and ready to display."""

    product: str
    version: str
    links: tuple[tuple[str, str], ...]
    authors: tuple[tuple[str, str], ...]
    acknowledgements: tuple[str, ...]

    @property
    def title(self) -> str:
        """Window title for the dialog."""
        return f"About {self.product}"


def about_model() -> AboutModel:
    """Build the About model for the running build."""
    return AboutModel(
        product=PRODUCT_NAME,
        version=package_version(),
        links=(
            ("Repository", REPOSITORY_URL),
            ("Issues", ISSUES_URL),
            ("Help", HELP_URL),
        ),
        authors=AUTHORS,
        acknowledgements=ACKNOWLEDGEMENTS,
    )
