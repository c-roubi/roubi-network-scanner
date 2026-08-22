"""Optional startup banner."""

from __future__ import annotations

from roubi._version import __version__

_ART = r"""
                   _     _
  _ __ ___   _   _| |__ (_)
 | '__/ _ \ | | | | '_ \| |
 | | | (_) || |_| | |_) | |
 |_|  \___/  \__,_|_.__/|_|
"""


def render(color: bool = True) -> str:
    tagline = f"  roubi {__version__} - TCP network scanner"
    if color:
        return f"\033[36m{_ART}\033[0m\n{tagline}\n"
    return f"{_ART}\n{tagline}\n"
