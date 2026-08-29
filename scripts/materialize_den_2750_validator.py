#!/usr/bin/env python3
"""Narrow the pinned DEN-2750 validator without exact-tag false positives."""

from __future__ import annotations

import argparse
from pathlib import Path


HELPER = '''/// Detect only malformed dotted numeric requirements that the semver parser
/// demotes to exact tags. A wildcard followed by any additional segment is a
/// typo, and more than three all-numeric components are not semver. Valid
/// calendar-like exact tags such as `2026.07.24` and ordinary opaque tags such
/// as `1.nginx` and `1.x86_64` remain exact.
fn looks_like_malformed_dotted_numeric_requirement(input: &str) -> bool {
    let mut segments = input.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if first.is_empty() || !first.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }

    let mut segment_count = 1;
    let mut all_numeric = true;
    let mut saw_wildcard = false;
    for segment in segments {
        segment_count += 1;
        if saw_wildcard {
            return true;
        }
        if matches!(segment, "x" | "X" | "*") {
            saw_wildcard = true;
            all_numeric = false;
            continue;
        }
        if segment.is_empty() {
            return false;
        }
        if segment.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        return false;
    }

    all_numeric && segment_count > 3
}
'''


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one {label}; found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()

    text = args.path.read_text(encoding="utf-8")
    start_marker = "/// Detect a dotted requirement whose leading segment is numeric"
    end_marker = "\nimpl Requirement {"
    start = text.find(start_marker)
    end = text.find(end_marker, start)
    if start < 0 or end < 0:
        raise SystemExit("could not locate the pinned broad dotted-requirement helper")
    text = text[:start] + HELPER + text[end:]

    text = replace_once(
        text,
        "            || looks_like_dotted_numeric_requirement(input);\n",
        "            || looks_like_malformed_dotted_numeric_requirement(input);\n",
        "broad validator helper call",
    )
    text = replace_once(
        text,
        "Strings with no range operators or numeric dotted shape are\n"
        "    /// legitimate opaque tags and pass.",
        "Strings without range operators or malformed dotted numeric shape are\n"
        "    /// legitimate opaque tags and pass.",
        "validator documentation boundary",
    )
    text = replace_once(
        text,
        '            "matrix-2",\n'
        '            "1.nginx",\n'
        '            "1.x86_64",\n',
        '            "matrix-2",\n'
        '            "1.nginx",\n'
        '            "1.x86_64",\n'
        '            "2026.07.24",\n',
        "accepted-tag regression list",
    )

    args.path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
