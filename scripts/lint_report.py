#!/usr/bin/env python3
"""Mechanical pre-submission linter for reports/*-SUBMISSION.md and *-EMAIL.txt.

This exists because the same mistakes (wrong GHSA ecosystem value, CVE ID in the
title, Korean text in a vendor-facing body, a restated CVSS vector in narrative
prose, a leftover reporter placeholder, markdown syntax in a plain-text email)
have recurred multiple times across sessions despite being written down in
CLAUDE.md and in auto-memory. Memory is advisory (depends on being recalled and
applied correctly every single time); this script is not - it is meant to be run
on every drafted report before considering it finished, and failing checks block
that by printing FAIL and exiting non-zero.

See CLAUDE.md's report-writing rules and the project memory files
feedback_ghsa-ecosystem-enum-names.md, feedback_keep-report-titles-subjects-concise.md,
feedback_no-korean-in-vendor-report-body.md, feedback_no-cvss-vector-in-narrative-text.md,
feedback_reporter-identity-default.md, feedback_email-reports-plain-text-not-markdown.md
for the incidents this encodes.

Usage:
    python3 scripts/lint_report.py reports/foo-SUBMISSION.md [reports/bar-EMAIL.txt ...]
    python3 scripts/lint_report.py --all          # lint every *-SUBMISSION.md/*-EMAIL.txt in reports/

Exit code 0 if every file passes every check, 1 if any FAIL. WARN does not affect
the exit code - it flags something for a human/LLM to look at, not a hard rule.
"""
from __future__ import annotations

import glob
import re
import sys

GHSA_ECOSYSTEMS = {
    "Composer", "Erlang", "GitHub Actions", "Go", "Maven", "npm", "NuGet",
    "pip", "Pub", "RubyGems", "Rust", "Swift", "Other",
}
# Common wrong guesses seen in the wild, mapped to a hint.
ECOSYSTEM_WRONG_GUESSES = {
    "pypi": "pip",
    "c": "Other (no C/C++ option exists - verify against the live dropdown, don't guess)",
    "c++": "Other",
    "cpp": "Other",
    "generic": "Other (no generic/language-agnostic option exists - verify against the live dropdown, don't guess)",
    "python": "pip",
    "javascript": "npm",
    "js": "npm",
    "node": "npm",
    "nodejs": "npm",
    "java": "Maven",
    "ruby": "RubyGems",
    "php": "Composer",
    "golang": "Go",
    "dart": "Pub",
    "elixir": "Erlang",
    "erlang/otp": "Erlang",
    ".net": "NuGet",
    "nuget": "NuGet",  # case fix
    "docker": "Other",
    "github actions": "GitHub Actions",  # case fix
}

HANGUL_RE = re.compile(r"[\uAC00-\uD7A3\u1100-\u11FF\u3130-\u318F]")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
GHSA_ID_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b")
CVSS_VECTOR_RE = re.compile(r"CVSS:3\.[01]/[A-Z:/.]+|CVSS:4\.0/[A-Z:/.]+")
MD_CODEFENCE_RE = re.compile(r"```")
MD_BOLD_RE = re.compile(r"\*\*[^*]+\*\*")
MD_HEADER_RE = re.compile(r"^#{1,6}\s", re.MULTILINE)
PLACEHOLDER_RE = re.compile(r"\[reporter name\]|\[your name\]|\[TODO\]|\[FIXME\]", re.IGNORECASE)
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")


class Result:
    def __init__(self):
        self.fails = []
        self.warns = []
        self.oks = []

    def fail(self, msg):
        self.fails.append(msg)

    def warn(self, msg):
        self.warns.append(msg)

    def ok(self, msg):
        self.oks.append(msg)


def extract_field(text: str, field_name: str) -> list[str]:
    """Find values for a `**Field**` or `| **Field** |` style line, case-insensitive."""
    out = []
    for line in text.splitlines():
        m = re.search(
            rf"\*\*{re.escape(field_name)}\*\*\s*[:|]\s*`?([^|`\n]+)`?", line, re.IGNORECASE
        )
        if m:
            out.append(m.group(1).strip().rstrip("|").strip())
            continue
        # Combined-header table row, e.g. "| **Ecosystem** / **Package name** | `X` / `Y` |" --
        # this project's reports routinely merge two fields into one cell pair. If the header
        # cell contains this field name alongside another bolded label (joined by "/"), take the
        # same position out of the value cell.
        if "|" not in line or f"**{field_name.lower()}**" not in line.lower():
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        header_parts = [h.strip() for h in cells[0].split("/")]
        idx = next(
            (i for i, h in enumerate(header_parts) if h.lower() == f"**{field_name.lower()}**"),
            None,
        )
        if idx is None:
            continue
        value_parts = [v.strip() for v in cells[1].split("/")]
        if idx < len(value_parts):
            out.append(value_parts[idx].strip("`").strip())
    return out


def check_ecosystem(text: str, result: Result):
    values = extract_field(text, "Ecosystem")
    if not values:
        result.ok("Ecosystem: no Ecosystem field found (fine if this isn't a GHSA-form report)")
        return
    for v in values:
        v_clean = v.strip().strip("`").split("(")[0].strip()
        if v_clean in GHSA_ECOSYSTEMS:
            result.ok(f"Ecosystem: '{v_clean}' is a valid GHSA dropdown value")
            continue
        hint = ECOSYSTEM_WRONG_GUESSES.get(v_clean.lower())
        if hint:
            result.fail(
                f"Ecosystem: '{v_clean}' is NOT a real GHSA dropdown value - likely means '{hint}'. "
                f"Valid values: {', '.join(sorted(GHSA_ECOSYSTEMS))}"
            )
        else:
            result.fail(
                f"Ecosystem: '{v_clean}' is not in the known GHSA dropdown list "
                f"({', '.join(sorted(GHSA_ECOSYSTEMS))}) - verify against the live form or use 'Other'"
            )


AFFECTED_VERSIONS_PROSE_RE = re.compile(
    r"[(){}]|[가-힣]|\bmain\b|\bmaster\b|\bcurrent\b|\btoday\b|\bcommit\b|\bbranch\b",
    re.IGNORECASE,
)


def check_affected_versions(text: str, result: Result):
    """'Affected versions' must be a clean semver range (<= X.Y.Z, >= A, <= B) -
    never prose, a branch name, or a commit hash. See
    feedback_affected-products-clean-version-range.md - this has recurred
    (Excelize/GitPython/PraisonAI 2026-09, then OpenEMR/vllm 2026-11-13: both
    wrote 'main (<date> 기준 미수정)' instead of the actual latest release tag)."""
    values = extract_field(text, "Affected versions")
    if not values:
        result.ok("Affected versions: no field found (fine if this isn't a GHSA-form report)")
        return
    bad = [v for v in values if AFFECTED_VERSIONS_PROSE_RE.search(v)]
    if bad:
        result.fail(
            f"Affected versions: {bad} looks like prose/a branch name/a commit hash, not a clean "
            "semver range - use the actual latest release version (e.g. '<= 8.5.0'), and put any "
            "'confirmed present on main at commit X' detail in the PoC's Versions-tested section "
            "instead."
        )
    else:
        result.ok("Affected versions: clean semver range")


def check_cve_in_title(text: str, is_email: bool, result: Result):
    titles = extract_field(text, "Title")
    # also catch a standalone "## Title" section
    m = re.search(r"^##\s+Title\s*\n+`?([^\n`]+)`?", text, re.MULTILINE)
    if m:
        titles.append(m.group(1).strip())
    if is_email:
        m = re.search(r"^Subject:\s*(.+)$", text, re.MULTILINE)
        if m:
            titles.append(m.group(1).strip())
    if not titles:
        result.warn("Title/Subject: no Title or Subject field found to check")
        return
    for t in titles:
        if CVE_RE.search(t) or GHSA_ID_RE.search(t):
            result.fail(f"Title/Subject: contains a CVE/GHSA ID ('{t}') - headline must stand on its own, no CVE framing")
        else:
            result.ok(f"Title/Subject: no CVE/GHSA ID found ('{t}')")


def _extract_email_fence(text: str) -> str:
    """For the single-.md email convention (see REPORT_WRITING_PROMPT.md's
    "Email-channel reports" section, 2026-11-06+), the only content that actually
    gets pasted into an email client is inside one fenced code block, identified
    by starting with "To:" - everything else in the file (H1 title, intro
    blockquote, internal '심각도 산정 메모' notes) is our own working notes and must
    never be run through the vendor-facing checks. Falls back to the whole text
    if no such fence is found, which keeps this correct for the older plain
    *-EMAIL.txt convention too (that file IS the pasteable body, no fence at all)."""
    for m in re.finditer(r"```\n(.*?)```", text, re.DOTALL):
        if m.group(1).lstrip().startswith("To:"):
            return m.group(1)
    return text


def _strip_internal_wrapper(text: str) -> str:
    """Drop our own H1 title + intro blockquote (before the first '---') and the
    trailing internal severity-rationale section (e.g. '## 심각도 산정 메모'),
    wherever it starts. What's left is everything a vendor would actually see if
    we pasted the file's relevant sections into their form - still including our
    own Korean section-label headers and reference tables at this stage."""
    parts = text.split("\n---\n")
    if len(parts) >= 2:
        text = "\n---\n".join(parts[1:])
    text = re.split(r"\n##\s*심각도.*", text, flags=re.DOTALL)[0]
    return text


def vendor_facing_body(text: str, is_email: bool) -> str:
    """Best-effort extraction of the part a vendor actually reads, for the Korean
    check specifically: additionally drops markdown headers and table rows, since
    those are always our own Korean section labels / reference tables for human
    navigation in this project's report files (e.g. "## 그대로 붙여넣기", "| 필드 | 값 |"),
    never literal content that gets pasted into the vendor's form - only prose
    *paragraphs* (e.g. the actual value written under a "## Asset"/"## Title"
    heading) are literal paste content."""
    if is_email:
        return _extract_email_fence(text)
    text = _strip_internal_wrapper(text)
    lines = text.splitlines()
    body_lines = [
        l for l in lines
        if not l.strip().startswith(">")
        and not re.match(r"^#{1,6}\s", l.strip())
        and not l.strip().startswith("|")
    ]
    return "\n".join(body_lines)


def check_korean(text: str, is_email: bool, result: Result):
    body = vendor_facing_body(text, is_email)
    matches = HANGUL_RE.findall(body)
    if matches:
        # show a bit of context for the first hit
        idx = HANGUL_RE.search(body).start()
        ctx = body[max(0, idx - 30): idx + 30].replace("\n", " ")
        result.fail(
            f"Korean text found in vendor-facing body ({len(matches)} char(s)) - context: ...{ctx}..."
        )
    else:
        result.ok("Korean: none found in vendor-facing body")


def check_cvss_narrative(text: str, is_email: bool, result: Result):
    # Headers must survive here (unlike the Korean check) so "## Severity" can be
    # recognized as the structured field; only strip our own intro/internal wrapper.
    body = _extract_email_fence(text) if is_email else _strip_internal_wrapper(text)
    lines = body.splitlines()
    # Lines that are clearly the structured field (table row or **Severity**/**Vector string** line)
    structured_lines = set()
    for i, line in enumerate(lines):
        if re.search(r"\*\*(Severity|Vector string)\*\*", line, re.IGNORECASE) or line.strip().startswith("|"):
            structured_lines.add(i)
        if re.match(r"^##\s+Severity\s*$", line.strip(), re.IGNORECASE):
            structured_lines.add(i)
            # the next non-blank line is the actual value (skip the blank line
            # markdown conventionally leaves between a heading and its content)
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            structured_lines.add(j)
    stray = []
    for i, line in enumerate(lines):
        if CVSS_VECTOR_RE.search(line) and i not in structured_lines:
            stray.append((i, line.strip()))
    if stray:
        for i, line in stray:
            result.warn(f"CVSS vector appears in narrative prose (line ~{i}): '{line[:100]}' - confirm this isn't a restated score outside the structured Severity field (citing a DIFFERENT CVE's own published vector for comparison is fine; restating THIS finding's own vector in prose is not)")
    else:
        result.ok("CVSS vector: no stray occurrences found outside the structured Severity field")


def check_reporter(text: str, is_ghsa: bool, result: Result):
    if PLACEHOLDER_RE.search(text):
        result.fail("Reporter: leftover placeholder found (e.g. '[reporter name]') - fill in baeseungwon1010")
        return
    if is_ghsa:
        # GitHub Security Advisory forms auto-identify/credit the submitting account -
        # a manual Reporter line is redundant, not just unnecessary (2026-11-07).
        if "baeseungwon1010" in text:
            result.warn("Reporter: 'baeseungwon1010' present but this is a GHSA-channel report - "
                        "GitHub auto-identifies the submitter, drop the manual Reporter line")
        else:
            result.ok("Reporter: none present (correct for a GHSA-channel report - GitHub auto-identifies)")
        return
    if "baeseungwon1010" in text:
        result.ok("Reporter: baeseungwon1010 present")
    else:
        result.warn("Reporter: 'baeseungwon1010' not found anywhere - confirm reporter identity is set")


def check_email_plaintext(text: str, result: Result):
    # Check only the pasteable fence content, not the file's own markdown
    # wrapper (H1 title, "## 그대로 붙여넣기" heading, the fence markers themselves).
    body = _extract_email_fence(text)
    issues = []
    if MD_CODEFENCE_RE.search(body):
        issues.append("code fence (```)")
    if MD_BOLD_RE.search(body):
        issues.append("**bold**")
    if MD_HEADER_RE.search(body):
        issues.append("# header")
    if issues:
        result.fail(f"Email plain-text: markdown syntax found ({', '.join(issues)}) - the pasteable body must be pure plain text")
    else:
        result.ok("Email plain-text: no markdown syntax found")


def check_relative_image_links(text: str, is_email: bool, result: Result):
    """A markdown image with a relative/local path renders broken once the text is
    pasted into a vendor's web form textarea (no filesystem behind it there) - see
    feedback_no-relative-image-paths-in-pasted-vendor-forms.md. Only an absolute
    http(s)/data: URL (meaning the image was actually already uploaded somewhere)
    is safe to leave in a pasteable section."""
    body = _extract_email_fence(text) if is_email else _strip_internal_wrapper(text)
    bad = []
    for m in MD_IMAGE_RE.finditer(body):
        target = m.group(1).strip()
        if not re.match(r"^(https?://|data:)", target, re.IGNORECASE):
            bad.append(target)
    if bad:
        result.fail(
            f"Image link: relative/local path(s) {bad} found in pasteable body - this renders "
            f"broken once pasted into a web form. Use a placeholder like "
            f"'[recording to be dropped in here]' instead, and put the drag-and-drop instruction "
            f"in the internal header note, not inside the pasteable section."
        )
    else:
        result.ok("Image link: no relative/local-path markdown images found in pasteable body")


FIELD_HEADER_RE = re.compile(
    r"^##\s*\[(Summary|Details|Proof of concept|Impact) field\]\s*$", re.MULTILINE
)


def check_field_fences(text: str, result: Result):
    """GHSA-style reports: each '## [X field]' header's body must start with a
    code fence, so a copy button/block-select grabs exactly that field - see
    feedback_report-fields-wrapped-in-code-fences.md. This has silently lapsed
    three times across sessions (2026-11-01, -08, -13) because it lived only in
    memory text with nothing mechanically checking it; this is that check."""
    headers = list(FIELD_HEADER_RE.finditer(text))
    if not headers:
        result.ok("Field fences: no '## [X field]' headers found (not a GHSA-style report)")
        return
    unfenced = []
    for i, m in enumerate(headers):
        start = m.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        body = text[start:end].strip()
        if not body.startswith("```"):
            unfenced.append(m.group(1))
    if unfenced:
        result.fail(
            f"Field fences: {unfenced} field body(ies) don't start with a ``` fence - "
            "wrap each field's pasteable content in its own code fence immediately "
            "under its header so a copy button/block-select grabs exactly that field."
        )
    else:
        result.ok("Field fences: every '## [X field]' body is fenced")


def check_ai_disclosure(text: str, result: Result):
    if re.search(r"AI Use Disclosure", text, re.IGNORECASE):
        result.ok("AI Use Disclosure: section present")
    else:
        result.warn("AI Use Disclosure: no 'AI Use Disclosure' section found")


def lint_file(path: str) -> bool:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # The older convention was a standalone *-EMAIL.txt file (the whole file IS
    # the pasteable body). Since 2026-11-06 an email-channel report is a single
    # *-SUBMISSION.md with the pasteable body inside one fenced "그대로 붙여넣기"
    # block instead - detect that too, or every check gated on is_email silently
    # no-ops/mis-scopes on the new format (caught 2026-11-07: Subject-line check
    # never ran, and Korean/CVSS-narrative/image-link checks ran against either
    # the wrong region or an accidentally-empty one instead of the real fence).
    is_email = path.endswith("-EMAIL.txt") or re.search(
        r"^##\s*그대로\s*붙여넣기\s*\(이메일", text, re.MULTILINE
    )
    is_ghsa = "security/advisories/new" in text

    result = Result()
    check_ecosystem(text, result)
    check_affected_versions(text, result)
    check_cve_in_title(text, is_email, result)
    check_korean(text, is_email, result)
    check_cvss_narrative(text, is_email, result)
    check_reporter(text, is_ghsa, result)
    check_relative_image_links(text, is_email, result)
    check_ai_disclosure(text, result)
    if not is_email:
        check_field_fences(text, result)
    if is_email:
        check_email_plaintext(text, result)

    print(f"\n=== {path} ===")
    for msg in result.oks:
        print(f"  OK   {msg}")
    for msg in result.warns:
        print(f"  WARN {msg}")
    for msg in result.fails:
        print(f"  FAIL {msg}")
    if not result.fails:
        print(f"  --> PASS ({len(result.warns)} warning(s))" if result.warns else "  --> PASS")
    else:
        print(f"  --> {len(result.fails)} FAIL(S)")
    return not result.fails


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    if args == ["--all"]:
        paths = sorted(
            glob.glob("reports/*-SUBMISSION.md") + glob.glob("reports/*-EMAIL.txt")
        )
    else:
        paths = args

    if not paths:
        print("No files to lint.")
        sys.exit(0)

    all_ok = True
    for p in paths:
        ok = lint_file(p)
        all_ok = all_ok and ok

    print()
    print("ALL PASS" if all_ok else "SOME FILES FAILED - fix before considering the report done")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
