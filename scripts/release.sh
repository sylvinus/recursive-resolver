#!/usr/bin/env bash
#
# Interactive release for recursive-resolver: PyPI, then a GitHub release.
#
# The structure of this script: the interactive gates, the hermetic
# build-and-upload inside Docker, and the artifact-inspection step: is adapted
# from bin/release-jmap-email.sh in https://github.com/suitenumerique/messages
#
#   Copyright (c) 2025 Direction Interministérielle du Numérique
#   Gouvernement Français
#   Licensed under the MIT License.
#
# Hermetic: building, checking and uploading all happen inside the
# python:3.13-slim image, so the host never needs pip, build or twine. A clean
# machine needs only Docker and git; the gh CLI is only needed to run the
# command the last step prints.
#
# Flow:
#   1. Pre-flight: clean tree, version consistency, changelog entry, no tag yet
#   2. make check-all: lint, format, types, full test suite, coverage gate
#   3. Build sdist + wheel in Docker, run twine check
#   4. Inspect artifact contents and METADATA against what this package promises
#   5. Upload to TestPyPI, then smoke-install and actually resolve a name
#   6. Upload to PyPI
#   7. Print the git tag / push / gh release commands. The script never runs
#      them: it does not touch git state or publish a release itself.
#
# Every gate is interactive (y/N). Ctrl-C bails out at any point.
#
#   SKIP_GATES=1   skip step 2 on a retry
#   SKIP_TESTPYPI=1 go straight to PyPI (not recommended for a first release)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_IMAGE="python:3.13-slim"
PKG_NAME="recursive-resolver"
PKG_MODULE="recursive_resolver"

BOLD=$'\033[1m'
GREEN=$'\033[1;32m'
BLUE=$'\033[1;34m'
RED=$'\033[1;31m'
YELLOW=$'\033[1;33m'
RESET=$'\033[0m'

say()  { printf '%s%s%s\n' "${BLUE}" "$*" "${RESET}"; }
ok()   { printf '%s✓ %s%s\n' "${GREEN}" "$*" "${RESET}"; }
warn() { printf '%s%s%s\n' "${YELLOW}" "$*" "${RESET}"; }
die()  { printf '%s✗ %s%s\n' "${RED}" "$*" "${RESET}" >&2; exit 1; }

confirm() {
    local ans
    read -r -p "${BOLD}$1 [y/N]${RESET} " ans
    [[ "${ans}" =~ ^[Yy]$ ]] || die "aborted"
}

read_token() {
    local label="$1" varname="$2" token
    read -r -s -p "${BOLD}${label} API token (pypi-…):${RESET} " token
    echo
    [[ -n "${token}" ]] || die "empty token"
    [[ "${token}" == pypi-* ]] || warn "token does not start with 'pypi-': continuing anyway"
    printf -v "${varname}" '%s' "${token}"
}

in_container() {
    # $1 = extra docker args (may be empty), rest = bash -c script
    docker run --rm -t \
        --user "$(id -u):$(id -g)" \
        -v "${REPO_DIR}:/pkg" \
        -w /pkg \
        -e HOME=/tmp \
        "$@"
}

# ── pre-flight ────────────────────────────────────────────────────────────
command -v docker >/dev/null || die "docker not found in PATH"
command -v git    >/dev/null || die "git not found in PATH"
[[ -f "${REPO_DIR}/pyproject.toml" ]] || die "no pyproject.toml at ${REPO_DIR}"

VERSION="$(awk -F'"' '/^version = /{print $2; exit}' "${REPO_DIR}/pyproject.toml")"
[[ -n "${VERSION}" ]] || die "could not read version from pyproject.toml"

MODULE_VERSION="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "${REPO_DIR}/src/${PKG_MODULE}/__init__.py")"
[[ "${MODULE_VERSION}" == "${VERSION}" ]] \
    || die "version mismatch: pyproject.toml=${VERSION} but __init__.py=${MODULE_VERSION}"

# The release notes below are extracted from a "## [VERSION]" *heading*, so a
# version that only appears in a link definition at the bottom of the file must
# not pass pre-flight and then yield empty notes after the irreversible PyPI
# upload. index()==1 anchors at column 1, and awk's index() is a fixed-string
# search, so the version's dots are not wildcards. This matches the check the
# `release-check` target in the Makefile runs.
awk -v v="## [${VERSION}]" 'index($0, v) == 1 { found = 1; exit } END { exit !found }' \
    "${REPO_DIR}/CHANGELOG.md" \
    || die "CHANGELOG.md has no '## [${VERSION}]' section heading"

TAG="v${VERSION}"
if git -C "${REPO_DIR}" rev-parse "${TAG}" >/dev/null 2>&1; then
    die "tag ${TAG} already exists locally: bump the version first"
fi
# Also check the remote. A tag pushed from another machine, or left behind by a
# run that died between push and release, would otherwise pass here and only
# fail after the irreversible PyPI upload.
if git -C "${REPO_DIR}" ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null 2>&1; then
    die "tag ${TAG} already exists on origin: bump the version first"
fi

if [[ -n "$(git -C "${REPO_DIR}" status --porcelain)" ]]; then
    warn "working tree is dirty:"
    git -C "${REPO_DIR}" status --short
    confirm "Release anyway?"
fi

printf '\n%s════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${RESET}"
printf '%s  Release %s %s%s\n' "${BLUE}" "${PKG_NAME}" "${VERSION}" "${RESET}"
printf '%s════════════════════════════════════════════════════════════%s\n\n' "${BLUE}" "${RESET}"
say "Image:    ${PYTHON_IMAGE}"
say "Repo:     ${REPO_DIR}"
say "Tag:      ${TAG}"
say "Flow:     checks → build → inspect → TestPyPI → smoke → PyPI → print tag/release commands"
[[ "${SKIP_GATES:-0}" == "1" ]]    && warn "SKIP_GATES=1: checks will be skipped"
[[ "${SKIP_TESTPYPI:-0}" == "1" ]] && warn "SKIP_TESTPYPI=1: going straight to PyPI"
echo
confirm "Proceed?"

# ── 1. checks ─────────────────────────────────────────────────────────────
if [[ "${SKIP_GATES:-0}" == "1" ]]; then
    warn "skipping lint/typecheck/tests (SKIP_GATES=1)"
else
    say "→ make check-all (lint, format, types, full suite, 100% coverage gate)"
    make -C "${REPO_DIR}" check-all
    ok "Checks passed"
fi

# ── 2. build ──────────────────────────────────────────────────────────────
BUILD_SHA="$(git -C "${REPO_DIR}" rev-parse HEAD)"
say "→ Building from ${BUILD_SHA}"

say "→ Cleaning previous artifacts"
rm -rf "${REPO_DIR}/dist" "${REPO_DIR}/build"

say "→ Building sdist + wheel inside ${PYTHON_IMAGE}"
in_container "${PYTHON_IMAGE}" bash -c '
    set -euo pipefail
    pip install --quiet --no-cache-dir --root-user-action=ignore --target /tmp/pip build twine
    export PYTHONPATH=/tmp/pip
    python -m build --outdir dist
    python -m twine check dist/*
'
echo
ls -lh "${REPO_DIR}/dist/"
echo
ok "Build + twine check passed"

# ── 3. inspect artifacts ──────────────────────────────────────────────────
say "→ Inspecting wheel and sdist contents against what this package promises"
docker run --rm -i -v "${REPO_DIR}/dist:/dist:ro" "${PYTHON_IMAGE}" \
    python - "${VERSION}" <<'PYEOF'
import re
import sys
import tarfile
import zipfile
from pathlib import Path

VERSION = sys.argv[1]
DIST = Path("/dist")
WHEEL = DIST / f"recursive_resolver-{VERSION}-py3-none-any.whl"
SDIST = DIST / f"recursive_resolver-{VERSION}.tar.gz"

errors, warnings = [], []

if not WHEEL.exists():
    print(f"FATAL: wheel missing: {WHEEL}")
    sys.exit(1)
with zipfile.ZipFile(WHEEL) as zf:
    wheel_names = set(zf.namelist())
    metadata = zf.read(f"recursive_resolver-{VERSION}.dist-info/METADATA").decode()
    wheel_file_count = sum(1 for n in wheel_names if not n.endswith("/"))

expected_wheel = {
    "recursive_resolver/__init__.py",
    "recursive_resolver/__main__.py",
    "recursive_resolver/addresses.py",
    "recursive_resolver/budget.py",
    "recursive_resolver/cache.py",
    "recursive_resolver/cli.py",
    "recursive_resolver/dnssec.py",
    "recursive_resolver/exceptions.py",
    "recursive_resolver/resolver.py",
    "recursive_resolver/roots.py",
    "recursive_resolver/singleflight.py",
    # Without this marker the Typing :: Typed classifier is a lie and every
    # downstream type checker silently sees Any.
    "recursive_resolver/py.typed",
    f"recursive_resolver-{VERSION}.dist-info/METADATA",
    f"recursive_resolver-{VERSION}.dist-info/WHEEL",
    f"recursive_resolver-{VERSION}.dist-info/RECORD",
    f"recursive_resolver-{VERSION}.dist-info/entry_points.txt",
}
missing = expected_wheel - wheel_names
if missing:
    errors.append(f"wheel missing required files: {sorted(missing)}")

forbidden = [
    ("tests/", lambda n: n.startswith("tests/")),
    ("scripts/", lambda n: n.startswith("scripts/")),
    (".pyc files", lambda n: n.endswith(".pyc")),
    ("__pycache__", lambda n: "__pycache__" in n),
    (".pytest_cache", lambda n: ".pytest_cache" in n),
]
for label, pred in forbidden:
    bad = [n for n in wheel_names if pred(n)]
    if bad:
        errors.append(f"wheel contains forbidden {label}: {bad[:3]}")

if not any("LICENSE" in n for n in wheel_names):
    errors.append("wheel does not bundle LICENSE")


def meta(key):
    m = re.search(rf"^{re.escape(key)}: (.+)$", metadata, re.MULTILINE)
    return m.group(1).strip() if m else None


if meta("Name") != "recursive-resolver":
    errors.append(f"METADATA Name: expected 'recursive-resolver', got {meta('Name')!r}")
if meta("Version") != VERSION:
    errors.append(f"METADATA Version: expected {VERSION!r}, got {meta('Version')!r}")

rp = meta("Requires-Python")
if not rp or "3.10" not in rp:
    errors.append(f"METADATA Requires-Python missing or not >=3.10: {rp!r}")

if not (meta("License-Expression") or meta("License")):
    errors.append("METADATA has no License or License-Expression")

dct = meta("Description-Content-Type")
if not dct or "markdown" not in dct.lower():
    errors.append(f"METADATA Description-Content-Type isn't markdown: {dct!r}")

# The dependency floor is a security floor, and there is exactly one canonical
# value for it: pyproject.toml, SECURITY.md, CONTRIBUTING.md and this check all
# say 2.8.0. Below 2.6.1 dnspython is affected by CVE-2023-29483, 2.6.0 broke
# UDP->TCP failover, and 2.7.0 is the first release with the EDNS and DNSSEC
# behaviour this package relies on.
deps = re.findall(r"^Requires-Dist: (.+)$", metadata, re.MULTILINE)
dnspython = [d for d in deps if d.startswith("dnspython")]
if not dnspython:
    errors.append("METADATA does not require dnspython")
else:
    spec = dnspython[0]
    if "dnssec" not in spec or "idna" not in spec:
        errors.append(f"dnspython requirement is missing the dnssec/idna extras: {spec!r}")
    m = re.search(r">=(\d+)\.(\d+)\.(\d+)", spec)
    if not m or tuple(int(x) for x in m.groups()) < (2, 8, 0):
        errors.append(f"dnspython floor is below the 2.8.0 security floor: {spec!r}")

if "Typing :: Typed" not in metadata:
    errors.append("METADATA missing the 'Typing :: Typed' classifier")
if "Topic :: Security" not in metadata:
    warnings.append("METADATA missing the 'Topic :: Security' classifier")
if f"# {'recursive-resolver'}" not in metadata:
    warnings.append("METADATA description does not contain the README heading")
for url in ("Homepage", "Repository", "Issues"):
    if f"Project-URL: {url}," not in metadata:
        warnings.append(f"METADATA missing Project-URL: {url}")

if not SDIST.exists():
    print(f"FATAL: sdist missing: {SDIST}")
    sys.exit(1)
with tarfile.open(SDIST) as tf:
    sdist_names = tf.getnames()

prefix = f"recursive_resolver-{VERSION}/"
sdist_rel = {n[len(prefix):] for n in sdist_names if n.startswith(prefix)}

expected_sdist = {
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "PKG-INFO",
    "src/recursive_resolver/__init__.py",
    "src/recursive_resolver/resolver.py",
    "src/recursive_resolver/dnssec.py",
    "src/recursive_resolver/py.typed",
}
missing_sdist = expected_sdist - sdist_rel
if missing_sdist:
    errors.append(f"sdist missing required files: {sorted(missing_sdist)}")

if not any(n.startswith("tests/") and n.endswith(".py") for n in sdist_rel):
    warnings.append("sdist contains no tests/*.py")

bad_sdist = [n for n in sdist_rel if n.endswith(".pyc") or "__pycache__" in n]
if bad_sdist:
    errors.append(f"sdist contains bytecode: {bad_sdist[:3]}")

print()
print(f"  Wheel:  {WHEEL.name}  ({WHEEL.stat().st_size // 1024} KB, {wheel_file_count} files)")
print(f"  Sdist:  {SDIST.name}  ({SDIST.stat().st_size // 1024} KB, {len(sdist_rel)} entries)")
print()
print("  METADATA highlights:")
for key in ("Name", "Version", "Requires-Python", "License-Expression",
            "License", "Description-Content-Type"):
    v = meta(key)
    if v:
        print(f"    {key:28s} {v}")
for d in deps:
    print(f"    {'Requires-Dist':28s} {d}")
print()

if warnings:
    print("  ⚠  Warnings:")
    for w in warnings:
        print(f"     {w}")
    print()

if errors:
    print("  ✗ Errors:")
    for e in errors:
        print(f"     {e}")
    print()
    sys.exit(1)

print("  ✓ All artifact checks passed")
PYEOF

echo
confirm "Artifacts look right?"

# ── 4. TestPyPI + smoke install ───────────────────────────────────────────
if [[ "${SKIP_TESTPYPI:-0}" != "1" ]]; then
    say "→ TestPyPI upload"
    echo "Get a token at https://test.pypi.org/manage/account/token/"
    echo "(Account-scoped on a first release; project-scoped afterwards.)"
    read_token "TestPyPI" TESTPYPI_TOKEN
    # Passed by name, not by value: "-e VAR=secret" would put the token in the
    # docker client's argv, where any local process can read it from ps.
    export TWINE_PASSWORD="${TESTPYPI_TOKEN}"

    in_container \
        -e TWINE_USERNAME=__token__ \
        -e TWINE_PASSWORD \
        "${PYTHON_IMAGE}" bash -c '
            set -euo pipefail
            pip install --quiet --no-cache-dir --root-user-action=ignore --target /tmp/pip twine
            export PYTHONPATH=/tmp/pip
            python -m twine upload --skip-existing --repository-url https://test.pypi.org/legacy/ dist/*
        '
    ok "Uploaded to TestPyPI"
    echo "  https://test.pypi.org/project/${PKG_NAME}/${VERSION}/"

    say "→ Smoke-installing ${PKG_NAME}==${VERSION} from TestPyPI and resolving for real"
    # Only the package under test comes from TestPyPI; dnspython, cryptography
    # and idna are resolved from real PyPI. The retry loop covers index
    # propagation lag after upload (~30s).
    docker run --rm -t "${PYTHON_IMAGE}" bash -c "
        set -euo pipefail
        for i in 1 2 3 4 5; do
            if pip install --quiet --no-cache-dir \
                --index-url https://test.pypi.org/simple/ \
                --extra-index-url https://pypi.org/simple/ \
                '${PKG_NAME}==${VERSION}'; then
                break
            fi
            echo 'index not yet propagated, retrying in 10s…'
            sleep 10
        done
        python - <<'SMOKE'
import recursive_resolver
from recursive_resolver import RecursiveResolver, ValidationState

assert recursive_resolver.__version__ == '${VERSION}', recursive_resolver.__version__

resolver = RecursiveResolver(max_resolution_time=25)

# A signed zone must validate.
signed = resolver.resolve_answer('cloudflare.com', 'A')
assert signed.dnssec is ValidationState.SECURE, signed.dnssec
assert signed.records

# A multi-chunk DKIM key must join with no separator.
dkim = resolver.resolve_answer('zendesk1._domainkey.zendesk.com', 'TXT')
value = dkim.text_values()[0]
assert '\" \"' not in value, value[:80]
assert 'p=' in value

print('smoke ok: version', recursive_resolver.__version__)
print('  cloudflare.com A ->', signed.records[0], '(' + signed.dnssec.value + ')')
print('  DKIM key joined  ->', value[:48] + '…')
SMOKE
        recursive-resolver --version
    "
    ok "Smoke install passed"
fi

# ── 5. PyPI ───────────────────────────────────────────────────────────────
echo
warn "The next step is irreversible: PyPI version numbers can never be reused."
confirm "Publish ${PKG_NAME} ${VERSION} to real PyPI?"

say "→ PyPI upload"
echo "Get a token at https://pypi.org/manage/account/token/"
read_token "PyPI" PYPI_TOKEN
export TWINE_PASSWORD="${PYPI_TOKEN}"

in_container \
    -e TWINE_USERNAME=__token__ \
    -e TWINE_PASSWORD \
    "${PYTHON_IMAGE}" bash -c '
        set -euo pipefail
        pip install --quiet --no-cache-dir --root-user-action=ignore --target /tmp/pip twine
        export PYTHONPATH=/tmp/pip
        # No --skip-existing here (unlike TestPyPI, where it makes retries
        # painless): on PyPI it would turn "this version is already published"
        # into a silent success, and we would go on to tag and cut a GitHub
        # release for artifacts PyPI never accepted.
        python -m twine upload dist/*
    '
echo
ok "${PKG_NAME} ${VERSION} released to PyPI"
echo "  https://pypi.org/project/${PKG_NAME}/${VERSION}/"

# ── 6. Tag and GitHub release: printed, not executed ──────────────────────
#
# The script stops short of touching git. Tagging rewrites local history and
# pushes to a shared remote, and cutting a release is a public act; neither
# should happen as a side effect of a script the operator is watching scroll
# past. Everything needed is prepared here and handed over as commands to run.
echo
say "→ Preparing the release notes"

if [[ "$(git -C "${REPO_DIR}" rev-parse HEAD)" != "${BUILD_SHA}" ]]; then
    warn "HEAD has moved since the build (${BUILD_SHA} -> $(git -C "${REPO_DIR}" rev-parse --short HEAD))"
    warn "the tag command below pins the commit that was actually built and published"
fi

# Take this version's section out of the changelog as the release notes. This
# goes to a real file rather than a mktemp: the gh command below is run by hand
# afterwards, so the notes have to outlive this process. `make clean` and the
# next run's "Cleaning previous artifacts" step both remove it with dist/.
NOTES_FILE="${REPO_DIR}/dist/RELEASE_NOTES_${VERSION}.md"
awk -v ver="${VERSION}" '
    $0 ~ "^## \\[" ver "\\]" { inside = 1; next }
    inside && /^## \[/       { exit }
    inside                   { print }
' "${REPO_DIR}/CHANGELOG.md" > "${NOTES_FILE}"
[[ -s "${NOTES_FILE}" ]] || die "extracted release notes for ${VERSION} are empty"
printf '\n---\n\nInstall: `pip install %s==%s`\n' "${PKG_NAME}" "${VERSION}" >> "${NOTES_FILE}"
ok "release notes written to ${NOTES_FILE}"

REPO_SLUG="$(git -C "${REPO_DIR}" remote get-url origin \
    | sed -E 's#\.git$##' \
    | sed -E 's#.*[:/]([^/]+/[^/]+)$#\1#')"

command -v gh >/dev/null \
    || warn "gh CLI not found: install it, or create the release from the web UI"

printf '\n%s════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${RESET}"
printf '%s  %s %s is on PyPI.%s\n' "${BLUE}" "${PKG_NAME}" "${VERSION}" "${RESET}"
printf '%s  Run these to tag it and cut the GitHub release:%s\n' "${BLUE}" "${RESET}"
printf '%s════════════════════════════════════════════════════════════%s\n\n' "${BLUE}" "${RESET}"

# Only the two artifact globs, never dist/*: the notes file lives there too and
# must not end up attached to the release.
cat <<EOF
git tag -a ${TAG} -m 'Release ${TAG}' ${BUILD_SHA}
git push origin ${TAG}

gh release create ${TAG} \\
    ${REPO_DIR}/dist/*.tar.gz ${REPO_DIR}/dist/*.whl \\
    --title ${TAG} \\
    --notes-file ${NOTES_FILE} \\
    --repo ${REPO_SLUG}
EOF

echo
echo "Once that is done: https://github.com/${REPO_SLUG}/releases/tag/${TAG}"
