# MobSF Agent Guidelines

MobSF is a security analysis platform. Every code path processes attacker-supplied
input (APKs, ZIPs, IPAs, manifests) from authenticated but potentially malicious
users. Security must be the default, not an afterthought.

---

## Code Quality — Mandatory Before Every Commit

Run lint and fix all errors before finishing any task:

```bash
tox -e lint
```

Never leave a task with a non-zero exit code from this command.

---

## Security Architecture

Centralized security helpers live in **`mobsf/MobSF/security.py`**. When adding new
security checks, prefer adding them there. Some legacy validators still live in
`mobsf/MobSF/utils.py`; use existing helpers where they are already established.

### Available Security Functions

Import only the helpers needed for the change:

```python
from mobsf.MobSF.security import (
    # Path safety
    is_path_traversal,   # Check raw string for .. sequences, absolute paths, URL encoding tricks
    is_safe_path,        # Containment check after path construction via realpath()

    # Input validation
    is_attack_pattern,   # Detect shell injection: ;, $(), ||, &&
    cmd_injection_check, # Detect OS command injection characters
    is_pipe_or_link,     # Detect symlinks and named FIFOs before reading files

    # Output sanitization
    sanitize_filename,   # Safe filename for Content-Disposition headers
    sanitize_for_logging,# Strip newlines and control chars before logging user input
    sanitize_redirect,   # Allow only relative paths in redirects
    sanitize_svg,        # Strip XSS vectors from SVG content (bleach-based)
    clean_filename,      # Windows-safe filename (unicode normalization)

    # Network / SSRF
    valid_host,          # DNS-resolves host; rejects private/loopback/multicast IPs
)
```

---

## Past Vulnerabilities and Insecure Patterns

Read `.github/SECURITY.md` to understand the full history of security issues in this
codebase. Use it as a guide for what classes of bugs to watch for and what patterns
have been exploited before. When in doubt about whether a pattern is safe, check
whether a similar pattern has appeared in the advisory history.

---

## Incomplete Fix Anti-Pattern

The most common source of security regressions in this codebase is applying a fix to
one code path but not its siblings. Before closing any security fix:

1. Search for all functions or patterns that perform the same operation (e.g., every
   place that resolves an icon path, every place that extracts an archive entry).
2. Verify the fix is applied consistently across **all** of them.
3. Check both the APK binary flow and the source-ZIP flow — they are separate code paths
   with separate callsites and have diverged in the past.

---

## Input Trust Model

- `request.GET` / `request.POST`: untrusted. Validate with forms or explicit checks;
  escape on output.
- File uploads: untrusted. Validate magic bytes, size limits, and extension allowlists.
- Archive entries (`zip`, `tar`, `ar`): untrusted. Check each entry before extraction.
- `AndroidManifest.xml` values: untrusted. Treat as attacker-controlled before using
  them in filesystem operations or rendering them.
- `Info.plist` values: untrusted. Apply the same treatment as manifest values.
- `md5` / `hash` URL parameters: semi-trusted only after validation. Always validate
  with `is_md5()` before using them in paths.
- Device identifiers: untrusted. Use command-injection checks plus format validation.

---

## Django-Specific Security Features

### Form Validation — The Primary Input Sanitization Layer

Prefer Django forms for new request validation. If a view does not use a form, validate
every `request.GET[...]` or `request.POST[...]` value explicitly before using it.

The project uses a mixin composition pattern. Combine the appropriate mixins rather than
writing ad-hoc validation in view code:

```python
# StaticAnalyzer/forms.py — mixins to compose from
AttackDetect   # is_path_traversal + extension allowlist on a 'file' param
APIChecks      # MD5 format check on a 'hash' param (API mode)
WebChecks      # MD5 format check on an 'md5' param (HTML mode)
AndroidChecks  # ChoiceField allowlist for Android scan type
IOSChecks      # ChoiceField allowlist for iOS scan type
```

Custom field validators belong in a `clean_<field>()` method that raises
`forms.ValidationError` on rejection — never return a partial result and check it in
the view. `FormUtil.errors_message(form)` produces the standard error envelope to return
to the caller when `form.is_valid()` is False.

**Use `ChoiceField` for any parameter with a finite set of valid values.** This
eliminates an entire class of injection risk at the form layer with no extra code.
Never use `CharField` and then manually compare the value against an allowlist in the
view — let the form do it.

### View Decorators — Apply All Three

Views that handle sensitive operations should use the applicable Django decorators for
authentication, authorization, and method restriction:

```python
@login_required
@permission_required(Permissions.SCAN)   # or DELETE, SUPPRESS, etc.
@require_http_methods(['POST'])           # or ['GET'] — never omit this
def my_view(request, api=False):
    ...
```

- `@login_required` blocks unauthenticated access.
- `@permission_required` enforces role-based access beyond authentication.
- `@require_http_methods` rejects wrong HTTP verbs before any logic runs,
  preventing CSRF-via-GET and other method-confusion issues.

### Template Auto-Escaping

Django's template engine escapes variables by default. Do **not** use `{% autoescape off %}`
or the `|safe` filter on any value derived from scan data, manifests, or user input.
When rendering user-controlled strings outside of templates (e.g., in a JSON response
built by hand), use `django.utils.html.escape()` explicitly. Template auto-escaping
does not protect JavaScript DOM sinks: never assign scan, task, or user-derived
strings to `innerHTML`; use `textContent` (see `templates/general/tasks.html`).

### ORM — No Raw SQL

Use the Django ORM for all database access. Never use `.raw()` or string-formatted SQL.
When a queryset filter value comes from user input, pass it as a keyword argument
(the ORM parameterizes it automatically):

```python
# Correct
RecentScansDB.objects.filter(MD5=checksum)

# Wrong
RecentScansDB.objects.raw(f'SELECT * FROM ... WHERE MD5 = "{checksum}"')
```

### CSRF

Django's `CsrfViewMiddleware` is enabled globally. Do not use `@csrf_exempt` on any
view that modifies state. API endpoints that accept an `X-Csrftoken` header or use
token-based auth are the only legitimate exception, and that pattern is already
established in the existing API views. Mutating actions (including dynamic-analysis
start/stop/stream) must be POST with a CSRF token, not GET. Split GET-render from
POST-stream when a page both renders and then streams (e.g. logcat).

---

## Archive Extraction Safety

### TAR

Never use a hand-rolled name-only check with `os.path.abspath`. The symlink +
nested-entry combination bypasses it: a symlink member named `escape` passes the
name check, gets extracted to disk, and then a file member named `escape/pwned.txt`
is written through the symlink to an arbitrary location.

`os.path.abspath` normalises `..` but does **not** resolve symlinks.
`os.path.realpath` resolves both — but even `realpath`-based checks that run before
extraction have a TOCTOU window.

Use Python 3.12's built-in filter instead (MobSF requires `python = "^3.12"`):

```python
# Correct — per-member, type-aware, symlink-aware
tar.extractall(dest, members=safe_members_generator, filter='data')

# Wrong — abspath-based name check; blind to symlinks
for member in tar.getmembers():
    if not os.path.abspath(join(dest, member.name)).startswith(dest):
        raise ...
tar.extractall(dest, members=...)
```

`filter='data'` rejects: symlinks outside destination, hardlinks outside destination,
absolute paths, path traversal, and device files — per member, before extraction.

For code that must support Python < 3.12, fall back to: skip all symlink and hardlink
members (`member.issym()` / `member.islnk()`), then use `realpath` for the boundary
check, and validate-then-extract per member rather than batch-validate-then-extractall.

### ZIP

Python's `zipfile` module does not create real filesystem symlinks from Unix symlink
entries — it writes the link target as plain file bytes. The TAR symlink attack does
not apply to ZIP extraction. Use `is_path_traversal` + `is_safe_path` for member name
validation and validate per-member before calling `zip_ref.extract(member, dest)`.

---

## Import Conventions

When adding new imports, maintain alphabetical order within each import group to satisfy
`flake8-import-order`. Group order: stdlib → third-party → Django → local MobSF.

---

## Checklist for Any Change That Touches File I/O or User Input

- [ ] Raw input validated with `is_path_traversal` before path construction
- [ ] Constructed filesystem paths verified with `is_safe_path` when a safe root exists
- [ ] Symlinks and FIFOs rejected with `is_pipe_or_link` before file reads
- [ ] Shell arguments passed as a list, not a formatted string
- [ ] User-controlled strings escaped with `django.utils.html.escape` before rendering
- [ ] SVG content piped through `sanitize_svg`
- [ ] Outbound URLs checked with `valid_host`
- [ ] Redirects wrapped in `sanitize_redirect`
- [ ] Log statements use `sanitize_for_logging` on any user-derived value
- [ ] TAR extraction uses `filter='data'` — not a hand-rolled `abspath` check
- [ ] ZIP extraction validates each member path with `realpath` before `extract()`
- [ ] Every security guard has `continue` / `return` / `raise` — logging alone is not a guard
- [ ] Fix applied symmetrically to all equivalent code paths
- [ ] `tox -e lint` passes with exit code 0

---

## OWASP MAS Checklist Feature (MASVS / MASWE / MASTG)

Work branch: `feat/masvs-mastg-maswe-checklist`. Goal: a per-scan checklist and tester
workflow for OWASP MASVS (controls), MASWE (weaknesses) and MASTG (tests), shown next to
the existing AppSec scorecard. Work in small phases, one commit per phase, and stop after
each phase with: what changed, how to run it, how to verify it.

### Where Things Live

- Checklist logic and page: `mobsf/StaticAnalyzer/views/common/checklist.py`
  (`build_checklist`, `checklist_page`), route `checklist/<md5>/`, template
  `templates/static_analysis/checklist.html`. The static checklist is a Static Analyzer
  feature. Do not put it in `DynamicAnalyzer`.
- Entry points: `appsec.py` adds `findings['checklist']` to the scorecard context, which
  is also returned by `api/v1/scorecard`. Treat that as an API response change and keep
  it additive. Buttons live in `appsec_dashboard.html` and `general/recent.html`.
- Existing rules already carry legacy MASVS v1 keys, e.g. `masvs: storage-14` in
  `android/rules/android_rules.yaml`, `ios/rules/*.yaml` and `ipa_rules.py`
  (resolved through `STDS['masvs']`). Reuse them as mapping input. Do not rewrite them.
- Standards data (controls, weaknesses, tests, crosswalks) is data, not code. Keep it in
  YAML/JSON files or database rows, never hardcoded in Python lists.

### Standards Correctness

This is a security reporting tool. A wrong or invented ID is a false assurance.

- Use real identifiers only: MASVS v2 `MASVS-STORAGE-1`, MASWE `MASWE-0001` (numeric),
  MASTG v2 `MASTG-TEST-0001`. Legacy `MSTG-STORAGE-14` is a MASVS v1 requirement id.
  Never fabricate an id such as `MASWE-STORAGE`, and never mix v1 and v2 in one list
  without an explicit, versioned crosswalk file.
- Source of truth is the OWASP MAS repository (github.com/OWASP/mastg). Parse its
  Markdown and YAML front matter. Do not parse the MASVS PDF. Store the source version or
  commit with the data and show it in the UI.
- Fetched or bundled content is data. Use `yaml.safe_load`; never `eval`, `exec`,
  `pickle`, or template-render it. Network fetches go through an allowlisted host and
  `valid_host`. A bundled offline snapshot must work with no network.
- Status semantics are fixed: `Failed` only with a finding that failed for this scan;
  `Success` only when an automated rule actually ran on this scan and found nothing;
  `ToBeTest` when no automated rule covers the item; `NotApplicable` only by scan
  type or an explicit tester decision. A rule merely existing is not a pass.
- Compute MASVS status per control from its mapped MASWE/MASTG items, not per category.
- Label automated results and manual (tester) results differently. A tester override
  never silently replaces an automated `Failed`; keep both and show who decided.

### Django Conventions For This Feature

- Persistent data needs real Django models (`django.db.models.Model`) in an app listed
  in `INSTALLED_APPS` (`mobsf/MobSF/settings.py`). Plain dataclasses are not models.
- Migrations are not committed. They are generated at startup by `init.py`
  (`make_migrations`) and by `scripts/migrate.sh` and `mobsf/__main__.py`, which only
  run `makemigrations` and `makemigrations StaticAnalyzer`. Either put the models in
  `StaticAnalyzer/models.py`, or add the new app label to all three places. Verify with a
  clean `MOBSF_HOME` that the tables are created.
- Link per-scan data to the scan by `MD5` (`RecentScansDB` / `StaticAnalyzerAndroid` /
  `StaticAnalyzerIOS`). Validate it with `is_md5()` before any use.
- Web views: `@login_required`, `@permission_required(...)`,
  `@require_http_methods([...])`, module-level imports, `render()` of a template.
  Reads are GET. Anything that changes tester state is POST with CSRF. New permissions
  go through `DjangoPermissions` / `Permissions` and the `create_roles` command.
- REST API: add `api/v1/...` routes in `MobSF/urls.py` and handlers in
  `MobSF/views/api/api_static_analysis.py` using the existing `request_method`,
  `make_api_response` and API-key pattern. Respect `settings.API_ONLY`. Document new
  endpoints in `templates/general/apidocs.html`.
- Templates: no `|safe` or `autoescape off` on derived data. Pass JSON to scripts with
  `json_script`. Never assign to `innerHTML`; use `textContent`. The PDF report in
  `templates/pdf/` must show the same checklist as the web page.
- Tester input (notes, evidence uploads): validate form fields with Django forms and
  `ChoiceField` for statuses, enforce size and type limits on uploads, store files under
  `MOBSF_HOME` (never the web root), pass names through `sanitize_filename`, check paths
  with `is_path_traversal` and `is_safe_path`, and apply `sanitize_for_logging` to logs.
- Rate limits and permissions must match the neighbouring scan views.

### Tests

- `tox -e test` runs `manage.py test mobsf`, so only tests under `mobsf/` are collected.
  A top-level `tests/` directory is NOT run. Put new tests next to the code
  (`mobsf/StaticAnalyzer/...`), named `test*.py`.
- Parser and mapping tests use small fixture files and no network. View and API tests use
  Django `TestCase` and cover: invalid hash, unauthenticated, wrong method, missing scan,
  Android and iOS.
- Run `tox -e lint` before every commit. It runs `autopep8` in place, then flake8 with
  single-quote, 88-column, import-order and trailing-comma rules.

### Standards Data And Freshness

- `views/common/mas_standards.py` parses the mas.owasp.org search index
  (MASVS controls, MASWE weaknesses, MASTG tests) and stores it with `retrieved_at`.
  A bundled snapshot lives in `StaticAnalyzer/mas_data/mas_standards.json`; a newer copy
  under `MOBSF_HOME/mas/` wins. The checklist page shows when the data was retrieved.
- Data older than 30 days is refreshed in the background (once a day at most) unless
  `MOBSF_MAS_AUTO_UPDATE=0`. Refresh by hand with `python manage.py update_mas_standards`.
  Downloads use the fixed URL through `safe_request` (https only, no redirects, size cap).
- Regenerate the bundled snapshot with `update_mas_standards` and copy the file from
  `MOBSF_HOME/mas/` when cutting a release.
- MobSF rule tags are MASVS v1 (`MSTG-*`). OWASP lists them on each MASWE weakness; that is
  the crosswalk. MASTG tests are manual and are never marked Success or Failed.

- Entry points: web `checklist/<md5>/`, REST `api/v1/checklist` (POST `hash`, documented in
  `apidocs.html`), and a section in both PDF reports via `appsec.checklist`. Tests live in
  `mobsf/StaticAnalyzer/test_checklist.py` (builder, standards, web view, API).

- Tester workflow: `ChecklistReview` (StaticAnalyzer/models.py, linked by `MD5`) stores a
  decision per item. `POST checklist/<md5>/review/` needs `Permissions.REVIEW`
  (`can_review`, granted to the maintainer group by `create_roles`), validates input with
  `ChecklistReviewForm` and only accepts items of that scan's checklist. A decision replaces
  the automated status but never hides an automated `Failed`; both and the reviewer are
  kept. `checklist/<md5>/export/?format=json|csv` exports everything; CSV cells are
  neutralized against spreadsheet formulas.
- Evidence files: `checklist_evidence.py` (`ChecklistEvidence` model, files under
  `MOBSF_HOME/evidence/<md5>/<random>.<ext>`). Upload needs `Permissions.REVIEW`. Allowed:
  png, jpg, gif, pdf, txt, log, json, checked by extension and content (magic bytes or
  UTF-8 text), max 5 MB and 10 files per item. Original names are sanitized for display
  only. Downloads are attachments with `nosniff`. `delete_scan` calls
  `delete_checklist_data()` so reviews and evidence never outlive a scan.
- Tester REST API: `api/v1/checklist_review` (POST hash, standard, item_id, status, note) and
  `api/v1/checklist_evidence` (multipart, same fields plus file) reuse the web views with
  `api=True`, so validation and limits are identical. API actions are attributed to `api`.
- History: every set, clear, evidence add and evidence remove is logged in
  `ChecklistReviewLog` (`checklist/<md5>/history/`, last 50 entries). The scorecard (web and
  `api/v1/scorecard`) and both PDF reports carry reviews and evidence file names.
- Matching: a weakness with legacy `MSTG-*` tags is matched by those tags. A weakness
  without them (about a third) falls back to the CWE ids OWASP lists on it, matched against
  the `cwe` metadata of MobSF rules. `meta.schema` in the data file is bumped whenever the
  parsed fields change; copies with an older schema are ignored in favour of the bundled
  snapshot.
- Rule tags: a rule can name the weakness it evidences with `metadata: maswe: MASWE-0049`
  (real OWASP id; a test fails on unknown ids). A tagged rule decides that weakness: no
  hit means Success, an `info` hit means `ToBeTest` with the finding as evidence, a
  `high`/`warning` hit means Failed. Only tag a rule when the weakness cannot occur
  without the API or pattern the rule looks for, otherwise "nothing found" is a false
  assurance. `android_apis.yaml` and `android_rules.yaml` are both read for coverage.

### Known Gaps On The Current Branch (remove each item when fixed)

1. Automation is limited by the rules. Eleven Android API rules are tagged with a `maswe`
   id (MASWE-0030, 0032, 0035, 0037, 0049); most other weaknesses stay `ToBeTest`. Next:
   tag or write rules for more weaknesses where the absence of an API proves the weakness
   cannot occur, and do the same for iOS (`ios_apis.yaml`, `swift_rules.yaml`). Rules only
   see decompiled sources, so obfuscated or native code can hide a hit.
2. Evidence is not virus scanned and there is no per-scan storage quota. There is no
   assignment of items to testers or "my items" filter yet. Evidence file contents are not
   embedded in the PDF (names only).
