#!/usr/bin/env python3
"""
Browser smoke test: drives the real dashboard in headless Chromium through the path a new
customer takes, against a server that has just been started with NO users.

  setup (with the setup code) -> sign in -> first-run welcome -> create an organization
  (with a data-since date) -> issue an agent key -> an agent sends a log line -> the
  violation shows in the ledger -> acknowledge and resolve it -> verify the hash chain ->
  Policy tab shows the date -> Users tab: add a user, reset the password, the user is forced
  to choose their own on first sign-in.

Environment:
  VERITAS_URL         default https://localhost:8000
  VERITAS_SETUP_CODE  the server's setup code (required)
  SMOKE_SHOTS         directory for screenshots (default ./smoke-shots)

Any uncaught JavaScript error on any page fails the run.
"""
from __future__ import annotations

import os
import re
import sys
from datetime import date, timedelta
from pathlib import Path

import requests
import urllib3
from playwright.sync_api import Page, expect, sync_playwright

urllib3.disable_warnings()

URL = os.environ.get("VERITAS_URL", "https://localhost:8000").rstrip("/")
CODE = os.environ["VERITAS_SETUP_CODE"]
SHOTS = Path(os.environ.get("SMOKE_SHOTS", "smoke-shots"))
SHOTS.mkdir(parents=True, exist_ok=True)

ADMIN, ADMIN_PW = "smoke_admin", "Violet-Harbor#2468"
ORG = "smoke_org"
NEW_USER = "smoke_viewer"
NEW_USER_PW = "Orchid-Lantern#9753"
TIMEOUT = 20_000

js_errors: list[str] = []
outside_requests: list[str] = []      # anything the dashboard asked for from beyond this machine
console_errors: list[str] = []


def step(msg: str) -> None:
    print(f"\n==> {msg}", flush=True)


def _leaves_this_machine(url: str) -> bool:
    from urllib.parse import urlparse
    u = urlparse(url)
    return u.scheme in ("http", "https", "ws", "wss") and u.hostname not in ("localhost", "127.0.0.1", "::1")


def watch(page: Page, name: str) -> None:
    page.on("request", lambda r: outside_requests.append(f"[{name}] {r.url}") if _leaves_this_machine(r.url) else None)
    page.on("pageerror", lambda e: js_errors.append(f"[{name}] {e}"))
    page.on("console", lambda m: console_errors.append(f"[{name}] {m.text}")
            if m.type == "error" and "Failed to load resource" not in m.text else None)


def shot(page: Page, name: str) -> None:
    page.wait_for_timeout(500)      # let fade-in/out animations settle
    page.screenshot(path=str(SHOTS / f"{name}.png"), full_page=True)


def sign_in(page: Page, user: str, password: str) -> None:
    page.goto(f"{URL}/login")
    page.fill("#username", user)
    page.fill("#password", password)
    page.click("#submitBtn")


def flow(browser, pages: list) -> None:
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
    ctx.set_default_timeout(TIMEOUT)
    page = ctx.new_page()
    watch(page, "admin")
    pages.append(page)

    # ── 1. A server with no users sends every visitor to setup ──────────
    step("fresh server redirects to /setup")
    page.goto(f"{URL}/")
    expect(page).to_have_url(re.compile(r"/setup"))
    shot(page, "01-setup")

    step("setup refuses a wrong setup code, accepts the right one")
    page.fill("#setupCode", "wrong-code")
    page.fill("#username", ADMIN)
    page.fill("#email", "smoke@example.com")
    page.fill("#password", ADMIN_PW)
    page.fill("#confirm", ADMIN_PW)
    expect(page.locator("#pwHints")).to_contain_text("At least 10 characters")
    expect(page.locator("#pwHints")).to_contain_text("Strong")
    page.click("#submitBtn")
    expect(page.locator("body")).to_contain_text(re.compile("setup code", re.I))
    assert "/setup" in page.url
    page.fill("#setupCode", CODE)
    page.click("#submitBtn")
    expect(page).to_have_url(re.compile(r"/login"), timeout=15_000)

    # ── 2. Sign in, first-run screen ────────────────────────────────────
    step("sign in; a dashboard with no organization shows the welcome guide")
    sign_in(page, ADMIN, ADMIN_PW)
    expect(page.locator("#userBadge")).to_be_visible()
    expect(page.locator("#welcomeOverlay")).to_have_class(re.compile("visible"))
    expect(page.locator("#welcomeOverlay")).to_contain_text("Configure your organisation")
    page.wait_for_timeout(600)          # let the fade-in finish before the screenshot
    shot(page, "02-welcome")
    assert page.locator("#serverVersion").inner_text().startswith("Veritas"), "sidebar version label missing"
    assert "3.0.0-generic" not in page.content(), "a made-up version number is still on the page"

    # ── 3. Create the organization through the form ─────────────────────
    step("create an organization with a 'data since' date")
    page.click("#welcomeOverlay button:has-text('Configure Organisation')")
    expect(page.locator("#addOrgModal")).to_be_visible()
    expect(page.locator("#welcomeOverlay")).not_to_have_class(re.compile("visible"))   # not covering the form
    page.click("#addOrgModal .modal-close")                                            # cancel: welcome returns
    expect(page.locator("#welcomeOverlay")).to_have_class(re.compile("visible"))
    page.click("#welcomeOverlay button:has-text('Configure Organisation')")
    page.fill("#newOrgId", ORG)
    row = page.locator("#orgFieldsRows .fields-row").first
    row.locator(".f-field_name").fill("aadhaar")
    row.locator(".f-pii_category").fill("aadhaar")
    row.locator(".f-declared_purpose").fill("onboarding_kyc")
    row.locator(".f-consent_scope").fill("onboarding_kyc")
    row.locator(".f-retention_days").fill("180")
    row.locator(".f-source_system").fill("kyc-service")
    since = (date.today() - timedelta(days=30)).isoformat()
    row.locator(".f-data_since").fill(since)
    page.click("button:has-text('Add Identifier')")
    ident = page.locator("#orgIdentifiersRows .identifiers-row").first
    ident.locator(".i-name").fill("aadhaar")
    ident.locator(".i-pattern").fill("indian_aadhaar")
    ident.locator(".i-validator").select_option("aadhaar")
    shot(page, "03-org-form")
    page.click("#addOrgSubmitBtn")
    expect(page.locator("#toast")).to_contain_text("created")
    expect(page.locator("#orgSelector")).to_have_value(ORG)
    expect(page.locator("#welcomeOverlay")).not_to_have_class(re.compile("visible"))

    # ── 4. Issue an agent key in the UI ─────────────────────────────────
    step("issue a registration key from the Agents tab")
    page.click("#nav-agents")
    page.click("button:has-text('Issue Registration Key')")
    page.click("button:has-text('Generate Key')")
    key_el = page.locator("#issueKeyValue")
    expect(key_el).not_to_have_text("")
    key = key_el.inner_text().strip()
    assert key.startswith("VRT-") or len(key) > 20, f"unexpected key shape: {key!r}"
    shot(page, "04-issued-key")
    page.click("#issueKeyModal button:has-text('Done')")

    # ── 5. An agent registers with that key and sends one log line ──────
    step("an agent registers with the key and forwards a log line holding an Aadhaar number")
    s = requests.Session()
    s.verify = False
    reg = s.post(f"{URL}/agent/register", json={"registration_key": key, "source_label": "smoke-agent"}, timeout=30)
    assert reg.status_code == 200, reg.text
    r = reg.json()
    ev = s.post(f"{URL}{r['event_endpoint']}", timeout=30,
                headers={"Authorization": f"Bearer {r['auth_token']}"},
                json={"source_type": "log", "source_system": "kyc-service",
                      "raw_snippet": "DEBUG customer verified with Aadhaar 2345 6789 0124"})
    assert ev.status_code == 200, ev.text
    page.click("#nav-agents")
    page.click("button:has-text('Refresh')") if page.locator("#main-agents button:has-text('Refresh')").count() else None

    # ── 6. The violation in the ledger: acknowledge, resolve, verify ────
    step("the finding is grouped into an incident in the Audit Ledger")
    page.click("#nav-audit")
    inc_row = page.locator("#incTbody tr", has_text="EXPOSURE_001").first
    expect(inc_row).to_be_visible()
    expect(page.locator("#incSummary")).to_contain_text("incident")
    shot(page, "05a-incidents")
    inc_row.locator("button:has-text('Findings')").click()
    expect(page.locator("#incTbody .inc-detail").first).to_contain_text("Details")
    inc_row.locator("button:has-text('Acknowledge')").click()
    expect(page.locator("#toast")).to_contain_text("ACKNOWLEDGED")
    expect(page.locator("#incTbody .status-badge.ACKNOWLEDGED").first).to_be_visible()

    step("the same finding in the list of all findings")
    page.click("#viewVerdicts")
    first_row = page.locator("#auditTbody tr", has_text="EXPOSURE_001").first
    expect(first_row).to_be_visible()
    shot(page, "05-ledger")

    step("acknowledge and resolve the finding")
    first_row.locator("button:has-text('Details')").click()
    expect(page.locator("#whyBody")).to_contain_text("Personal data where it should not be")      # why this fired: the rule's conditions
    expect(page.locator("#whyBody")).to_contain_text("a kind of personal data was detected")
    page.click("#drawerContent button:has-text('Acknowledge')")
    expect(page.locator("#toast")).to_contain_text("ACKNOWLEDGED")
    page.click("#drawerContent button:has-text('Mark as Resolved')")
    expect(page.locator("#toast")).to_contain_text("RESOLVED")
    expect(page.locator("#drawerContent button:has-text('Fully Resolved')")).to_be_visible()
    page.click("#drawer .drawer-close, #drawer [onclick*='closeDrawer']")
    expect(page.locator("#auditTbody .status-badge.RESOLVED").first).to_be_visible()

    step("the observed processing map shows the system, its open incident and exports the record")
    page.click("#nav-flows")
    node = page.locator("#flowSvg g.flow-node", has_text="kyc-service")
    expect(node).to_be_visible()
    expect(node).to_have_attribute("aria-label", "kyc-service: red")
    node.click()
    expect(page.locator("#flowPanel")).to_contain_text("Open incidents")
    shot(page, "05b-data-map")
    with page.expect_download() as dl:
        page.click("#main-flows button:has-text('Record (CSV)')")
    assert dl.value.suggested_filename.endswith(".csv")
    page.click("#nav-audit")

    step("rules: the six rules, propose a change, approve it as the only administrator, and open the exception form")
    page.click("#nav-rules")
    expect(page.locator("#rulesTbody tr")).to_have_count(6)
    expect(page.locator("#rulesNote")).to_contain_text("not a legal conclusion")
    page.locator("#rulesTbody tr", has_text="EXPOSURE_001").locator("button:has-text('Propose change')").click()
    page.select_option("#rfSeverity", "MEDIUM")
    page.fill("#rfReason", "smoke test")
    page.click("#ruleForm button:has-text('Propose')")
    expect(page.locator("#toast")).to_contain_text("Proposed")
    page.locator("#ruleChangesTbody tr", has_text="EXPOSURE_001").locator("button:has-text('Approve')").click()
    expect(page.locator("#ruleChangesTbody")).to_contain_text("APPROVED")
    expect(page.locator("#rulesTbody tr", has_text="EXPOSURE_001")).to_contain_text("severity MEDIUM")
    page.click("#main-rules button:has-text('Propose an exception')")
    expect(page.locator("#ruleForm")).to_contain_text("always ends")
    shot(page, "05c-rules")
    page.click("#nav-audit")

    step("look an identifier up, open an erasure request, confirm the task and download the signed record")
    page.click("#nav-requests")
    page.click("#main-requests button:has-text('Look up an identifier')")
    page.select_option("#lookupCategory", "aadhaar")
    page.fill("#lookupIdentifier", "2345 6789 0124")
    page.click("#lookupModal button:has-text('Look up')")
    expect(page.locator("#lookupResult")).to_contain_text("kyc-service")
    expect(page.locator("#lookupIdentifier")).to_have_value("")          # the identifier does not stay in the page
    page.click("#lookupModal .modal-close")
    page.click("#main-requests button:has-text('New request')")
    page.fill("#reqRef", "SMOKE-1")
    page.fill("#reqIdentifiers .req-id", "2345 6789 0124")
    page.select_option("#reqIdentifiers .req-cat", "aadhaar")
    page.click("#requestModal button:has-text('Create request')")
    expect(page.locator("#reqDetail")).to_contain_text("SMOKE-1")
    expect(page.locator("#reqDetail")).to_contain_text("kyc-service")
    page.click("#reqDetail button:has-text('Confirm')")
    expect(page.locator("#reqDetail")).to_contain_text("CLOSED")
    with page.expect_download() as rec:
        page.click("#reqDetail button:has-text('Record (PDF)')")
    assert rec.value.suggested_filename.endswith(".pdf")
    shot(page, "05c-rights-request")
    page.click("#nav-audit")

    step("verify the cryptographic hash chain")
    page.click("button:has-text('Verify Cryptographic Hash Chain')")
    expect(page.locator("#integrityResult")).to_contain_text("chain intact")
    shot(page, "06-chain-verified")

    step("hostile names are refused by the API and cannot run script in the dashboard")
    evil = '<img src=x onerror="window.__xss=1">'
    refused = page.evaluate("""async (evil) => {
        const r = await fetch('/v1/%s/scan', {method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text: 'hello', source_system: evil})});
        return r.status;
    }""" % ORG, evil)
    assert refused == 422, f"markup in a source name was accepted by the scan API (status {refused})"
    # even if such a name were already stored, the dashboard must show it as text
    page.evaluate("""(evil) => {
        const v = {severity: 'HIGH', rule_id: evil, source_system: evil, field: evil, explanation: evil,
                   section_cited: evil, verdict_id: evil, violation_id: evil};
        document.body.appendChild(buildViolationCard(v));
        showToast(evil, 'success');
    }""", evil)
    page.wait_for_timeout(500)
    assert page.evaluate("window.__xss") is None, "script from a hostile name ran in the dashboard"
    assert page.locator("img[onerror]").count() == 0, "a hostile name became an element in the dashboard"
    assert page.locator("text=onerror").count() >= 1, "the hostile name should be visible as plain text"

    # ── 7. Policy tab shows the data-since date ─────────────────────────
    step("Policy tab shows the 'data since' date")
    page.click("#nav-policy")
    expect(page.locator("#policyFieldsTbody")).to_contain_text(since)
    shot(page, "07-policy")

    step("Edit Policy opens the form already filled in, with the organization fixed")
    page.click("#main-policy button:has-text('Edit Policy')")
    expect(page.locator("#newOrgId")).to_have_js_property("readOnly", True)   # set once the policy has loaded
    expect(page.locator("#newOrgId")).to_have_value(ORG)
    expect(page.locator("#orgFieldsRows .f-data_since").first).to_have_value(since)
    page.click("#addOrgModal .modal-close")

    step("saving the policy in the dashboard keeps the sections its form does not edit (owners)")
    page.evaluate("""async (org) => {
        const r = await fetch(`/v1/orgs/${org}/config`, {credentials: 'include'});
        const d = await r.json(); const c = d.config || d;
        c.owners = {'kyc-service': {team: 'Risk', email: 'risk@example.com'}};
        c.notices = [{notice_id: 'n-smoke', version: '1', effective_from: '2026-01-01', data_categories: ['aadhaar'], systems: ['kyc-service']}];
        await fetch(`/v1/orgs/${org}/config`, {method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(c)});
    }""", ORG)
    page.click("#main-policy button:has-text('Edit Policy')")
    expect(page.locator("#newOrgId")).to_have_js_property("readOnly", True)
    page.click("#addOrgSubmitBtn")
    expect(page.locator("#toast")).to_contain_text("updated")
    owners = page.evaluate("""async (org) => { const r = await fetch(`/v1/orgs/${org}/config`, {credentials: 'include'});
                                               const d = await r.json(); return (d.config || d).owners; }""", ORG)
    assert owners and owners["kyc-service"]["team"] == "Risk", f"the dashboard dropped the owners when saving the policy: {owners}"
    notices = page.evaluate("""async (org) => { const r = await fetch(`/v1/orgs/${org}/config`, {credentials: 'include'});
                                                const d = await r.json(); return (d.config || d).notices; }""", ORG)
    assert notices and notices[0]["notice_id"] == "n-smoke" and notices[0]["data_categories"] == ["aadhaar"], f"the notices did not survive a save: {notices}"

    # ── 8. Users: add, reset, forced password change ────────────────────
    step("Users tab: add a viewer and give it access to the organization")
    page.click("#nav-users")
    page.click("#main-users button:has-text('Add User')")
    page.fill("#addUserName", NEW_USER)
    page.fill("#addUserEmail", "viewer@example.com")
    page.select_option("#addUserRole", "VIEWER")
    page.fill("#addUserPassword", "Initial-Pass#1357")
    page.click("#addUserModal button:has-text('Create User')")
    user_row = page.locator("#usersTbody tr", has_text=NEW_USER)
    expect(user_row).to_be_visible()
    expect(user_row).to_contain_text("Must set password")
    user_row.locator("select", has_text="+ add").select_option(ORG)
    expect(page.locator("#usersTbody tr", has_text=NEW_USER)).to_contain_text(ORG)
    shot(page, "08-users")

    step("reset the viewer's password: a temporary password is shown once")
    page.locator("#usersTbody tr", has_text=NEW_USER).locator("button:has-text('Reset password')").click()
    page.click("#resetPwModal button:has-text('Generate Temporary Password')")
    expect(page.locator("#resetPwStep2")).to_be_visible()
    temp = page.locator("#resetPwValue").inner_text().strip()
    assert len(temp) >= 12, temp
    shot(page, "09-reset-password")
    page.click("#resetPwModal button:has-text('Done')")

    step("the new user signs in with the temporary password and must choose their own")
    ctx2 = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
    ctx2.set_default_timeout(TIMEOUT)
    page2 = ctx2.new_page()
    pages.append(page2)
    watch(page2, "viewer")
    sign_in(page2, NEW_USER, temp)
    expect(page2.locator("#accountModal")).to_have_class(re.compile("open"))
    expect(page2.locator("#accountTitle")).to_have_text("Choose a new password")
    shot(page2, "10-forced-change")
    page2.fill("#accCurrent", temp)
    page2.fill("#accNew", "short")
    expect(page2.locator("#accHints")).to_contain_text("Too weak")
    page2.fill("#accNew", "password123")
    page2.fill("#accNew2", "password123")
    page2.click("#accountModal button:has-text('Change Password')")
    expect(page2.locator("#accountError")).to_contain_text("too common")
    page2.fill("#accNew", NEW_USER_PW)
    page2.fill("#accNew2", NEW_USER_PW)
    page2.click("#accountModal button:has-text('Change Password')")
    expect(page2.locator("#userBadge")).to_contain_text(NEW_USER)
    expect(page2.locator("#accountModal")).not_to_have_class(re.compile("open"))
    expect(page2.locator("#orgSelector")).to_have_value(ORG)

    step("a viewer sees no admin screens")
    for nav in ("nav-users", "nav-auditlog", "nav-policy"):
        expect(page2.locator(f"#{nav}")).to_be_hidden()
    shot(page2, "11-viewer-dashboard")

    step("the administrator's Users tab now shows the user as active")
    page.click("#main-users button:has-text('Refresh')")
    expect(page.locator("#usersTbody tr", has_text=NEW_USER)).to_contain_text("Active")

    step("resetting the password ends the open session: the viewer's page goes to the sign-in page by itself")
    page.locator("#usersTbody tr", has_text=NEW_USER).locator("button:has-text('Reset password')").click()
    page.click("#resetPwModal button:has-text('Generate Temporary Password')")
    expect(page.locator("#resetPwStep2")).to_be_visible()
    page.click("#resetPwModal button:has-text('Done')")
    expect(page2).to_have_url(re.compile(r"/login"), timeout=20_000)
    shot(page2, "12-viewer-session-ended")

    step("the administrator can sign out with the visible button")
    expect(page.locator("#signOutBtn")).to_be_visible()
    page.click("#signOutBtn")
    expect(page).to_have_url(re.compile(r"/login"))




def run(pages: list) -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            flow(browser, pages)
        except BaseException:
            for i, pg in enumerate(pages):      # a picture of where it stopped, taken while the browser is open
                try:
                    shot(pg, f"FAILED-page{i}")
                except Exception:
                    pass
            raise
        finally:
            browser.close()

    print("\nconsole errors seen (informational):", *console_errors, sep="\n  ")
    if js_errors:
        print("\nFAIL: uncaught JavaScript errors:", *js_errors, sep="\n  ", file=sys.stderr)
        return 1
    if outside_requests:
        # an air-gapped customer must see no request that leaves the machine (no fonts, scripts, maps or analytics)
        print("\nFAIL: the dashboard asked for resources from outside this machine:", *sorted(set(outside_requests)), sep="\n  ", file=sys.stderr)
        return 1
    print("\nBROWSER SMOKE TEST PASSED")
    return 0


def main() -> int:
    try:
        return run([])
    finally:
        if js_errors:
            print("JavaScript errors seen:", *js_errors, sep="\n  ", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
