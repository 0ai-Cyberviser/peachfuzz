# Defensive Security Test Checklist (Authorized Scope)

Use this checklist only for assets you own or are explicitly authorized to test.

## 1) Scope and Authorization

- [ ] Written scope includes domains, subdomains, repos, and environments.
- [ ] Approved testing window with timezone and emergency stop condition.
- [ ] Incident contact list (primary + backup) is validated.
- [ ] Data handling rules documented (PII, credentials, production data).

## 2) GitHub and SDLC Security

- [ ] CodeQL enabled for all active repositories.
- [ ] Dependabot alerts enabled and update PRs configured.
- [ ] Secret scanning and push protection enabled.
- [ ] Branch protection: required reviews + required checks + signed commits.
- [ ] SECURITY.md and responsible disclosure process are current.

## 3) CI Security Pipeline (PR Gate)

- [ ] SAST passes (Semgrep / CodeQL).
- [ ] Dependency vulnerability checks pass (OSV, pip-audit, npm audit where applicable).
- [ ] Container image/filesystem scan passes (Trivy) for build artifacts.
- [ ] IaC checks pass (Checkov) for Terraform/Kubernetes/Cloud templates.
- [ ] Failing HIGH/CRITICAL findings block merge unless waiver is approved.

## 4) Web/App Hardening Validation

- [ ] HTTPS enforced with valid certificates.
- [ ] HSTS configured with safe max-age and preload decision documented.
- [ ] Security headers verified (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- [ ] AuthN/AuthZ controls tested (MFA for admins, least privilege role model).
- [ ] Rate limiting and bot protection validated on sensitive endpoints.
- [ ] Audit and access logs are centralized with alert routing.

## 5) Autonomous/Self-Learning Safety Controls

- [ ] Feedback loop captures false positives/negatives and remediation outcomes.
- [ ] Security policies are versioned and change-reviewed.
- [ ] Evaluation dataset is maintained for regression testing.
- [ ] Human-in-the-loop approval required for high-impact actions.
- [ ] Prompt/response decision logs retained for auditability.

## 6) Evidence Package (for each test cycle)

- [ ] CI run URLs and artifact exports archived.
- [ ] Findings triaged by severity and business impact.
- [ ] CVE references and patch links recorded.
- [ ] Waivers include expiry date + compensating controls.
- [ ] Retest evidence captured after remediation.

## 7) Exit Criteria

- [ ] No unresolved CRITICAL findings in production scope.
- [ ] HIGH findings have owners, deadlines, and approved risk acceptance if deferred.
- [ ] Security sign-off completed by engineering + security owner.
