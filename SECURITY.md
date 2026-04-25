# Security Policy

## Supported Versions

This project currently supports security updates on the `main` branch.

## Reporting a Vulnerability

Please report vulnerabilities privately to CyberViser / 0AI maintainers.

- Do not open public issues for undisclosed vulnerabilities.
- Include reproduction steps, impact, and affected versions.
- Provide logs and proof-of-concept details needed to validate and remediate.

PeachFuzz AI is not intended for offensive operations. Reports involving unauthorized third-party testing are out of scope.

## Repository Security Baseline

The repository uses GitHub-native controls and CI security checks:

- **Code scanning:** CodeQL and Semgrep run in CI.
- **Dependency scanning:** Dependabot + OSV Scanner + language-native audits.
- **Secret protection:** Enable secret scanning and push protection in repository settings.
- **IaC/container scanning:** Checkov and Trivy run in CI.

## Recommended GitHub Org/Repo Settings

Apply these settings on all repos in the organization:

1. **Branch protection**
   - Require pull request before merge.
   - Require status checks to pass.
   - Require linear history.
   - Require conversation resolution.
2. **Review gates**
   - Require at least 1 approving review.
   - Dismiss stale approvals when new commits are pushed.
3. **Signed commits**
   - Require signed commits for protected branches.
4. **Authentication**
   - Require MFA for all org members and admins.
5. **Least privilege**
   - Restrict admin role usage; use fine-grained PATs and GitHub Apps where possible.
