# Design Note: Managing Detection Rules at Scale

This repo has 10 rules. A real SOC has hundreds or thousands, written by several people, deployed to more than one SIEM. This note covers what I would add to the current setup to handle that, and why.

## 1. Every rule needs an owner and a lifecycle

At scale, the main risk is rules nobody understands any more. Each rule should carry metadata that CI enforces:

- **Owner** (person or team), so someone answers for false positives.
- **Status**: `experimental` → `test` → `stable` → `deprecated`. Sigma already has this field. New rules start as `experimental` and alert to a review queue, not the main SOC queue.
- **Review date.** CI can warn when a rule hasn't been reviewed in, say, 12 months.

`CODEOWNERS` would require the owning team to approve changes to their folder, for example `rules/sentinel/identity/` owned by the identity team.

## 2. Folder structure by data source, not by author

```
rules/sigma/windows/process_creation/
rules/sigma/windows/registry/
rules/sentinel/identity/
rules/sentinel/cloud/
```

Naming follows the SigmaHQ convention (`<logsource>_<os>_<behaviour>`), which this repo already uses. That makes it obvious where a new rule goes and stops near-duplicates from appearing in different places.

## 3. Staged deployment

Merging to `main` should not mean "live in production" straight away.

1. **PR**: CI validates and tests (what this repo does today).
2. **Merge to main**: automatic deployment to a **staging** Sentinel workspace that receives a copy of production logs.
3. **Soak period**: the rule runs in staging for a few days; alert volume is measured.
4. **Promotion**: a tagged release deploys to production.

Deployment itself would be automated through Sentinel's built-in **Repositories** feature or the Sentinel REST API from a GitHub Actions job, so the portal is never edited by hand. A nightly job would compare what is deployed against Git and flag **drift** (someone changed a rule in the portal).

## 4. Alert volume budgets

A rule that fires 500 times a day is as harmful as one that never fires, because analysts start ignoring it. Each rule should declare an expected volume. In staging, a rule that exceeds its budget fails promotion until it is tuned.

## 5. Better test data

Today the test samples are hand-written. At scale I would:

- Capture **real attack telemetry** from lab runs of Atomic Red Team tests, sanitise it, and store it as test fixtures.
- Add **regression samples**: every false positive reported by the SOC becomes a new `should_not_match` sample, so the same false positive can never come back.
- Keep a shared library of benign baseline events (normal admin activity) that every rule in a category is tested against.

## 6. Run KQL in CI

The biggest gap in this repo is that KQL is not executed in CI. Two options:

- An **Azure Data Explorer free cluster**: CI ingests the sample events into a table and runs each Sentinel rule's query against it, giving the same match / no-match proof that Sigma rules have.
- Converting Sentinel detections to **Sigma where possible**, so they share the Sigma test harness, and keeping native KQL only for logic Sigma cannot express.

## 7. Coverage reporting

Every rule already carries ATT&CK technique IDs. A CI job can turn those into an **ATT&CK Navigator layer** on each merge, showing which techniques are covered, by how many rules, and where the gaps are. That turns the repo into a planning tool, not just a rule store.

## 8. Keep up with framework changes

While building this repo, MITRE split Defense Evasion into Stealth and Defense Impairment, and the Sigma validator flagged the old tag immediately. Sentinel had not caught up yet. At scale, a scheduled CI run (not only on PRs) should re-validate all existing rules against the latest ATT&CK data, so stale tags are found across the whole library, not only in rules someone happens to edit.

## Summary

| Problem at scale | Control |
|---|---|
| Rules nobody owns | Owner, status and review date enforced by CI; CODEOWNERS |
| Broken rules reaching production | Tests per rule (done), staging workspace and soak period |
| Portal edits drifting from Git | Automated deployment and nightly drift check |
| Noisy rules | Alert volume budgets measured in staging |
| Weak test data | Real lab telemetry and regression samples from false positives |
| KQL not tested | ADX free cluster in CI |
| Unknown coverage | ATT&CK Navigator layer generated on merge |
| Framework drift | Scheduled re-validation of every rule |
