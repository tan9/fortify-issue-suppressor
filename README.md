Fortify Issue Suppressor
========================

Post-processes Fortify analysised FPR files, mark specified issues as `suppressed`.

### How to run

```bash
./issue-suppressor.jar --rule rcs-suppression-rule.yml rcs-report.fpr rcs-report-suppressed.fpr
```

```bash
./issue-suppressor.jar -h

```

### Specification of Suppression Rules

Example:

```yaml
build:
  id: "rcs"
vulnerabilities:
  - classInfo:
      type: "Access Control"
      subtype: "Database"
  - classInfo:
      type: "Dynamic Code Evaluation"
      subtype: "Code Injection"

```
