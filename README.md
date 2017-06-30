Fortify Issue Suppressor
========================

對 Fortify 結果報告 FPR 檔後續處理的程式，可以透過定義檔將指定的錯誤標註為 `suppressed`。

### 執行指令

```bash
./issue-suppressor.jar --rule rcs-suppression-rule.yml rcs-report.fpr rcs-report-suppressed.fpr
```

```bash
./issue-suppressor.jar -h

```

### Suppression 規則 YAML

範例如下:

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
