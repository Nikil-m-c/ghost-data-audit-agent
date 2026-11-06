# Ghost Data Audit Agent

My solution to the **HackerRank Orchestrate October 2026** challenge "Ghost Data Still Exists". The challenge and dataset are by HackerRank.

## Overview
A deletion workflow can report "Complete" while a user's personal data still exists in logs, attachments, exports, search indexes or backups. This agent audits each deletion request and checks whether the deletion was really finished.

For each request, the agent:
- checks whether deletion was actually requested,
- returns a status: `COMPLETE`, `INCOMPLETE` or `NOT_APPLICABLE`,
- lists the remaining data or recreation risks,
- outputs the ordered remediation and verification steps.

## Project structure
```
code/
  main.py                    # the audit agent
  validate_output_format.py  # checks the format of output.csv
dataset/                     # input CSV files and evidence files
output.csv                   # generated result
```

## How it works
`code/main.py` defines a `DeletionAuditAgent` class.

**On start-up it:**
1. Loads `user_identities.csv`, `user_audit_log.csv`, `system_activity.csv` and `evidence_files.csv` from `dataset/`.
2. Builds an identity index, so a user can be matched by email, hash, phone number or user ID.
3. Parses the files in `dataset/evidence/` into evidence records.

**For each row in `deletion_requests.csv` it:**
1. Checks the request text with regex patterns. If it is not a real deletion request (for example, an access request or a request for a copy of data), it returns `NOT_APPLICABLE` with no steps.
2. Otherwise, it identifies the user and audits their data across systems using the evidence.
3. Returns the status (`COMPLETE` or `INCOMPLETE`) with the findings, remediation and verification steps. Steps are sorted by operation order, then system ID, then resource ID.

Finally, the results are sorted by case number and written to `output.csv`.

## How to run
Requirements: Python 3.13 (tested), standard library only.

```bash
cd code
python main.py
```

The agent reads `dataset/deletion_requests.csv` and writes `output.csv` in the project root folder.

Note: the challenge dataset is not included in this repository. Place the HackerRank dataset files in a `dataset/` folder in the project root before running.

## Output format
`output.csv` has one row per case with 3 columns:

| Column | Description |
|---|---|
| `case_id` | Case identifier, for example `case_01` |
| `deletion_status` | `COMPLETE`, `INCOMPLETE` or `NOT_APPLICABLE` |
| `steps_json` | JSON list of steps, each with a `phase` (for example `FINDING` or `VERIFICATION`), a `system_id` and a `resource_id` |

## Validation
`code/validate_output_format.py` checks that `output.csv` matches the format required by the problem statement.

```bash
cd code
python validate_output_format.py
```

My output passes this check.

## Limitations
- The agent is rule-based (regex patterns and fixed rules), not a learned model.
- The validator checks only the output **format**. I did not measure how correct the statuses are.
- Some evidence files are handled with file-specific rules, so it may not generalize to new datasets without changes.

## Credits
Challenge: HackerRank Orchestrate, October 2026.