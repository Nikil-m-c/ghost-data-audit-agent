import csv
import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / 'output.csv'
REQUESTS_FILE = BASE_DIR / 'dataset' / 'deletion_requests.csv'
EVIDENCE_META_FILE = BASE_DIR / 'dataset' / 'evidence_files.csv'

ALLOWED_FINDINGS = {
    'REPORT_REMAINING_RECORD': 'PRESENT',
    'REPORT_EXPOSED_PII': 'PRESENT',
    'REPORT_ACTIVE_DATA_FLOW': 'ACTIVE',
    'REPORT_RESTORE_RISK': 'ACTIVE'
}

ALLOWED_REMEDIATIONS = {
    'DISABLE_DATA_FLOW': 'DISABLED',
    'BLOCK_RESTORE': 'BLOCKED',
    'DELETE_RECORD': 'ABSENT',
    'REDACT_RECORD': 'REDACTED',
    'ANONYMIZE_RECORD': 'ANONYMIZED'
}

ALLOWED_VERIFICATIONS = {
    'VERIFY_RECORD_ABSENT': 'ABSENT',
    'VERIFY_RECORD_PRESENT': 'PRESENT',
    'VERIFY_RECORD_REDACTED': 'REDACTED',
    'VERIFY_RECORD_ANONYMIZED': 'ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED': 'DISABLED',
    'VERIFY_RESTORE_BLOCKED': 'BLOCKED'
}

REQUIRED_STEP_KEYS = {'step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id'}

def validate_output():
    mismatches = []
    
    # 1. Existence check
    if not OUTPUT_FILE.exists():
        return ["output.csv does not exist at repository root."]

    # 2. Header and row count
    with open(REQUESTS_FILE, encoding='utf-8') as f:
        req_rows = list(csv.DictReader(f))
    expected_case_ids = [r['case_id'] for r in req_rows]
    req_by_id = {r['case_id']: r for r in req_rows}

    with open(EVIDENCE_META_FILE, encoding='utf-8') as f:
        evid_meta = {r['file_id']: r for r in csv.DictReader(f)}

    with open(OUTPUT_FILE, encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header != ['case_id', 'deletion_status', 'steps_json']:
            mismatches.append(f"Header mismatch: expected ['case_id', 'deletion_status', 'steps_json'], got {header}")

    with open(OUTPUT_FILE, encoding='utf-8') as f:
        dict_reader = list(csv.DictReader(f))

    if len(dict_reader) != len(expected_case_ids):
        mismatches.append(f"Row count mismatch: expected {len(expected_case_ids)} rows, got {len(dict_reader)} rows.")

    # 3. Case ID matching and sorting
    actual_case_ids = [r['case_id'] for r in dict_reader]
    if set(actual_case_ids) != set(expected_case_ids):
        missing = set(expected_case_ids) - set(actual_case_ids)
        extra = set(actual_case_ids) - set(expected_case_ids)
        if missing: mismatches.append(f"Missing case_ids: {len(missing)} (e.g. {list(missing)[:5]})")
        if extra: mismatches.append(f"Extra case_ids: {len(extra)} (e.g. {list(extra)[:5]})")

    # Check sorting
    def sort_key(cid):
        if '_' in cid and cid.split('_')[1].isdigit():
            return int(cid.split('_')[1])
        return cid

    expected_sorted = sorted(actual_case_ids, key=sort_key)
    if actual_case_ids != expected_sorted:
        mismatches.append("Rows are not strictly sorted by case_id.")

    # 4. Row by row checks
    for i, row in enumerate(dict_reader, start=1):
        cid = row.get('case_id')
        status = row.get('deletion_status')
        steps_raw = row.get('steps_json')

        if status not in ('COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'):
            mismatches.append(f"Row {i} ({cid}): invalid deletion_status '{status}'")
            continue

        try:
            steps = json.loads(steps_raw)
        except Exception as e:
            mismatches.append(f"Row {i} ({cid}): invalid JSON in steps_json: {e}")
            continue

        if not isinstance(steps, list):
            mismatches.append(f"Row {i} ({cid}): steps_json is not a JSON array.")
            continue

        if status == 'NOT_APPLICABLE':
            if steps != []:
                mismatches.append(f"Row {i} ({cid}): status NOT_APPLICABLE must have empty steps_json [], got {steps}")
            continue

        # Case is COMPLETE or INCOMPLETE
        req = req_by_id.get(cid)
        audit_at = req['audit_at'] if req else None

        # Check consecutive step_no starting at 1
        for idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                mismatches.append(f"Row {i} ({cid}): step {idx} is not an object.")
                continue

            if set(step.keys()) != REQUIRED_STEP_KEYS:
                diff = set(step.keys()) ^ REQUIRED_STEP_KEYS
                mismatches.append(f"Row {i} ({cid}) step {idx}: field keys mismatch. Diff: {diff}")

            if step.get('step_no') != idx:
                mismatches.append(f"Row {i} ({cid}) step {idx}: step_no expected {idx}, got {step.get('step_no')}")

            phase = step.get('phase')
            op = step.get('operation')
            st = step.get('state')
            eid = step.get('evidence_id')

            if phase not in ('FINDING', 'REMEDIATION', 'VERIFICATION'):
                mismatches.append(f"Row {i} ({cid}) step {idx}: unknown phase '{phase}'")

            # Check valid operation and state pairing
            if phase == 'FINDING':
                if op not in ALLOWED_FINDINGS:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: finding operation '{op}' invalid.")
                elif st != ALLOWED_FINDINGS[op]:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: finding op '{op}' requires state '{ALLOWED_FINDINGS[op]}', got '{st}'")
                if not eid:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: FINDING step must cite non-empty evidence_id.")
                elif eid not in evid_meta:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: cited evidence_id '{eid}' does not exist in manifest.")
                elif audit_at and evid_meta[eid]['captured_at'] > audit_at:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: cited evidence_id '{eid}' captured after audit_at ({evid_meta[eid]['captured_at']} > {audit_at}).")

            elif phase == 'REMEDIATION':
                if op not in ALLOWED_REMEDIATIONS:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: remediation operation '{op}' invalid.")
                elif st != ALLOWED_REMEDIATIONS[op]:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: remediation op '{op}' requires state '{ALLOWED_REMEDIATIONS[op]}', got '{st}'")
                if eid != '':
                    mismatches.append(f"Row {i} ({cid}) step {idx}: REMEDIATION step must have empty evidence_id, got '{eid}'")

            elif phase == 'VERIFICATION':
                if op not in ALLOWED_VERIFICATIONS:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: verification operation '{op}' invalid.")
                elif st != ALLOWED_VERIFICATIONS[op]:
                    mismatches.append(f"Row {i} ({cid}) step {idx}: verification op '{op}' requires state '{ALLOWED_VERIFICATIONS[op]}', got '{st}'")
                
                if status == 'COMPLETE':
                    if not eid:
                        mismatches.append(f"Row {i} ({cid}) step {idx}: COMPLETE case verification must cite non-empty evidence_id.")
                    elif eid not in evid_meta:
                        mismatches.append(f"Row {i} ({cid}) step {idx}: cited evidence_id '{eid}' does not exist in manifest.")
                    elif audit_at and evid_meta[eid]['captured_at'] > audit_at:
                        mismatches.append(f"Row {i} ({cid}) step {idx}: cited evidence_id '{eid}' captured after audit_at ({evid_meta[eid]['captured_at']} > {audit_at}).")
                elif status == 'INCOMPLETE':
                    if eid != '':
                        mismatches.append(f"Row {i} ({cid}) step {idx}: INCOMPLETE future verification must have empty evidence_id, got '{eid}'")

        # Check phase ordering: FINDING -> REMEDIATION -> VERIFICATION
        phases = [s.get('phase') for s in steps]
        phase_ranks = {'FINDING': 1, 'REMEDIATION': 2, 'VERIFICATION': 3}
        ranks = [phase_ranks.get(p, 99) for p in phases]
        if ranks != sorted(ranks):
            mismatches.append(f"Row {i} ({cid}): phase ordering invalid. Found phases: {phases}")

        if status == 'COMPLETE':
            if any(p != 'VERIFICATION' for p in phases):
                mismatches.append(f"Row {i} ({cid}): COMPLETE case must only contain VERIFICATION steps, found {set(phases)}")

        if status == 'INCOMPLETE':
            if 'FINDING' not in phases:
                mismatches.append(f"Row {i} ({cid}): INCOMPLETE case must have at least one FINDING step.")
            if 'REMEDIATION' not in phases:
                mismatches.append(f"Row {i} ({cid}): INCOMPLETE case must have at least one REMEDIATION step.")
            if 'VERIFICATION' not in phases:
                mismatches.append(f"Row {i} ({cid}): INCOMPLETE case must have at least one VERIFICATION step.")

    return mismatches

if __name__ == '__main__':
    errs = validate_output()
    if not errs:
        print("PERFECT MATCH: output.csv fully complies with all problem statement and AGENTS.md requirements!")
    else:
        print(f"FAILED with {len(errs)} mismatches:")
        for e in errs[:20]:
            print(f" - {e}")
        if len(errs) > 20:
            print(f" ... and {len(errs) - 20} more.")

