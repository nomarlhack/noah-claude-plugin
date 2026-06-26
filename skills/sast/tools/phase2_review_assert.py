#!/usr/bin/env python3
"""
Step 10 (연계 분석) 진입 가드.

모든 후보가 status 필드와 적법한 tag/safe_category enum을 가지는지,
mode=phase2-review 완료 이후에 연계 분석이 실행되는지 런타임 assert한다.

Phase 2 우선 원칙에 따라 Phase 1↔Phase 2 불일치는 phase2-review가 Phase 2
증거로 status를 확정하므로 인간 개입 차단 경로(exit 2)는 사용하지 않는다.

Usage:
  python3 phase2_review_assert.py <master-list.json> <phase1_results_dir>

Exit code (sub-skills/scan-report-review/_contracts.md §2 Exit Code 통일 테이블):
  0: 통과
  1: incomplete / invalid state (status 미완결, enum 위반 등)
  3: 비차단 경고 (rederivation 편향)
  4: reopen_pending — phase1-review 재호출 권장 (품질 개선 힌트, 파이프라인 차단 아님)
  7: safe_bucket_unclassified — safe 후보에 safe_category 누락
"""

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("master_list")
    parser.add_argument("phase1_dir")
    args = parser.parse_args()

    master_list_path = args.master_list
    phase1_results_dir = args.phase1_dir

    with open(master_list_path) as f:
        m = json.load(f)

    candidates = m.get("candidates", [])
    if not candidates:
        print("FAIL: candidates 배열이 비어 있음")
        return 1

    # 1. 모든 후보가 status 필드를 가지는가
    missing = [
        c["id"] for c in candidates
        if "status" not in c or c["status"] is None or c["status"] == ""
    ]
    if missing:
        print(
            f"FAIL: {len(missing)}개 후보가 status 없음: {missing[:10]}"
            f"{' …' if len(missing) > 10 else ''}"
        )
        print("mode=phase2-review가 완료되지 않았거나 갱신에 실패했다.")
        return 1

    # 2. status 값이 enum에 속하는가
    allowed = {"confirmed", "candidate", "safe"}
    invalid = [
        (c["id"], c["status"]) for c in candidates
        if c["status"] not in allowed
    ]
    if invalid:
        print(f"FAIL: 비정형 status 값: {invalid[:5]}")
        return 1

    # 3. candidate 판정은 tag 필드 필수 + tag enum 검증
    allowed_tags = {
        "도구 한계",
        "정보 부족",
        "환경 제한",
        "차단",
        "동적 분석 생략",
        # LLM 그룹(prereq_group == "llm") 사전 단계 결과별 tag — _contracts.md §3 / §5
        "LLM endpoint 미확보",
        "LLM endpoint 확인됨",
        "LLM endpoint 정적 식별",
    }
    cand_no_tag = [
        c["id"] for c in candidates
        if c["status"] == "candidate"
        and (c.get("tag") is None or c.get("tag") == "")
    ]
    if cand_no_tag:
        print(
            f"FAIL: {len(cand_no_tag)}개 candidate가 tag 없음: "
            f"{cand_no_tag[:5]}"
        )
        print("_contracts.md §5 판정×태그별 필수 필드 매트릭스 위반.")
        return 1
    invalid_tags = [
        (c["id"], c.get("tag")) for c in candidates
        if c["status"] == "candidate" and c.get("tag") not in allowed_tags
    ]
    if invalid_tags:
        print(
            f"FAIL: {len(invalid_tags)}개 candidate의 tag가 enum 외 값: "
            f"{invalid_tags[:5]}"
        )
        print(f"_contracts.md §3 tag enum 위반. 허용 값: {sorted(allowed_tags)}")
        return 1

    # 3-B. safe 판정은 safe_category 필드 필수 + safe_category enum 검증 — exit 7
    allowed_safe_cats = {
        "no_external_path", "defense_verified",
        "not_applicable", "false_positive",
        "platform_default_defense",
        "architectural_rationale_only",
    }
    safe_no_cat = [
        c["id"] for c in candidates
        if c["status"] == "safe"
        and (c.get("safe_category") is None or c.get("safe_category") == "")
    ]
    if safe_no_cat:
        print(
            f"FAIL: {len(safe_no_cat)}개 safe 후보에 safe_category 누락: "
            f"{safe_no_cat[:5]}"
        )
        print("_contracts.md §9 하위 호환 fallback 위반 (status=safe + safe_category=null 금지).")
        print(
            "복구: 해당 후보에 phase1_eval_state.reopen=true 설정 후 phase1-review 재호출: IDs="
            + ",".join(safe_no_cat[:10])
            + (" (…외 추가 후보)" if len(safe_no_cat) > 10 else "")
            + " 인자로 재호출하여 safe_category를 채우거나, "
            "phase1_discarded_reason이 있는 구조적 폐기면 'no_external_path'로 수동 기록."
        )
        return 7
    invalid_safe_cats = [
        (c["id"], c.get("safe_category")) for c in candidates
        if c["status"] == "safe" and c.get("safe_category") not in allowed_safe_cats
    ]
    if invalid_safe_cats:
        print(
            f"FAIL: {len(invalid_safe_cats)}개 safe 후보의 safe_category가 enum 외 값: "
            f"{invalid_safe_cats[:5]}"
        )
        print(f"_contracts.md §3 safe_category enum 위반. 허용 값: {sorted(allowed_safe_cats)}")
        return 7

    # 3-C. safe_category ↔ 관련 필드 정합성 — writer 권한 간접 검증 (홀 3)
    #   - defense_verified (phase2-review writer) → verified_defense 객체 필수
    #   - no_external_path / false_positive / not_applicable (phase1-review writer)
    #     → phase1_discarded_reason 또는 phase1_validated=true 필수
    safe_consistency_violations = []
    for c in candidates:
        if c["status"] != "safe":
            continue
        cat = c.get("safe_category")
        if cat == "defense_verified":
            vd = c.get("verified_defense")
            if not (isinstance(vd, dict) and vd.get("file") and vd.get("content_hash")):
                safe_consistency_violations.append(
                    (c["id"], "defense_verified인데 verified_defense 부재/malformed")
                )
        elif cat in {"no_external_path", "false_positive", "not_applicable"}:
            if not (
                c.get("phase1_discarded_reason")
                or c.get("phase1_validated") is True
            ):
                safe_consistency_violations.append(
                    (c["id"], f"{cat}인데 phase1_discarded_reason/phase1_validated 근거 부재")
                )
    if safe_consistency_violations:
        print(
            f"FAIL: {len(safe_consistency_violations)}개 safe 후보의 safe_category↔관련 필드 불일치:"
        )
        for cid, reason in safe_consistency_violations[:5]:
            print(f"  - {cid}: {reason}")
        print("_contracts.md §1 writer 권한 간접 위반 의심.")
        return 1

    # 4. master-list.json의 mtime이 Phase 2 파일보다 나중인가
    master_mtime = os.path.getmtime(master_list_path)
    phase2_files = list(Path(phase1_results_dir).glob("*-phase2.md"))
    # Phase 2 파일이 0건이고 candidate 후보가 존재하면 경고 (Phase 2 미실행 징후)
    if not phase2_files:
        candidate_count = sum(1 for c in candidates if c.get("status") == "candidate")
        confirmed_count = sum(1 for c in candidates if c.get("status") == "confirmed")
        if candidate_count > 0 or confirmed_count > 0:
            print(
                f"WARNING: *-phase2.md 파일이 0건 — Phase 2 동적 분석이 실행되지 않았거나\n"
                f"  '동적 분석 생략' 태그로 처리되지 않은 것으로 보입니다.\n"
                f"  (candidate={candidate_count}건, confirmed={confirmed_count}건)",
                file=sys.stderr,
            )
    if phase2_files:
        latest_phase2 = max(os.path.getmtime(p) for p in phase2_files)
        if master_mtime < latest_phase2:
            print(
                f"FAIL: master-list.json mtime({master_mtime})이 "
                f"Phase 2 파일({latest_phase2})보다 이르다."
            )
            print("phase2-review 단계가 Phase 2보다 먼저 실행되었거나 누락되었다.")
            return 1

    # 4-B. Phase 2 manifest v2에 금지된 `status` 필드가 있는지 검사 (홀 4)
    #      _contracts.md §4 제약: "각 result에 status 필드를 넣지 않는다."
    import re as _re
    manifest_re = _re.compile(
        r"<!--\s*NOAH-SAST PHASE2 MANIFEST v2\s*-->\s*```json\s*(.*?)\s*```\s*<!--\s*/NOAH-SAST PHASE2 MANIFEST\s*-->",
        _re.DOTALL,
    )
    manifest_status_violations = []
    for p in phase2_files:
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        m = manifest_re.search(text)
        if not m:
            continue
        try:
            manifest = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        for r in manifest.get("results", []):
            if "status" in r:
                manifest_status_violations.append((p.name, r.get("id", "<no id>")))
    if manifest_status_violations:
        print(
            f"FAIL: {len(manifest_status_violations)}개 Phase 2 manifest result가 "
            f"금지된 `status` 필드를 포함:"
        )
        for fname, rid in manifest_status_violations[:5]:
            print(f"  - {fname} :: {rid}")
        print("_contracts.md §4 제약 위반. Phase 2 에이전트가 status를 할당하면 안 됨 (phase2-review 전용).")
        return 1

    # 5. reopen_pending 체크 — exit 4
    #    phase2-review가 §10-A 교차 검증에서 모순 발견 후 reopen=true 세팅한 후보가 있으면
    #    phase1-review 재호출 필요.
    reopen_pending = [
        c["id"] for c in candidates
        if c.get("phase1_eval_state", {}).get("reopen")
    ]
    if reopen_pending:
        print(
            f"BLOCK: {len(reopen_pending)}개 후보가 reopen_pending: {reopen_pending[:10]}"
        )
        print("phase1-review 재호출이 필요. SKILL.md 'reopen 재호출 원자성' 절차 수행.")
        return 4

    # (레거시 requires_human_review 경로는 Phase 2 우선 원칙으로 폐기됨)

    # 7. rederivation_performed 편향 관측 — safe 판정 중 §9 Source 도달성 폐기가 아닌
    #    항목만 분모로 사용 (false alarm 방지).
    #    phase1_discarded_reason 있는 safe는 구조적 폐기로 rederivation 개념 비적용.
    safe_items = [
        c for c in candidates
        if c["status"] == "safe"
        and not c.get("phase1_discarded_reason")
    ]
    if safe_items:
        no_rederivation = [
            c["id"] for c in safe_items
            if not c.get("rederivation_performed", False)
        ]
        ratio = len(no_rederivation) / len(safe_items)
        if ratio > 0.30:
            print(
                f"WARN: phase2-review-safe 판정 중 rederivation_performed=false 비율 "
                f"{ratio:.1%} > 30% 경고선."
            )
            print(f"편향 의심 항목: {no_rederivation}")
            _summary(candidates)
            # non-blocking 경고 — exit 3
            return 3

    # 통과
    _summary(candidates)
    return 0


def _summary(candidates: list) -> None:
    dist = {"confirmed": 0, "candidate": 0, "safe": 0}
    for c in candidates:
        dist[c["status"]] = dist.get(c["status"], 0) + 1
    print(
        f"OK: 후보 {len(candidates)}건 "
        f"(confirmed={dist['confirmed']}, "
        f"candidate={dist['candidate']}, "
        f"safe={dist['safe']})"
    )


if __name__ == "__main__":
    sys.exit(main())
