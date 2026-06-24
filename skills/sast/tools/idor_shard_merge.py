#!/usr/bin/env python3
"""IDOR 샤드 result.md → idor-scanner.md 자동 병합 (에이전트 책임 제거).

역할:
  샤드 에이전트가 생성한 idor_shard_<n>_result.md 파일들을 읽어
  idor-scanner.md(소스)에 직접 병합한다. 병합 후 완전성을 검증하고
  결과를 출력한다.

  이 스크립트가 병합 책임을 갖는 이유:
  - 에이전트에게 병합을 맡기면 [INCOMPLETE] 마커만 지우고 후보를 안 넣을 수 있다.
  - ID 충돌(샤드 간 중복, 기존 ID와 충돌)을 인간 개입 없이 기계적으로 탐지·차단한다.
  - 병합 완전성 검증이 같은 스크립트 안에서 수행되므로 invariant가 보장된다.

검증 항목:
  1. 각 샤드 result.md의 MANIFEST JSON 실제 파싱 성공
  2. 샤드 ID가 할당된 id_start~id_end 범위 내에 있는지 (idor_shard.py 할당 범위)
  3. ID가 IDOR-\\d+ 형식인지
  4. 샤드 간 ID 중복 없는지
  5. 기존 idor-scanner.md ID와 충돌 없는지
  6. 병합 후 idor-scanner.md에 모든 후보 ID의 ## <ID>: 헤더 + 최소 본문(200자) 존재
  7. [INCOMPLETE] 마커 해소 여부

사용:
  python3 idor_shard_merge.py <idor_scanner_md> <shard_dir>

exit code:
  0 — 병합 완료, 모든 검증 통과
  1 — 검증 실패 (병합 중단 또는 병합 후 불일치)
  2 — idor-scanner.md 또는 shard_dir 경로 오류
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# phase1_build_master_list.py의 MANIFEST_RE와 동일한 패턴 사용 (파싱 일관성)
_MANIFEST_RE = re.compile(
    r"<!-- NOAH-SAST MANIFEST v1 -->\s*```json\s*(\{.*?\})\s*```\s*<!-- /NOAH-SAST MANIFEST -->",
    re.S,
)
_CANDIDATE_HEADER_RE = re.compile(r'^##\s+(IDOR-\d+)\s*:', re.MULTILINE)
_IDOR_ID_RE = re.compile(r'^IDOR-\d+$')
_MIN_BODY_BYTES = 200  # 후보 본문 최소 길이 (헤더만 껍데기로 넣는 것 차단)


def _parse_shard_manifest(body: str, shard_n: int) -> tuple[dict | None, str]:
    """샤드 result.md에서 MANIFEST JSON을 파싱한다."""
    m = _MANIFEST_RE.search(body)
    if not m:
        return None, f"샤드 {shard_n}: MANIFEST JSON 블록을 찾지 못함 (마커 형식 불일치)"
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError as e:
        return None, f"샤드 {shard_n}: MANIFEST JSON 파싱 실패 — {e}"
    return data, ""


def _extract_candidate_section(body: str, cid: str) -> str:
    """body에서 ## <cid>: 헤더로 시작하는 섹션을 추출한다."""
    pattern = re.compile(rf'^(##\s+{re.escape(cid)}\s*:.*?)(?=^##\s+IDOR-|\Z)', re.MULTILINE | re.DOTALL)
    m = pattern.search(body)
    return m.group(1).rstrip() if m else ""


def merge(idor_md_path: Path, shard_dir: Path) -> int:
    if not idor_md_path.is_file():
        print(f"ERROR: idor-scanner.md 없음: {idor_md_path}", file=sys.stderr)
        return 2
    manifest_path = shard_dir / "idor_shards_manifest.json"
    if not manifest_path.is_file():
        print(f"ERROR: idor_shards_manifest.json 없음: {manifest_path}", file=sys.stderr)
        return 2

    try:
        man = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"ERROR: manifest 파싱 실패 — {e}", file=sys.stderr)
        return 1

    shard_files = man.get("files", [])
    declared_shards = man.get("shards", len(shard_files))

    # shards 카운트 vs files 배열 길이 일치 검사
    if len(shard_files) != declared_shards:
        print(f"ERROR: manifest shards={declared_shards} vs files 배열 길이={len(shard_files)} 불일치", file=sys.stderr)
        return 1

    idor_md_text = idor_md_path.read_text(encoding="utf-8")
    existing_ids: set[str] = set(_CANDIDATE_HEADER_RE.findall(idor_md_text))

    # --- Phase 1: 모든 샤드 result.md 파싱 + 사전 검증 ---
    all_new_candidates: list[tuple[int, dict, str]] = []  # (shard_n, candidate, section_text)
    seen_ids: dict[str, int] = {}  # id -> shard_n (샤드 간 중복 탐지)
    errors: list[str] = []

    for entry in shard_files:
        n = entry.get("shard")
        id_start = entry.get("id_start")
        id_end = entry.get("id_end")
        shard_path = Path(entry.get("path", ""))
        result_path = shard_path.with_name(shard_path.stem + "_result.md")

        if not result_path.is_file():
            errors.append(f"샤드 {n}: result.md 없음 — {result_path}")
            continue

        body = result_path.read_text(encoding="utf-8", errors="ignore")
        if len(body.encode("utf-8")) < 200:
            errors.append(f"샤드 {n}: result.md가 비정상적으로 작음 ({result_path})")
            continue

        data, err = _parse_shard_manifest(body, n)
        if err:
            errors.append(err)
            continue

        for cand in data.get("candidates", []):
            cid = cand.get("id", "")

            # ID 형식 검사
            if not _IDOR_ID_RE.match(cid):
                errors.append(f"샤드 {n}: ID '{cid}'가 IDOR-\\d+ 형식 위반")
                continue

            num = int(cid.split("-")[1])

            # ID 범위 검사 (id_start/id_end가 manifest에 있는 경우만)
            if id_start is not None and id_end is not None:
                if not (id_start <= num <= id_end):
                    errors.append(
                        f"샤드 {n}: ID '{cid}'가 할당 범위 IDOR-{id_start}~IDOR-{id_end} 밖"
                    )
                    continue

            # 샤드 간 중복 검사
            if cid in seen_ids:
                errors.append(f"샤드 {n}: ID '{cid}'가 샤드 {seen_ids[cid]}에서 이미 사용됨 (중복)")
                continue
            seen_ids[cid] = n

            # 기존 idor-scanner.md ID 충돌 검사
            if cid in existing_ids:
                # 이미 병합된 경우 스킵 (멱등성)
                section_text = _extract_candidate_section(idor_md_text, cid)
                if len(section_text.encode("utf-8")) >= _MIN_BODY_BYTES:
                    continue  # 이미 병합됨, 스킵
                errors.append(
                    f"샤드 {n}: ID '{cid}'가 idor-scanner.md에 이미 존재하지만 본문이 너무 짧음 "
                    f"(껍데기 헤더로 의심) — 수동 확인 필요"
                )
                continue

            # 후보 본문 섹션 추출
            section_text = _extract_candidate_section(body, cid)
            if not section_text:
                errors.append(f"샤드 {n}: ID '{cid}'가 manifest에 선언됐으나 result.md에 ## {cid}: 헤더 없음")
                continue
            if len(section_text.encode("utf-8")) < _MIN_BODY_BYTES:
                errors.append(
                    f"샤드 {n}: ID '{cid}' 섹션이 너무 짧음 ({len(section_text.encode())}B < {_MIN_BODY_BYTES}B) "
                    f"— 헤더만 있고 본문 없는 것으로 의심"
                )
                continue

            all_new_candidates.append((n, cand, section_text))

    if errors:
        print("ERROR: 사전 검증 실패 — 병합 중단", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    if not all_new_candidates:
        print("INFO: 병합할 신규 후보 없음 (모두 기존 idor-scanner.md에 이미 존재)")
    else:
        print(f"INFO: {len(all_new_candidates)}개 신규 후보를 idor-scanner.md에 병합")

    # --- Phase 2: idor-scanner.md에 후보 섹션 삽입 ---
    # MANIFEST 블록 앞에 신규 후보 섹션들을 삽입한다
    if all_new_candidates:
        insert_sections = "\n\n".join(sec for _, _, sec in all_new_candidates)

        manifest_marker = "<!-- NOAH-SAST MANIFEST v1 -->"
        if manifest_marker in idor_md_text:
            idor_md_text = idor_md_text.replace(
                manifest_marker,
                insert_sections + "\n\n---\n\n" + manifest_marker,
                1,
            )
        else:
            # MANIFEST 블록이 없으면 파일 끝에 추가
            idor_md_text = idor_md_text.rstrip() + "\n\n" + insert_sections + "\n"

        # idor-scanner.md의 MANIFEST JSON에서 declared_count와 candidates 배열 갱신
        def _update_idor_manifest(text: str, new_cands: list[tuple[int, dict, str]]) -> str:
            m = _MANIFEST_RE.search(text)
            if not m:
                return text
            try:
                data = json.loads(m.group(1))
            except json.JSONDecodeError:
                return text
            for _, cand, _ in new_cands:
                # 기존 candidates에 없으면 추가
                existing_cids = {c.get("id") for c in data.get("candidates", [])}
                if cand.get("id") not in existing_cids:
                    data.setdefault("candidates", []).append(cand)
            data["declared_count"] = len(data.get("candidates", []))
            new_json = json.dumps(data, ensure_ascii=False, indent=2)
            return text[:m.start(1)] + new_json + text[m.end(1):]

        idor_md_text = _update_idor_manifest(idor_md_text, all_new_candidates)

    # [INCOMPLETE] 마커 해소: 모든 샤드가 처리 완료됐으므로 마커를 제거한다.
    # 인벤토리 행의 [미확인] 열은 에이전트가 result.md에 기록한 내용(후보 섹션)으로 대체된다.
    idor_md_text = re.sub(r'\[INCOMPLETE[^\]]*\]', '', idor_md_text)
    idor_md_path.write_text(idor_md_text, encoding="utf-8")

    # --- Phase 3: 병합 후 완전성 검증 ---
    final_text = idor_md_path.read_text(encoding="utf-8")
    post_errors: list[str] = []

    for _, cand, _ in all_new_candidates:
        cid = cand.get("id", "")
        if f"## {cid}:" not in final_text:
            post_errors.append(f"병합 후 검증 실패: ## {cid}: 헤더가 idor-scanner.md에 없음")
            continue
        section = _extract_candidate_section(final_text, cid)
        if len(section.encode("utf-8")) < _MIN_BODY_BYTES:
            post_errors.append(f"병합 후 검증 실패: {cid} 본문이 너무 짧음")

    if post_errors:
        print("ERROR: 병합 후 완전성 검증 실패", file=sys.stderr)
        for e in post_errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    merged_count = len(all_new_candidates)
    total_ids = len(_CANDIDATE_HEADER_RE.findall(final_text))
    print(f"병합 완료: 신규 {merged_count}건 추가, idor-scanner.md 총 후보 {total_ids}건")
    return 0


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="IDOR 샤드 result.md → idor-scanner.md 자동 병합")
    ap.add_argument("idor_md", help="idor-scanner.md 경로")
    ap.add_argument("shard_dir", help="샤드 결과 디렉토리 (idor_shards_manifest.json 포함)")
    args = ap.parse_args()
    return merge(Path(args.idor_md), Path(args.shard_dir))


if __name__ == "__main__":
    sys.exit(main())
