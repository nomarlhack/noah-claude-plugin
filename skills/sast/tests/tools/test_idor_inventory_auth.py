#!/usr/bin/env python3
"""idor_inventory.py 인증 게이트 미경유(auth 컬럼) 회귀 테스트.

회귀 대상: 인증 인터셉터/시큐리티가 제외한 경로(예: Spring excludePathPatterns)의
식별자 단독 리소스 조회 진입점이 'auth=제외'로 표시되어, phase1.md의
"인증 게이트 미경유 진입점은 [미확인]로 종결 금지" 우선 검토 대상이 되는지 검증한다.

배경: 인증 미경유 + 식별자 단독 조회 + 소유권 게이트 부재 진입점이 인벤토리에서
[미확인]로 방치되어 후보 승격이 누락된 사례의 재발 방지. 픽스처는 특정 도메인/자원명에
묶이지 않은 합성 경로로 작성한다(범용 스캐너 룰이므로).
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_MOD_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "idor_inventory.py")
_spec = importlib.util.spec_from_file_location("idor_inventory", _MOD_PATH)
idor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(idor)


class TestAuthLabel(unittest.TestCase):
    def _rx(self, *pats):
        return [idor._ant_to_regex(p) for p in pats]

    def test_excluded_subtree_is_marked(self):
        # 인증 미경유(`/public/**` 제외) + 식별자 단독 리소스 조회 → '제외' (회귀 핵심)
        rx = self._rx("/public/**")
        self.assertEqual(idor.auth_label("GET /public/v1/items/{id}/tickets", rx), "제외")

    def test_non_excluded_is_applied(self):
        rx = self._rx("/public/**")
        self.assertEqual(idor.auth_label("GET /v1/users/{id}", rx), "적용")

    def test_no_patterns_is_unknown(self):
        # 도구가 인증 설정을 못 찾거나 미지원 프레임워크면 '미상' (정책이 백스톱)
        self.assertEqual(idor.auth_label("GET /public/x", []), "미상")

    def test_single_star_is_one_segment(self):
        rx = self._rx("/a/*/b")
        self.assertEqual(idor.auth_label("GET /a/x/b", rx), "제외")
        self.assertEqual(idor.auth_label("GET /a/x/y/b", rx), "적용")  # `*`는 한 세그먼트만

    def test_verb_and_leading_slash_normalized(self):
        # prefix에 선행 슬래시 없는 매핑도 정규화되어 매칭
        rx = self._rx("/inhouse/**")
        self.assertEqual(idor.auth_label("GET inhouse/v1/bookings", rx), "제외")


class TestCollectPatterns(unittest.TestCase):
    def test_multiline_exclude_collected_and_build_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "config").mkdir()
            (root / "config" / "WebMvcConfig.java").write_text(
                "registry.addInterceptor(auth)\n"
                "    .excludePathPatterns(\n"
                '        "/public/**",\n'
                '        "/internal/**");\n',
                encoding="utf-8",
            )
            # build/ 산출물은 스캔에서 제외되어야 함
            (root / "build").mkdir()
            (root / "build" / "Gen.java").write_text(
                '.excludePathPatterns("/should-be-ignored/**");', encoding="utf-8"
            )
            pats = idor.collect_auth_excluded_patterns(root)
            self.assertIn("/public/**", pats)
            self.assertIn("/internal/**", pats)
            self.assertNotIn("/should-be-ignored/**", pats)

    def test_no_config_yields_empty(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "Plain.java").write_text("class Plain {}", encoding="utf-8")
            self.assertEqual(idor.collect_auth_excluded_patterns(root), [])


if __name__ == "__main__":
    unittest.main()
