#!/usr/bin/env python3
"""idor_inventory.py Spring 다중 마운트(@RequestMapping 배열) 회귀 테스트.

회귀 대상: 클래스 레벨 `@RequestMapping("/a", "/b")`처럼 한 컨트롤러가 여러 경로에
마운트될 때, 첫 prefix만 행으로 생성하고 나머지 마운트를 조용히 누락하던 버그.
인증 제외 마운트(예: `/guest/public/...`)가 인증 마운트(`/common`)에 가려져
인벤토리에 아예 등장하지 못하면 auth_label이 [제외] 판정 기회를 잃는다.

픽스처는 특정 도메인/자원명에 묶이지 않은 합성 경로로 작성한다(범용 스캐너 룰이므로).
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


class TestMappingPathLiterals(unittest.TestCase):
    def test_single_positional(self):
        self.assertEqual(idor._mapping_path_literals('@RequestMapping("/common")'), ["/common"])

    def test_multiple_positional(self):
        self.assertEqual(
            idor._mapping_path_literals('@RequestMapping("/common", "/guest/public/common")'),
            ["/common", "/guest/public/common"],
        )

    def test_value_array(self):
        self.assertEqual(
            idor._mapping_path_literals('@RequestMapping(value = {"/a", "/b"})'),
            ["/a", "/b"],
        )

    def test_produces_not_treated_as_path(self):
        # produces= 등 비경로 명명인자의 문자열 값은 prefix로 들어가면 안 됨(정밀도)
        self.assertEqual(
            idor._mapping_path_literals('@RequestMapping(value = "/x", produces = "application/json")'),
            ["/x"],
        )

    def test_trailing_slash_stripped(self):
        self.assertEqual(idor._mapping_path_literals('@RequestMapping("/a/")'), ["/a"])


class TestMultiMountRows(unittest.TestCase):
    def _scan(self, src: str, suffix: str = ".kt"):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / f"C{suffix}"
            p.write_text(src, encoding="utf-8")
            return idor._scan_controller_file(p)

    def test_each_mount_emits_a_row_kotlin(self):
        src = (
            "import org.springframework.web.bind.annotation.*\n"
            "@RestController\n"
            '@RequestMapping("/common", "/guest/public/common")\n'
            "class C(val svc: Svc) {\n"
            '    @GetMapping("/items")\n'
            "    fun get(@RequestHeader(\"x\") h: Long, @RequestParam id: Long): Any = svc.f(id)\n"
            "}\n"
        )
        eps = {r["endpoint"] for r in self._scan(src)}
        self.assertIn("GET /common/items", eps)
        self.assertIn("GET /guest/public/common/items", eps)

    def test_single_mount_still_one_row(self):
        src = (
            "import org.springframework.web.bind.annotation.*\n"
            "@RestController\n"
            '@RequestMapping("/common")\n'
            "class C(val svc: Svc) {\n"
            '    @GetMapping("/items")\n'
            "    fun get(@RequestParam id: Long): Any = svc.f(id)\n"
            "}\n"
        )
        eps = [r["endpoint"] for r in self._scan(src)]
        self.assertEqual(eps, ["GET /common/items"])

    def test_each_mount_emits_a_row_java(self):
        src = (
            "import org.springframework.web.bind.annotation.*;\n"
            "@RestController\n"
            '@RequestMapping({"/common", "/guest/public/common"})\n'
            "class C {\n"
            '    @GetMapping("/items")\n'
            "    public Object get(@RequestParam Long id) { return null; }\n"
            "}\n"
        )
        eps = {r["endpoint"] for r in self._scan(src, suffix=".java")}
        self.assertIn("GET /common/items", eps)
        self.assertIn("GET /guest/public/common/items", eps)

    def test_no_class_mapping_unaffected(self):
        # 클래스 레벨 매핑이 없으면 메서드 경로 그대로(다중 마운트 무관) — 회귀 없음
        src = (
            "import org.springframework.web.bind.annotation.*\n"
            "@RestController\n"
            "class C(val svc: Svc) {\n"
            '    @GetMapping("/items")\n'
            "    fun get(@RequestParam id: Long): Any = svc.f(id)\n"
            "}\n"
        )
        eps = [r["endpoint"] for r in self._scan(src)]
        self.assertEqual(eps, ["GET /items"])


class TestImplicitBindVisibility(unittest.TestCase):
    """②b: 어노테이션 없이 요청에서 암묵 바인딩되는 복합 타입 파라미터 가시화.

    Spring은 미어노테이션 파라미터를 요청에서 바인딩한다(복합타입→커맨드객체, enum→컨버터).
    클라이언트가 채우는 이 값이 신원 식별자로 쓰이는 경우,
    params 컬럼에 보이지 않으면 에이전트가 '세션 단독'으로 오판할 수 있다.
    """

    def test_kotlin_command_object_marked(self):
        sig = "fun get(@Valid request: SomeRequest, @RequestHeader(\"x\") h: Long)"
        params = idor._params_in_signature(sig, "kotlin")
        self.assertIn("request(implicit-bind SomeRequest)", params)
        self.assertIn("h(@RequestHeader Long)", params)

    def test_kotlin_unannotated_enum_marked(self):
        # 미어노테이션 enum도 Spring이 요청에서 바인딩 → 표지 대상(실코드 회귀)
        sig = "fun get(bizGroupType: BizGroupType, productSaleStatus: ProductSaleStatus?)"
        params = idor._params_in_signature(sig, "kotlin")
        self.assertIn("bizGroupType(implicit-bind BizGroupType)", params)
        self.assertIn("productSaleStatus(implicit-bind ProductSaleStatus)", params)

    def test_java_command_object_marked(self):
        sig = "public Object get(@Valid SomeReq req, @RequestHeader Long h)"
        params = idor._params_in_signature(sig, "java")
        self.assertIn("req(implicit-bind SomeReq)", params)

    def test_framework_types_not_marked_kotlin(self):
        sig = "fun get(model: Model, exchange: ServerWebExchange, pageable: Pageable)"
        self.assertEqual(idor._params_in_signature(sig, "kotlin"), [])

    def test_framework_types_not_marked_java(self):
        sig = "public Object get(Model model, Pageable pageable, BindingResult br)"
        self.assertEqual(idor._params_in_signature(sig, "java"), [])

    def test_request_body_dto_not_double_counted(self):
        # @RequestBody DTO는 1차(어노테이션)에서만 잡히고 2차 표지로 중복되면 안 됨
        sig = "fun create(@RequestBody dto: CreateReq)"
        params = idor._params_in_signature(sig, "kotlin")
        self.assertEqual(params, ["dto(@RequestBody CreateReq)"])

    def test_unannotated_primitive_not_marked(self):
        # 어노테이션 없는 원시/래퍼 단일값은 stoplist로 제외(노이즈 억제)
        sig = "fun get(id: Long, name: String)"
        self.assertEqual(idor._params_in_signature(sig, "kotlin"), [])


if __name__ == "__main__":
    unittest.main()
