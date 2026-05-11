#!/usr/bin/env python3
"""llm_channel_probe.py — Noah SAST LLM 그룹 채널 어댑터.

`llm_endpoint.json`(probe-agent의 산출물)을 입력으로 받아 단일 채팅 왕복을
수행하고, 표준화된 단일 JSON 라인을 stdout으로 반환한다. 채널 종류
(http / ws-raw / ws-stomp / ws-socketio / ws-graphql / sse)를 어댑터로
추상화하여 probe-agent와 Phase 2 에이전트가 동일한 호출 인터페이스로
사용한다.

원칙:
  - 본 스크립트는 **채널 어댑터**에 한정한다. 페이로드 생성, 변형, 반복,
    판정 로직을 갖지 않는다.
  - 한 호출 = 한 utterance = 한 응답. 멀티턴 누적은 호출자가
    `--referer-cid`를 다음 호출에 주입하는 방식으로 처리한다.
  - 모든 frame은 `--out-jsonl` 파일에 append되어 재현·감사 가능하다.

사용:
  python3 llm_channel_probe.py \\
    --endpoint <LLM_PROBE_DIR>/llm_endpoint.json \\
    --endpoint-index 0 \\
    --utterance "hi" \\
    [--referer-cid <cid>] \\
    [--mode discover|probe|test] \\
    [--timeout 30] \\
    --out-jsonl <LLM_PROBE_DIR>/llm_endpoint_probe.jsonl

stdout (단일 JSON 라인):
  {
    "status": "ok|timeout|connect_fail|auth_fail|block|unsupported_channel|error",
    "model_text": "...",
    "conversation_id": "..." | null,
    "events": {"LLM": 12, "PROGRESS": 3, ...},
    "frames_total": 18,
    "elapsed_ms": 4230,
    "channel": "ws-stomp",
    "endpoint_index": 0,
    "error": null | "<message>"
  }
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import uuid
from typing import Any

try:
    import requests
except ImportError:
    print(json.dumps({
        "status": "error",
        "error": "missing dependency: requests. install: pip install --user requests",
        "channel": "unknown", "endpoint_index": -1,
        "model_text": "", "conversation_id": None,
        "events": {}, "frames_total": 0, "elapsed_ms": 0,
    }))
    sys.exit(2)

try:
    import websocket  # websocket-client
except ImportError:
    websocket = None  # ws 계열 채널 호출 시점에 다시 체크


# ─── 공통 유틸 ────────────────────────────────────────────────

def _dotted_get(obj: Any, path: str) -> Any:
    """`a.b.c` 형식의 경로로 dict/list를 탐색하여 값을 반환. 없으면 None."""
    if not path:
        return None
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


def _find_first(obj: Any, key: str, max_depth: int = 6) -> Any:
    """JSON 트리를 BFS로 순회하여 첫 등장 key의 값을 반환. 없으면 None."""
    if not key:
        return None
    stack = [(obj, 0)]
    while stack:
        cur, depth = stack.pop(0)
        if depth > max_depth:
            continue
        if isinstance(cur, dict):
            if key in cur:
                return cur[key]
            for v in cur.values():
                stack.append((v, depth + 1))
        elif isinstance(cur, list):
            for v in cur:
                stack.append((v, depth + 1))
    return None


def _set_dotted(obj: dict, path: str, value: Any) -> None:
    """dotted path로 dict에 값을 셋팅. 중간 dict가 없으면 생성."""
    if not path:
        return
    parts = path.split(".")
    cur = obj
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


class TranscriptLogger:
    """frame 단위로 jsonl에 append. 호출자별 prefix로 충돌 회피."""

    def __init__(self, path: str | None, channel: str, endpoint_index: int):
        self.path = path
        self.channel = channel
        self.endpoint_index = endpoint_index
        self.session_id = uuid.uuid4().hex[:12]
        self._lock = threading.Lock()

    def write(self, direction: str, payload: Any, note: str = "") -> None:
        if not self.path:
            return
        rec = {
            "ts": _now_iso(),
            "session": self.session_id,
            "channel": self.channel,
            "endpoint_index": self.endpoint_index,
            "direction": direction,  # out | in | meta
            "payload": _truncate(payload, 2048),
            "note": note,
        }
        try:
            with self._lock, open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


def _truncate(v: Any, n: int) -> Any:
    if isinstance(v, str):
        return v if len(v) <= n else v[:n] + f"...[+{len(v)-n}B truncated]"
    if isinstance(v, (dict, list)):
        try:
            s = json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)[:n]
        return v if len(s) <= n else s[:n] + f"...[+{len(s)-n}B truncated]"
    return v


# ─── 결과 객체 ────────────────────────────────────────────────

class ChannelResult:
    """채널 어댑터 표준 결과."""

    def __init__(self, channel: str, endpoint_index: int):
        self.status: str = "error"
        self.model_text: str = ""
        self.conversation_id: str | None = None
        self.events: dict[str, int] = {}
        self.frames_total: int = 0
        self.elapsed_ms: int = 0
        self.channel: str = channel
        self.endpoint_index: int = endpoint_index
        self.error: str | None = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "model_text": self.model_text,
            "conversation_id": self.conversation_id,
            "events": self.events,
            "frames_total": self.frames_total,
            "elapsed_ms": self.elapsed_ms,
            "channel": self.channel,
            "endpoint_index": self.endpoint_index,
            "error": self.error,
        }


# ─── 채널 어댑터 기반 ────────────────────────────────────────

class BaseAdapter:
    def __init__(self, endpoint: dict, endpoint_index: int, log: TranscriptLogger, timeout: int):
        self.ep = endpoint
        self.idx = endpoint_index
        self.log = log
        self.timeout = timeout
        self.result = ChannelResult(endpoint.get("channel", "unknown"), endpoint_index)

    def run(self, utterance: str, referer_cid: str | None) -> ChannelResult:
        t0 = time.time()
        try:
            self._run(utterance, referer_cid)
        except Exception as e:  # 최상위 안전망
            self.result.status = self.result.status if self.result.status != "error" else "error"
            self.result.error = f"{type(e).__name__}: {e}"
        finally:
            self.result.elapsed_ms = int((time.time() - t0) * 1000)
        return self.result

    def _run(self, utterance: str, referer_cid: str | None) -> None:
        raise NotImplementedError

    # ── 공통 헬퍼 ──

    def _build_body(self, utterance: str, referer_cid: str | None) -> dict:
        """request_schema에 따라 본문 dict를 구성."""
        schema = self.ep.get("request_schema", {}) or {}
        body: dict = {}

        # extra_fields 먼저 baseline으로 깔고
        extra = schema.get("extra_fields", {}) or {}
        if isinstance(extra, dict):
            body.update(extra)

        # 메시지 필드
        msg_path = schema.get("message_path") or "message"
        _set_dotted(body, msg_path, utterance)

        # 멀티턴 inject_field
        mt = self.ep.get("multiturn", {}) or {}
        if referer_cid and isinstance(mt, dict):
            inj = mt.get("inject_field")
            if inj:
                _set_dotted(body, inj, referer_cid)

        # wrapper 처리
        wrapper = schema.get("wrapper")
        if wrapper:
            body = {wrapper: body}
        return body

    def _record_event(self, event_name: str) -> None:
        if not event_name:
            return
        self.result.events[event_name] = self.result.events.get(event_name, 0) + 1


# ─── HTTP ────────────────────────────────────────────────────

class HttpAdapter(BaseAdapter):

    def _run(self, utterance: str, referer_cid: str | None) -> None:
        base = self.ep.get("base_url", "").rstrip("/")
        route = self.ep.get("route", "")
        method = (self.ep.get("method") or "POST").upper()
        url = base + route
        headers = self.ep.get("headers", {}) or {}
        body = self._build_body(utterance, referer_cid)

        self.log.write("out", {"url": url, "method": method, "headers": headers, "body": body})
        try:
            r = requests.request(method, url, headers=headers, json=body, timeout=self.timeout)
        except requests.exceptions.ConnectionError as e:
            self.result.status = "connect_fail"
            self.result.error = str(e)
            self.log.write("meta", {}, note=f"connect_fail: {e}")
            return
        except requests.exceptions.Timeout:
            self.result.status = "timeout"
            self.log.write("meta", {}, note="timeout")
            return
        except Exception as e:
            self.result.status = "error"
            self.result.error = f"{type(e).__name__}: {e}"
            return

        self.result.frames_total = 1
        try:
            data = r.json()
            payload: Any = data
        except ValueError:
            data = None
            payload = r.text
        self.log.write("in", {"status": r.status_code, "body": payload})

        if r.status_code in (401, 403):
            self.result.status = "auth_fail"
            return
        if r.status_code >= 500:
            self.result.status = "error"
            self.result.error = f"http_{r.status_code}"
            return
        if r.status_code >= 400:
            self.result.status = "error"
            self.result.error = f"http_{r.status_code}: {str(payload)[:200]}"
            return

        # 모델 텍스트 추출
        resp_path = self.ep.get("response_path") or self.ep.get("event_stream", {}).get("chunk_field")
        text = ""
        if isinstance(data, dict) and resp_path:
            v = _dotted_get(data, resp_path)
            if isinstance(v, str):
                text = v
            elif isinstance(v, list):  # chunk 배열인 경우 join
                text = "".join(str(x) for x in v if isinstance(x, (str, int, float)))
        elif isinstance(payload, str):
            text = payload
        self.result.model_text = text

        # conversation_id 추출
        mt = self.ep.get("multiturn", {}) or {}
        extract = mt.get("extract_path")
        if isinstance(data, dict):
            cid = _dotted_get(data, extract) if extract else None
            if not cid and extract:
                # 마지막 segment 키로 fallback 탐색
                cid = _find_first(data, extract.split(".")[-1])
            if cid and isinstance(cid, (str, int)):
                self.result.conversation_id = str(cid)

        self._record_event("HTTP_OK")
        self.result.status = "ok"


# ─── WebSocket 공통 ──────────────────────────────────────────

def _require_ws() -> None:
    if websocket is None:
        raise RuntimeError("missing dependency: websocket-client. install: pip install --user websocket-client")


def _ws_url_with_query(handshake: dict) -> str:
    url = handshake.get("url", "")
    query = handshake.get("query") or {}
    if not query:
        return url
    from urllib.parse import urlencode, urlparse, urlunparse
    parsed = urlparse(url)
    existing = parsed.query
    extra = urlencode(query)
    new_q = (existing + "&" + extra) if existing else extra
    return urlunparse(parsed._replace(query=new_q))


def _ws_headers(handshake: dict) -> list[str]:
    headers = []
    origin = handshake.get("origin")
    if origin:
        headers.append(f"Origin: {origin}")
    for k, v in (handshake.get("headers") or {}).items():
        headers.append(f"{k}: {v}")
    return headers


# ─── WebSocket raw (JSON message) ────────────────────────────

class RawWsAdapter(BaseAdapter):

    def _run(self, utterance: str, referer_cid: str | None) -> None:
        _require_ws()
        hs = self.ep.get("handshake", {}) or {}
        url = _ws_url_with_query(hs)
        headers = _ws_headers(hs)
        subprotocols = hs.get("subprotocols") or None

        body = self._build_body(utterance, referer_cid)
        payload = json.dumps(body, ensure_ascii=False)
        es = self.ep.get("event_stream", {}) or {}
        chunk_field = es.get("chunk_field") or self.ep.get("response_path")
        done_signal = es.get("done_signal") or {}

        chunks: list[str] = []
        done_evt = threading.Event()
        opened = threading.Event()
        first_err: list[str] = []

        def on_open(ws):
            opened.set()
            self.log.write("out", {"url": url, "body": body})
            try:
                ws.send(payload)
            except Exception as e:
                first_err.append(f"send_fail: {e}")
                done_evt.set()

        def on_message(ws, msg):
            self.result.frames_total += 1
            self.log.write("in", msg)
            try:
                obj = json.loads(msg)
            except ValueError:
                # plain text chunk
                chunks.append(msg)
                self._record_event("TEXT")
                return
            ev = str(obj.get("event") or obj.get("type") or "MESSAGE")
            self._record_event(ev)
            # chunk 추출
            if chunk_field:
                v = _dotted_get(obj, chunk_field)
                if isinstance(v, str):
                    chunks.append(v)
            # cid 추출
            mt = self.ep.get("multiturn", {}) or {}
            extract = mt.get("extract_path")
            if not self.result.conversation_id and extract:
                cid = _dotted_get(obj, extract) or _find_first(obj, extract.split(".")[-1])
                if isinstance(cid, (str, int)):
                    self.result.conversation_id = str(cid)
            # 차단/완료
            if _match_signal(obj, done_signal):
                done_evt.set()
            for be in (es.get("block_events") or []):
                if str(obj.get("event")) == be:
                    self.result.status = "block"

        def on_error(ws, err):
            first_err.append(str(err))

        def on_close(ws, *_):
            done_evt.set()

        ws = websocket.WebSocketApp(
            url, header=headers,
            on_open=on_open, on_message=on_message,
            on_error=on_error, on_close=on_close,
            subprotocols=subprotocols,
        )
        run_thread = threading.Thread(
            target=lambda: ws.run_forever(ping_interval=15),
            daemon=True,
        )
        run_thread.start()
        if not opened.wait(timeout=self.timeout):
            self.result.status = "connect_fail"
            self.result.error = first_err[0] if first_err else "open timeout"
            try: ws.close()
            except Exception: pass
            return
        done_evt.wait(timeout=self.timeout)
        try: ws.close()
        except Exception: pass

        self.result.model_text = "".join(chunks)
        if self.result.status == "error":
            if done_evt.is_set():
                self.result.status = "ok" if self.result.model_text else "timeout"
            else:
                self.result.status = "timeout"


def _match_signal(obj: dict, signal: dict) -> bool:
    """{event: "DONE"} 또는 {event: "LLM", "data.status": "DONE"} 같은 매칭."""
    if not signal:
        return False
    for path, expected in signal.items():
        actual = _dotted_get(obj, path)
        if actual != expected:
            return False
    return True


# ─── STOMP over WebSocket ────────────────────────────────────

class StompAdapter(BaseAdapter):

    def _run(self, utterance: str, referer_cid: str | None) -> None:
        _require_ws()
        hs = self.ep.get("handshake", {}) or {}
        frames = self.ep.get("frames", {}) or {}
        es = self.ep.get("event_stream", {}) or {}
        hb_cfg = self.ep.get("heartbeat", {}) or {}

        url = _ws_url_with_query(hs)
        headers = _ws_headers(hs)
        subprotocols = hs.get("subprotocols") or ["v12.stomp", "v11.stomp", "v10.stomp"]

        from urllib.parse import urlparse
        host = urlparse(hs.get("url", "")).hostname or ""

        connect_tpl = frames.get("connect_template") or (
            "CONNECT\naccept-version:1.2\nheart-beat:10000,10000\nhost:{host}\n\n\x00"
        )
        terminator = frames.get("terminator", "\x00")
        sub_dest = frames.get("subscribe_destination", "/user/topic/v1/chat/reply")
        send_dest = frames.get("send_destination", "/app/v1/chat")

        body_obj = self._build_body(utterance, referer_cid)
        body_str = json.dumps(body_obj, ensure_ascii=False)
        clen = len(body_str.encode("utf-8"))

        chunks: list[str] = []
        done_evt = threading.Event()
        opened = threading.Event()
        hb_stop = [False]
        first_err: list[str] = []
        chunk_event = es.get("chunk_event") or "LLM"
        chunk_field = es.get("chunk_field") or "data.message"
        done_signal = es.get("done_signal") or {"event": "DONE"}
        block_events = es.get("block_events") or []
        progress_event = es.get("progress_event") or "PROGRESS"

        def on_open(ws):
            opened.set()
            try:
                ws.send(connect_tpl.format(host=host))
                self.log.write("out", connect_tpl.format(host=host), note="STOMP_CONNECT")
                time.sleep(0.6)
                sub_frame = f"SUBSCRIBE\nid:sub-0\ndestination:{sub_dest}\n\n{terminator}"
                ws.send(sub_frame)
                self.log.write("out", sub_frame, note="STOMP_SUBSCRIBE")
                time.sleep(0.3)
                send_frame = (
                    f"SEND\ndestination:{send_dest}\ncontent-type:application/json\n"
                    f"content-length:{clen}\n\n{body_str}{terminator}"
                )
                ws.send(send_frame)
                self.log.write("out", send_frame, note="STOMP_SEND")
                # heartbeat
                interval = int(hb_cfg.get("interval_sec") or 10)
                hb_payload = hb_cfg.get("payload") or "\n"
                def hb_loop():
                    while not hb_stop[0]:
                        time.sleep(interval)
                        try:
                            if not hb_stop[0]:
                                ws.send(hb_payload)
                        except Exception:
                            break
                threading.Thread(target=hb_loop, daemon=True).start()
            except Exception as e:
                first_err.append(f"open_send_fail: {e}")
                done_evt.set()

        def on_message(ws, msg):
            self.result.frames_total += 1
            if msg in ("\n", "\r\n"):
                self._record_event("HEARTBEAT")
                return
            self.log.write("in", msg)
            # STOMP frame 파싱
            try:
                hdr_end = msg.find("\n\n")
                if hdr_end < 0:
                    return
                header_block = msg[:hdr_end]
                body_block = msg[hdr_end + 2:].rstrip(terminator).rstrip()
                cmd = header_block.split("\n", 1)[0].strip()
                if cmd != "MESSAGE":
                    self._record_event(f"STOMP_{cmd}")
                    return
                try:
                    obj = json.loads(body_block)
                except ValueError:
                    return
                ev = str(obj.get("event") or "MESSAGE")
                self._record_event(ev)
                if ev == chunk_event:
                    v = _dotted_get(obj, chunk_field)
                    status_v = _dotted_get(obj, "data.status")
                    if isinstance(v, str) and status_v != "DONE":
                        chunks.append(v)
                # cid 추출
                mt = self.ep.get("multiturn", {}) or {}
                extract = mt.get("extract_path") or "conversationId"
                if not self.result.conversation_id:
                    cid = _dotted_get(obj, extract) or _find_first(obj, extract.split(".")[-1])
                    if isinstance(cid, (str, int)):
                        self.result.conversation_id = str(cid)
                # 차단 신호
                if ev in block_events:
                    self.result.status = "block"
                # 완료 신호
                if _match_signal(obj, done_signal):
                    done_evt.set()
            except Exception as e:
                first_err.append(f"parse_fail: {e}")

        def on_error(ws, err):
            first_err.append(str(err))

        def on_close(ws, *_):
            hb_stop[0] = True
            done_evt.set()

        ws = websocket.WebSocketApp(
            url, header=headers,
            on_open=on_open, on_message=on_message,
            on_error=on_error, on_close=on_close,
            subprotocols=subprotocols,
        )
        threading.Thread(
            target=lambda: ws.run_forever(ping_interval=15),
            daemon=True,
        ).start()
        if not opened.wait(timeout=self.timeout):
            self.result.status = "connect_fail"
            self.result.error = first_err[0] if first_err else "open timeout"
            hb_stop[0] = True
            try: ws.close()
            except Exception: pass
            return
        done_evt.wait(timeout=self.timeout)
        hb_stop[0] = True
        try: ws.close()
        except Exception: pass

        self.result.model_text = "".join(chunks)
        if self.result.status == "error":
            if done_evt.is_set():
                self.result.status = "ok" if (self.result.model_text or self.result.frames_total > 0) else "timeout"
            else:
                self.result.status = "timeout"


# ─── SSE ─────────────────────────────────────────────────────

class SseAdapter(BaseAdapter):

    def _run(self, utterance: str, referer_cid: str | None) -> None:
        base = self.ep.get("base_url", "").rstrip("/")
        route = self.ep.get("route", "")
        url = base + route
        headers = dict(self.ep.get("headers", {}) or {})
        headers.setdefault("Accept", "text/event-stream")
        method = (self.ep.get("method") or "POST").upper()
        body = self._build_body(utterance, referer_cid)
        es = self.ep.get("event_stream", {}) or {}
        chunk_field = es.get("chunk_field")
        done_signal_text = es.get("done_signal_text") or "[DONE]"
        block_markers = es.get("block_events") or []

        self.log.write("out", {"url": url, "method": method, "headers": headers, "body": body})
        try:
            r = requests.request(method, url, headers=headers, json=body, stream=True, timeout=self.timeout)
        except requests.exceptions.ConnectionError as e:
            self.result.status = "connect_fail"
            self.result.error = str(e)
            return
        except requests.exceptions.Timeout:
            self.result.status = "timeout"
            return

        if r.status_code in (401, 403):
            self.result.status = "auth_fail"
            return
        if r.status_code >= 400:
            self.result.status = "error"
            self.result.error = f"http_{r.status_code}"
            return

        chunks: list[str] = []
        for line in r.iter_lines(decode_unicode=True):
            if line is None:
                continue
            self.result.frames_total += 1
            self.log.write("in", line)
            if not line:
                continue
            if line.startswith(":"):
                self._record_event("COMMENT")
                continue
            if line.startswith("event:"):
                ev = line[6:].strip()
                self._record_event(ev or "EVENT")
                if ev in block_markers:
                    self.result.status = "block"
                continue
            if line.startswith("data:"):
                data = line[5:].lstrip()
                if data == done_signal_text:
                    self._record_event("DONE")
                    break
                self._record_event("DATA")
                # JSON chunk 시도, 아니면 raw
                try:
                    obj = json.loads(data)
                    v = _dotted_get(obj, chunk_field) if chunk_field else None
                    if isinstance(v, str):
                        chunks.append(v)
                    else:
                        chunks.append(data)
                    mt = self.ep.get("multiturn", {}) or {}
                    extract = mt.get("extract_path")
                    if not self.result.conversation_id and extract:
                        cid = _dotted_get(obj, extract) or _find_first(obj, extract.split(".")[-1])
                        if isinstance(cid, (str, int)):
                            self.result.conversation_id = str(cid)
                except ValueError:
                    chunks.append(data)

        self.result.model_text = "".join(chunks)
        if self.result.status == "error":
            self.result.status = "ok" if chunks else "timeout"


# ─── 스텁: SocketIO / GraphqlWs ─────────────────────────────

class _StubAdapter(BaseAdapter):

    def _run(self, utterance: str, referer_cid: str | None) -> None:
        self.result.status = "unsupported_channel"
        self.result.error = (
            f"channel '{self.ep.get('channel')}' adapter is not implemented yet. "
            "현재 지원: http, ws-raw, ws-stomp, sse"
        )


# ─── 어댑터 디스패치 ─────────────────────────────────────────

ADAPTERS = {
    "http": HttpAdapter,
    "ws-raw": RawWsAdapter,
    "ws-stomp": StompAdapter,
    "sse": SseAdapter,
    "ws-socketio": _StubAdapter,
    "ws-graphql": _StubAdapter,
}


# ─── 메인 ────────────────────────────────────────────────────

def _load_endpoint(path: str, index: int) -> tuple[dict | None, str | None]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return None, f"load_fail: {e}"
    endpoints = data.get("endpoints") or []
    if not isinstance(endpoints, list) or index >= len(endpoints) or index < 0:
        return None, f"endpoint_index out of range (have {len(endpoints)}, want {index})"
    ep = endpoints[index]
    if not isinstance(ep, dict):
        return None, "endpoint not a dict"
    return ep, None


def main() -> int:
    p = argparse.ArgumentParser(description="Noah SAST LLM 채널 어댑터.")
    p.add_argument("--endpoint", required=True, help="llm_endpoint.json 경로")
    p.add_argument("--endpoint-index", type=int, default=0)
    p.add_argument("--utterance", required=True)
    p.add_argument("--referer-cid", default=None)
    p.add_argument("--mode", choices=("discover", "probe", "test"), default="probe")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--out-jsonl", default=None)
    args = p.parse_args()

    ep, err = _load_endpoint(args.endpoint, args.endpoint_index)
    if err:
        out = ChannelResult(channel="unknown", endpoint_index=args.endpoint_index)
        out.status = "error"
        out.error = err
        print(json.dumps(out.to_dict(), ensure_ascii=False))
        return 1

    channel = ep.get("channel", "http")
    adapter_cls = ADAPTERS.get(channel)
    if adapter_cls is None:
        out = ChannelResult(channel=channel, endpoint_index=args.endpoint_index)
        out.status = "unsupported_channel"
        out.error = f"unknown channel: {channel}"
        print(json.dumps(out.to_dict(), ensure_ascii=False))
        return 1

    log = TranscriptLogger(args.out_jsonl, channel=channel, endpoint_index=args.endpoint_index)
    log.write("meta", {"mode": args.mode, "utterance": args.utterance, "referer_cid": args.referer_cid})
    adapter = adapter_cls(ep, args.endpoint_index, log, args.timeout)
    result = adapter.run(args.utterance, args.referer_cid)
    log.write("meta", result.to_dict(), note="result")
    print(json.dumps(result.to_dict(), ensure_ascii=False))
    return 0 if result.status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
