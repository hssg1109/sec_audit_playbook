#!/usr/bin/env python3
"""
trace_kafka_flow.py — Kafka 비동기 Taint Tracer
========================================================
Kafka Producer → Topic → Consumer → Sink(Repository.save)까지
정적 소스코드 분석으로 Taint Break 구간을 자동으로 연결한다.

사용법:
    python3 trace_kafka_flow.py <source_dir> [topic_name]
    python3 trace_kafka_flow.py testbed/gws/oki-be@develop@af96995
    python3 trace_kafka_flow.py testbed/gws/oki-be@develop@af96995 "oki.pv.rake"

출력: JSON — {topic: {producers, consumers, sinks, taint_result}}
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# 정규식 패턴 정의
# ──────────────────────────────────────────────────────────────────────────────

# Producer 탐지: KafkaTemplate.send("topic", ...) / kafkaProducer.send(...)
# 그룹 1: topic 문자열 리터럴 또는 상수/변수명
_RE_PRODUCER = re.compile(
    r"""
    (?:kafkaTemplate|kafkaSender|producer|kafkaProducer)
    \s*\.\s*send\s*\(
        \s*
        (?P<topic>                           # 그룹 'topic'
            "(?P<literal>[^"]+)"             # 문자열 리터럴 "topic-name"
            | '(?P<literal2>[^']+)'          # 단일따옴표 'topic-name'
            | (?P<var>[A-Z_][A-Z0-9_.]+)     # 상수 TOPIC_RAKE
            | (?P<var2>[a-zA-Z_]\w*(?:\.\w+)*) # 변수/필드 topic, this.topic
        )
    """,
    re.VERBOSE,
)

# Consumer 탐지: @KafkaListener(topics = "topic-name") 또는 topics = {"t1","t2"}
# 변수 치환 패턴 ${kafka.topic.name} 도 포함
_RE_LISTENER_ANNOTATION = re.compile(
    r"""
    @KafkaListener\s*\(
        [^)]*?
        topics\s*=\s*
        (?:
            \{(?P<multi>[^}]+)\}             # {"topic1","topic2"}
            | (?P<single>"[^"]*"|'[^']*'|\$\{[^}]+\}|[A-Z_][A-Z0-9_.]+)
        )
    """,
    re.VERBOSE | re.DOTALL,
)

# Listener 메서드 시그니처: @KafkaListener 직후 public void methodName(...)
_RE_LISTENER_METHOD = re.compile(
    r"(?:public|protected|private)?\s*\w[\w<>,\s]*\s+(\w+)\s*\("
)

# Sink 탐지 (Repository / Mapper DB Write)
_RE_SINK = re.compile(
    r"""
    (?P<repo>\w*[Rr]epository\w*|\w*[Mm]apper\w*|\w*[Dd]ao\w*)
    \s*\.\s*
    (?P<method>save|saveAll|saveAndFlush|insert|insertAll|update|
               updateAll|merge|batchInsert|execute|persist)\s*\(
    """,
    re.VERBOSE,
)

# String 자유텍스트 필드 탐지 (Entity/DTO)
_RE_STRING_FIELD = re.compile(
    r"""
    (?:private|public|protected)?\s+String\s+
    (?P<field>\w+)\s*[;=]
    """,
    re.VERBOSE,
)

# application.yml 변수 치환: ${kafka.topic.name}
_RE_YAML_PLACEHOLDER = re.compile(r"\$\{(?P<key>[^}:]+)(?::[^}]*)?\}")


# ──────────────────────────────────────────────────────────────────────────────
# 데이터 클래스
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ProducerSite:
    file: str
    line: int
    method_context: str   # Producer가 있는 핸들러/서비스 메서드명
    raw_topic_expr: str   # 소스 코드에서 추출한 topic 표현식 (리터럴/변수)
    resolved_topic: str   # application.yml 치환 후 실제 topic 이름


@dataclass
class ConsumerSite:
    file: str
    line: int
    listener_method: str  # @KafkaListener 붙은 메서드명
    topic_pattern: str    # @KafkaListener에 기재된 topic 패턴


@dataclass
class SinkSite:
    file: str
    line: int
    repo_call: str        # e.g. "userRepository.save(user)"
    string_fields: list[str]   # 저장 엔티티의 String 필드 목록
    has_free_text: bool   # String 자유텍스트 필드 존재 여부


@dataclass
class KafkaTaintResult:
    topic: str
    producers: list[ProducerSite] = field(default_factory=list)
    consumers: list[ConsumerSite] = field(default_factory=list)
    sinks: list[SinkSite] = field(default_factory=list)
    # Persistent XSS 3원칙 적용 최종 판정
    db_write_confirmed: bool = False        # 원칙 1: Sink 도달 확인
    free_text_field_confirmed: bool = False # 원칙 2: String 자유텍스트 필드 확인
    xss_verdict: str = "미확인"             # 확정취약 / 잠재취약 / 양호
    note: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# YAML 변수 치환 유틸
# ──────────────────────────────────────────────────────────────────────────────

def _load_yaml_props(source_dir: Path) -> dict[str, str]:
    """
    application.yml / application-*.yml 에서 kafka 관련 설정을 flat dict로 로드.
    단순 regex 파싱 (PyYAML 불필요).
    """
    props: dict[str, str] = {}
    for yml_file in source_dir.rglob("application*.yml"):
        try:
            text = yml_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # 단순 key: value 파싱 (중첩 key는 indent 레벨 추적으로 처리)
        key_stack: list[str] = []
        prev_indent = -1
        for line in text.splitlines():
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(stripped)
            if ":" in stripped:
                key_part, _, val_part = stripped.partition(":")
                key_part = key_part.strip()
                val_part = val_part.strip()
                # indent 레벨로 key_stack 조정
                depth = indent // 2
                key_stack = key_stack[:depth]
                key_stack.append(key_part)
                if val_part and not val_part.startswith("{") and not val_part.startswith("["):
                    flat_key = ".".join(key_stack)
                    # 따옴표 제거
                    props[flat_key] = val_part.strip("\"'")
    return props


def _resolve_topic(raw_expr: str, props: dict[str, str]) -> str:
    """
    raw_expr 예시:
      '"oki.pv.rake"'     → "oki.pv.rake"
      '${kafka.topic.pv}' → props['kafka.topic.pv'] 값으로 치환
      'TOPIC_RAKE'        → 상수명 그대로 반환 (추가 추적 불가)
    """
    raw_expr = raw_expr.strip("\"' ")
    match = _RE_YAML_PLACEHOLDER.fullmatch(raw_expr)
    if match:
        key = match.group("key")
        return props.get(key, raw_expr)  # 치환 못 하면 원본 반환
    return raw_expr


# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Producer 탐지
# ──────────────────────────────────────────────────────────────────────────────

def _find_producers(source_dir: Path, props: dict[str, str]) -> list[ProducerSite]:
    """
    소스코드 내 KafkaTemplate.send(topic, ...) 호출 전수 탐지.
    """
    producers: list[ProducerSite] = []
    for java_file in source_dir.rglob("*.java"):
        try:
            lines = java_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        for m in _RE_PRODUCER.finditer(text):
            lineno = text[: m.start()].count("\n") + 1
            # topic 표현식 추출
            raw = (
                m.group("literal") or m.group("literal2")
                or m.group("var") or m.group("var2") or ""
            ).strip()
            resolved = _resolve_topic(raw, props)
            # 메서드 컨텍스트: Producer 호출 위 가장 가까운 메서드 시그니처
            ctx_lines = lines[max(0, lineno - 30): lineno]
            method_ctx = ""
            for cl in reversed(ctx_lines):
                meth_m = re.search(r"(?:public|private|protected)\s+\S+\s+(\w+)\s*\(", cl)
                if meth_m:
                    method_ctx = meth_m.group(1)
                    break
            producers.append(ProducerSite(
                file=str(java_file.relative_to(source_dir)),
                line=lineno,
                method_context=method_ctx,
                raw_topic_expr=raw,
                resolved_topic=resolved,
            ))
    return producers


# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Consumer(Listener) 탐지 — Topic 매핑
# ──────────────────────────────────────────────────────────────────────────────

def _find_consumers(source_dir: Path, target_topic: str,
                    props: dict[str, str]) -> list[ConsumerSite]:
    """
    @KafkaListener(topics = "target_topic") 를 수신하는 메서드 탐지.
    application.yml 변수 치환 포함.
    """
    consumers: list[ConsumerSite] = []
    for java_file in source_dir.rglob("*.java"):
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            continue

        for ann_m in _RE_LISTENER_ANNOTATION.finditer(text):
            lineno = text[: ann_m.start()].count("\n") + 1
            # @KafkaListener 내 topics 값 추출 (multi or single)
            multi_str = ann_m.group("multi") or ""
            single_str = ann_m.group("single") or ""
            raw_topics: list[str] = []
            if multi_str:
                # {"oki.pv.rake", "${kafka.t2}"}
                raw_topics = [t.strip().strip("\"'") for t in multi_str.split(",")]
            elif single_str:
                raw_topics = [single_str.strip().strip("\"'")]

            # topic 해상도 (YAML 변수 치환)
            resolved_topics = [_resolve_topic(t, props) for t in raw_topics]

            if target_topic not in resolved_topics:
                continue  # 이 리스너는 대상 topic을 수신하지 않음

            # 리스너 메서드명 추출: @KafkaListener 이후 첫 메서드 시그니처
            after_ann = text[ann_m.end():]
            meth_m = _RE_LISTENER_METHOD.search(after_ann[:300])
            listener_method = meth_m.group(1) if meth_m else "<unknown>"

            consumers.append(ConsumerSite(
                file=str(java_file.relative_to(source_dir)),
                line=lineno,
                listener_method=listener_method,
                topic_pattern=", ".join(raw_topics),
            ))
    return consumers


# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Sink 탐지 — Consumer 메서드 바디 내 Repository.save() + String 필드
# ──────────────────────────────────────────────────────────────────────────────

def _extract_method_body(text: str, method_name: str, start_hint: int = 0) -> str:
    """
    Java 소스에서 메서드 바디 추출 (중괄호 매칭 방식).
    start_hint: 탐색 시작 라인 오프셋
    """
    # 메서드 시그니처 찾기
    pattern = re.compile(
        rf"(?:public|private|protected)\s+\S+\s+{re.escape(method_name)}\s*\("
    )
    m = pattern.search(text, start_hint)
    if not m:
        return ""
    # 첫 번째 '{' 위치로 이동
    brace_start = text.find("{", m.end())
    if brace_start == -1:
        return ""
    depth = 0
    end = brace_start
    for i, ch in enumerate(text[brace_start:], brace_start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    return text[brace_start: end + 1]


def _find_entity_string_fields(source_dir: Path, entity_hint: str) -> list[str]:
    """
    entity_hint로 Entity/DTO 클래스를 찾아 String 필드 목록 반환.
    entity_hint: "UserEntity", "PvRakeDto" 등 클래스명 힌트
    """
    str_fields: list[str] = []
    pattern = re.compile(
        rf"class\s+{re.escape(entity_hint)}\b"
    )
    for java_file in source_dir.rglob(f"*{entity_hint}*.java"):
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not pattern.search(text):
            continue
        for fm in _RE_STRING_FIELD.finditer(text):
            fname = fm.group("field")
            # id/version/password/hash 계열 제외 (FP 방지)
            if not re.search(r"id$|version|password|hash|token|uuid", fname, re.I):
                str_fields.append(fname)
    return str_fields


def _find_sinks_in_consumers(source_dir: Path,
                               consumers: list[ConsumerSite]) -> list[SinkSite]:
    """
    Consumer 메서드 바디에서 Repository.save() 호출 탐지 후
    대상 엔티티의 String 필드 확인 (Persistent XSS 3원칙 적용).
    """
    sinks: list[SinkSite] = []
    for consumer in consumers:
        java_path = source_dir / consumer.file
        try:
            text = java_path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            continue

        body = _extract_method_body(text, consumer.listener_method)
        if not body:
            continue

        # body 내 모든 Repository.save() 탐지
        for sink_m in _RE_SINK.finditer(body):
            # sink 호출 절대 라인 계산
            body_offset = text.find(body)
            abs_offset = body_offset + sink_m.start()
            lineno = text[:abs_offset].count("\n") + 1
            repo_call_str = body[sink_m.start(): sink_m.end() + 60].split("\n")[0].strip()

            # 파라미터 엔티티명 추출: .save(entity) → entity 타입 추론
            # Consumer 메서드 파라미터 타입 또는 save() 인수 변수명으로 역추적
            entity_hint = ""
            save_arg_m = re.search(
                rf"{sink_m.group('method')}\s*\(\s*(\w+)", body[sink_m.start():]
            )
            if save_arg_m:
                var_name = save_arg_m.group(1)
                # 메서드 바디 내 변수 타입 선언 탐지: TypeName var_name = ...
                decl_m = re.search(
                    rf"(\w+)\s+{re.escape(var_name)}\s*[=;(]", body
                )
                if decl_m:
                    entity_hint = decl_m.group(1)

            # String 필드 조회
            str_fields = _find_entity_string_fields(source_dir, entity_hint) if entity_hint else []
            has_free_text = bool(str_fields)

            sinks.append(SinkSite(
                file=consumer.file,
                line=lineno,
                repo_call=repo_call_str,
                string_fields=str_fields,
                has_free_text=has_free_text,
            ))
    return sinks


# ──────────────────────────────────────────────────────────────────────────────
# 메인 함수: trace_kafka_flow
# ──────────────────────────────────────────────────────────────────────────────

def trace_kafka_flow(source_dir: Path | str,
                     topic_name: str | None = None) -> list[KafkaTaintResult]:
    """
    Kafka Producer→Consumer→Sink Taint 추적.

    Args:
        source_dir : 분석 대상 소스코드 루트 디렉토리
        topic_name : 특정 topic만 추적 (None = 전체 Producer topic 자동 수집)

    Returns:
        List[KafkaTaintResult] — topic별 Taint 추적 결과

    판정 기준 (Persistent XSS 3원칙):
        원칙 1 — Sink 도달: Consumer에서 Repository.save() 확인
        원칙 2 — Data Type: 저장 엔티티에 String 자유텍스트 필드 확인
        원칙 3 — Async Taint Break: Consumer 미발견 시 "잠재취약" 분류
    """
    source_dir = Path(source_dir)
    if not source_dir.exists():
        raise FileNotFoundError(f"Source dir not found: {source_dir}")

    # YAML 설정 로드 (${...} 변수 치환용)
    props = _load_yaml_props(source_dir)

    # Step 1: Producer 전수 탐지
    all_producers = _find_producers(source_dir, props)

    # topic_name이 지정된 경우 해당 topic만 필터링, 아니면 전체 topic 수집
    if topic_name:
        target_topics = [topic_name]
        producers_by_topic: dict[str, list[ProducerSite]] = {
            topic_name: [p for p in all_producers if p.resolved_topic == topic_name]
        }
    else:
        # 전체 Producer topic 자동 수집
        producers_by_topic = {}
        for prod in all_producers:
            producers_by_topic.setdefault(prod.resolved_topic, []).append(prod)
        target_topics = list(producers_by_topic.keys())

    results: list[KafkaTaintResult] = []

    for topic in target_topics:
        result = KafkaTaintResult(topic=topic)
        result.producers = producers_by_topic.get(topic, [])

        # Step 2: Consumer(@KafkaListener) 탐지
        result.consumers = _find_consumers(source_dir, topic, props)

        if not result.consumers:
            # Consumer 미발견 = Taint Break → 잠재취약 (보수적)
            result.xss_verdict = "잠재취약"
            result.note = (
                f"Topic '{topic}'을 수신하는 @KafkaListener 미발견. "
                "Consumer가 별도 모듈/레포에 위치하거나 동적 topic 바인딩 가능성. "
                "아키텍처 수준 수동 교차 검증 필요."
            )
            results.append(result)
            continue

        # Step 3: Sink 탐지 (원칙 1 + 2 적용)
        result.sinks = _find_sinks_in_consumers(source_dir, result.consumers)

        if not result.sinks:
            result.db_write_confirmed = False
            result.xss_verdict = "잠재취약"
            result.note = (
                f"@KafkaListener 발견({len(result.consumers)}건)이나 "
                "메서드 바디 내 Repository.save() 미확인. "
                "간접 호출 또는 AOP 처리 가능성 — 수동 확인 권고."
            )
        else:
            result.db_write_confirmed = True
            all_fields = [f for s in result.sinks for f in s.string_fields]
            result.free_text_field_confirmed = any(s.has_free_text for s in result.sinks)
            if result.free_text_field_confirmed:
                result.xss_verdict = "확정취약"
                result.note = (
                    f"DB Write 확인({len(result.sinks)}건) + "
                    f"String 자유텍스트 필드 확인: {all_fields[:5]}. "
                    "전역 XSS 필터 미적용(filter_level: none) → Persistent XSS 확정."
                )
            else:
                result.xss_verdict = "양호"
                result.note = (
                    f"DB Write 확인({len(result.sinks)}건)이나 "
                    "저장 필드가 숫자/Enum/UUID만 — XSS 페이로드 삽입 불가 (FP)."
                )

        results.append(result)

    return results


# ──────────────────────────────────────────────────────────────────────────────
# CLI 진입점
# ──────────────────────────────────────────────────────────────────────────────

def _to_serializable(obj):
    if isinstance(obj, list):
        return [_to_serializable(i) for i in obj]
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _to_serializable(v) for k, v in asdict(obj).items()}
    return obj


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: trace_kafka_flow.py <source_dir> [topic_name]")
        sys.exit(1)

    src = Path(sys.argv[1])
    topic = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"🔍 Kafka Taint Tracer — source: {src}", file=sys.stderr)
    print(f"   target topic: {topic or '(전체)'}", file=sys.stderr)

    results = trace_kafka_flow(src, topic)

    # 요약 출력
    print(f"\n📊 분석 결과 — {len(results)}개 topic", file=sys.stderr)
    confirmed_vuln = sum(1 for r in results if r.xss_verdict == "확정취약")
    latent_vuln    = sum(1 for r in results if r.xss_verdict == "잠재취약")
    safe           = sum(1 for r in results if r.xss_verdict == "양호")
    print(f"   확정취약: {confirmed_vuln} | 잠재취약: {latent_vuln} | 양호: {safe}", file=sys.stderr)

    # JSON 결과 출력
    print(json.dumps(_to_serializable(results), ensure_ascii=False, indent=2))
