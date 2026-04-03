"""
phase3_coordinator.py — Phase 3 LLM 병렬 워커 코디네이터

여러 Phase 3 태스크(injection / xss / file_handling / data_protection / sca)를
ThreadPoolExecutor로 병렬 실행하고 API Rate Limit 방어, 실시간 비용 추적,
세이프가드(Safeguard), 에코 모드(Eco Mode)를 통합 제공한다.

사용법:
    python3 tools/scripts/phase3_coordinator.py \\
        --prefix 0331_comm_api \\
        --source-dir testbed/ocbwebview/comm_api \\
        --tasks injection xss file_handling data_protection sca \\
        --model claude-sonnet-4-6 \\
        --max-workers 3 \\
        --session-budget 10.0 \\
        --weekly-budget 50.0

출력:
    state/<prefix>/usage_summary.json  (효율성 리포트)
    state/<prefix>/task22_llm.json     (injection 결과, 태스크별)
    ...
"""

from __future__ import annotations

import argparse
import functools
import json
import logging
import os
import random
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── 써드파티 의존 ────────────────────────────────────────────────────────────
try:
    import anthropic
except ImportError:
    sys.exit("[Error] anthropic 패키지 없음. pip install anthropic 후 재실행.")

# ─── 로깅 설정 ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("phase3")

# ─── 모델 단가표 (USD / 1M tokens) ─────────────────────────────────────────────
#   갱신 기준: https://www.anthropic.com/pricing (2025-04 기준)
PRICE_TABLE: dict[str, dict[str, float]] = {
    "claude-sonnet-4-6": {
        "input":        3.00,
        "output":      15.00,
        "cache_read":   0.30,
        "cache_write":  3.75,
    },
    "claude-opus-4-6": {
        "input":       15.00,
        "output":      75.00,
        "cache_read":   1.50,
        "cache_write": 18.75,
    },
    "claude-haiku-4-5-20251001": {
        "input":        0.80,
        "output":        4.00,
        "cache_read":   0.08,
        "cache_write":  1.00,
    },
    # 폴백: 알 수 없는 모델은 Sonnet 단가 적용
    "_default": {
        "input":        3.00,
        "output":      15.00,
        "cache_read":   0.30,
        "cache_write":  3.75,
    },
}

# 컨텍스트 압축 임계값 (토큰)  — 에코 모드 시 50% 적용
NORMAL_COMPACT_THRESHOLD = 80_000
ECO_COMPACT_THRESHOLD    = NORMAL_COMPACT_THRESHOLD // 2   # 40_000

# Phase 3 태스크 → 출력 파일명 매핑
TASK_OUTPUT_MAP: dict[str, str] = {
    "injection":       "task22_llm.json",
    "xss":             "task23_llm.json",
    "file_handling":   "task24_llm.json",
    "data_protection": "task25_llm.json",
    "sca":             "sca_llm.json",
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. 데이터 클래스
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UsageMetrics:
    """단일 워커 실행에서 수집된 토큰/비용 정보."""
    task_id:                    str   = ""
    input_tokens:               int   = 0
    output_tokens:              int   = 0
    cache_read_input_tokens:    int   = 0
    cache_creation_input_tokens: int  = 0
    cost_usd:                   float = 0.0
    eco_mode_active:            bool  = False

    @classmethod
    def from_response(
        cls,
        task_id: str,
        usage: anthropic.types.Usage,
        model: str,
        eco_mode: bool = False,
    ) -> "UsageMetrics":
        prices = PRICE_TABLE.get(model, PRICE_TABLE["_default"])
        inp    = getattr(usage, "input_tokens",                0) or 0
        out    = getattr(usage, "output_tokens",               0) or 0
        cr     = getattr(usage, "cache_read_input_tokens",    0) or 0
        cw     = getattr(usage, "cache_creation_input_tokens",0) or 0

        cost = (
            inp * prices["input"]        / 1_000_000 +
            out * prices["output"]       / 1_000_000 +
            cr  * prices["cache_read"]   / 1_000_000 +
            cw  * prices["cache_write"]  / 1_000_000
        )
        return cls(
            task_id=task_id,
            input_tokens=inp,
            output_tokens=out,
            cache_read_input_tokens=cr,
            cache_creation_input_tokens=cw,
            cost_usd=cost,
            eco_mode_active=eco_mode,
        )


@dataclass
class WorkerResult:
    """워커 실행 결과 전체 (진단 결과 + 사용량)."""
    task_id:  str
    success:  bool
    payload:  dict[str, Any]   = field(default_factory=dict)
    metrics:  UsageMetrics     = field(default_factory=UsageMetrics)
    error:    str              = ""


# ─────────────────────────────────────────────────────────────────────────────
# 2. 지수 백오프 + 지터 데코레이터
# ─────────────────────────────────────────────────────────────────────────────

def retry_with_backoff(
    max_attempts: int = 5,
    base_delay:   float = 2.0,
    jitter_range: tuple[float, float] = (0.5, 1.5),
):
    """
    Rate Limit(429) 전용 재시도 데코레이터.

    - 429 / "rate limit" 감지 시에만 백오프 실행.
    - 그 외 예외는 즉시 re-raise (Fail-fast).
    - 지연 = base_delay * 2^(attempt-1) + random.uniform(*jitter_range)
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)

                except anthropic.RateLimitError as exc:
                    if attempt == max_attempts:
                        log.error("[Error] Rate limit — 최대 재시도 초과 (%d회). 포기.", max_attempts)
                        raise
                    jitter = random.uniform(*jitter_range)
                    wait   = delay + jitter
                    log.warning(
                        "[Warning] Rate limit 초과. %.1f초 후 재시도 (Attempt %d/%d)",
                        wait, attempt, max_attempts,
                    )
                    time.sleep(wait)
                    delay *= 2  # 지수 증가

                except anthropic.APIStatusError as exc:
                    # 429를 직접 구분하지 못하는 경우 메시지에서 키워드 탐지
                    msg = str(exc).lower()
                    if "429" in msg or "rate limit" in msg or "rate_limit" in msg:
                        if attempt == max_attempts:
                            log.error("[Error] Rate limit — 최대 재시도 초과 (%d회). 포기.", max_attempts)
                            raise
                        jitter = random.uniform(*jitter_range)
                        wait   = delay + jitter
                        log.warning(
                            "[Warning] Rate limit 초과. %.1f초 후 재시도 (Attempt %d/%d)",
                            wait, attempt, max_attempts,
                        )
                        time.sleep(wait)
                        delay *= 2
                    else:
                        # 치명적 오류 — 즉시 실패
                        log.error("[Error] API 오류 (Fail-fast): %s", exc)
                        raise

        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# 3. 세션 세이프가드 (SessionSafeguard)
# ─────────────────────────────────────────────────────────────────────────────

class SessionSafeguard:
    """
    시간 기반 소모율(Burn Rate)로 예산 초과를 선제 탐지한다.

    핵심 지표:
      hourly_rate = cumulative_cost / elapsed_hours
      predicted_session_cost = hourly_rate * SESSION_HOURS
      predicted_total_cost   = weekly_so_far + predicted_session_cost

    에코 모드 트리거: hourly_rate > (MAX_SESSION_BUDGET * 0.8) / SESSION_HOURS
    세이프가드 발동 : predicted_session_cost > MAX_SESSION_BUDGET
                  OR predicted_total_cost   > WEEKLY_BUDGET
    """

    SESSION_HOURS = 5.0   # Claude Pro 세션 한도 (시간)

    def __init__(
        self,
        max_session_budget: float,
        weekly_budget: float,
        weekly_usage_path: Path,
    ) -> None:
        self.max_session_budget = max_session_budget
        self.weekly_budget      = weekly_budget
        self._weekly_usage_path = weekly_usage_path

        self._lock              = threading.Lock()
        self._cumulative_cost   = 0.0
        self._start_time        = time.monotonic()
        self._eco_mode          = False
        self._halted            = False

        self._weekly_so_far     = self._load_weekly_cost()
        self._eco_trigger_rate  = (self.max_session_budget * 0.8) / self.SESSION_HOURS

        log.info(
            "[Safeguard] 세션 한도=$%.2f  주간 한도=$%.2f  에코 트리거=%.4f$/hr  "
            "주간 누적=$%.4f",
            max_session_budget, weekly_budget,
            self._eco_trigger_rate, self._weekly_so_far,
        )

    # ── 내부 헬퍼 ──────────────────────────────────────────────────────────────

    def _load_weekly_cost(self) -> float:
        if not self._weekly_usage_path.exists():
            return 0.0
        try:
            data = json.loads(self._weekly_usage_path.read_text(encoding="utf-8"))
            return float(data.get("total_cost_usd", 0.0))
        except (json.JSONDecodeError, ValueError):
            return 0.0

    def _elapsed_hours(self) -> float:
        elapsed_sec = time.monotonic() - self._start_time
        return max(elapsed_sec / 3600, 1e-9)   # 0 나누기 방지

    def _hourly_rate(self) -> float:
        return self._cumulative_cost / self._elapsed_hours()

    # ── 공개 API ───────────────────────────────────────────────────────────────

    def record_cost(self, cost_usd: float) -> None:
        """워커 완료 후 비용을 누적하고 상태를 갱신한다."""
        with self._lock:
            self._cumulative_cost += cost_usd
            self._evaluate()

    def _evaluate(self) -> None:
        """에코 모드 / 세이프가드 판정 (락 안에서 호출)."""
        hr = self._hourly_rate()
        predicted_session = hr * self.SESSION_HOURS
        predicted_total   = self._weekly_so_far + predicted_session

        # 에코 모드 진입 (아직 아니라면)
        if not self._eco_mode and hr > self._eco_trigger_rate:
            self._eco_mode = True
            log.warning(
                "[Eco Mode] 활성화 — hourly_rate=%.4f$/hr > 임계값=%.4f$/hr  "
                "(예상 세션 비용=%.4f$). 컨텍스트 압축 임계값 %d → %d 토큰으로 축소.",
                hr, self._eco_trigger_rate, predicted_session,
                NORMAL_COMPACT_THRESHOLD, ECO_COMPACT_THRESHOLD,
            )

        # 세이프가드 발동
        if not self._halted:
            if predicted_session > self.max_session_budget:
                self._halted = True
                log.error(
                    "[Safeguard] 강제 중단 — 예상 세션 비용 %.4f$ > 한도 %.2f$  "
                    "(hourly_rate=%.4f$/hr)",
                    predicted_session, self.max_session_budget, hr,
                )
            elif predicted_total > self.weekly_budget:
                self._halted = True
                log.error(
                    "[Safeguard] 강제 중단 — 예상 주간 누적 %.4f$ > 주간 한도 %.2f$  "
                    "(주간 기존=%.4f$ + 예상 세션=%.4f$)",
                    predicted_total, self.weekly_budget,
                    self._weekly_so_far, predicted_session,
                )

    @property
    def eco_mode(self) -> bool:
        with self._lock:
            return self._eco_mode

    @property
    def halted(self) -> bool:
        with self._lock:
            return self._halted

    def status_snapshot(self) -> dict[str, Any]:
        """현재 상태 스냅샷 (리포트용)."""
        with self._lock:
            hr = self._hourly_rate()
            return {
                "cumulative_cost_usd":    round(self._cumulative_cost, 6),
                "hourly_rate_usd_per_hr": round(hr, 6),
                "predicted_session_cost": round(hr * self.SESSION_HOURS, 6),
                "weekly_so_far_usd":      round(self._weekly_so_far, 6),
                "eco_mode_triggered":     self._eco_mode,
                "safeguard_halted":       self._halted,
                "elapsed_hours":          round(self._elapsed_hours(), 4),
            }

    def persist_weekly(self) -> None:
        """세션 비용을 weekly_usage.json에 누적 저장한다."""
        with self._lock:
            total = self._weekly_so_far + self._cumulative_cost
            data  = {
                "total_cost_usd":  round(total, 6),
                "last_updated_at": datetime.now(timezone.utc).isoformat(),
            }
        self._weekly_usage_path.parent.mkdir(parents=True, exist_ok=True)
        self._weekly_usage_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        log.info("[Safeguard] 주간 비용 갱신: %.6f$ → %s", total, self._weekly_usage_path)


# ─────────────────────────────────────────────────────────────────────────────
# 4. 워커 — API 호출 + 토큰 수집
# ─────────────────────────────────────────────────────────────────────────────

def _load_text(path: Path, max_chars: int | None = None) -> str:
    """파일 내용을 읽고 선택적으로 잘라 반환한다."""
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    if max_chars and len(text) > max_chars:
        text = text[:max_chars] + "\n... [truncated for eco mode]"
    return text


def _build_prompt(
    task_id: str,
    state_dir: Path,
    source_dir: Path,
    compact_threshold: int,
    playbook_root: Path,
) -> str:
    """태스크별 프롬프트를 조립한다."""
    task_prompt_map = {
        "injection":       "task_prompts/task_22_injection_review.md",
        "xss":             "task_prompts/task_23_xss_review.md",
        "file_handling":   "task_prompts/task_24_file_handling.md",
        "data_protection": "task_prompts/task_25_data_protection.md",
        "sca":             "task_prompts/task_sca_llm_review.md",
    }
    scan_file_map = {
        "injection":       "injection.json",
        "xss":             "xss.json",
        "file_handling":   "task24.json",
        "data_protection": "task25.json",
        "sca":             "sca.json",
    }

    ref_dir   = playbook_root / "skills" / "sec-audit-static" / "references"
    task_md   = ref_dir / task_prompt_map.get(task_id, "")
    scan_file = state_dir / scan_file_map.get(task_id, "")
    fp_memory = state_dir / "audit_memory.md"

    # 최대 문자 수 = compact_threshold * 4 (UTF-8 평균 4바이트/토큰)
    max_chars = compact_threshold * 4

    parts: list[str] = []

    # (1) FP 예외 메모리
    fp_text = _load_text(fp_memory)
    if fp_text.strip():
        parts.append(f"# [Project Specific Context & Exceptions]\n\n{fp_text}")

    # (2) 태스크 프롬프트
    if task_md.exists():
        parts.append(f"# Task 지침\n\n{task_md.read_text(encoding='utf-8')}")

    # (3) 자동스캔 결과 (JSON)
    scan_text = _load_text(scan_file, max_chars=max_chars // 2)
    if scan_text:
        parts.append(f"# 자동스캔 결과\n\n```json\n{scan_text}\n```")

    # (4) 소스 디렉터리 힌트
    parts.append(
        f"# 소스 경로\n\n분석 대상 소스코드 루트: `{source_dir}`\n"
        "필요 시 해당 경로에서 파일을 직접 읽어 교차검증하십시오."
    )

    return "\n\n---\n\n".join(parts)


@retry_with_backoff(max_attempts=5, base_delay=2.0, jitter_range=(0.5, 1.5))
def _call_claude(
    client: anthropic.Anthropic,
    model: str,
    prompt: str,
    max_tokens: int = 8192,
) -> anthropic.types.Message:
    return client.messages.create(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )


def run_worker(
    task_id:          str,
    state_dir:        Path,
    source_dir:       Path,
    model:            str,
    eco_mode:         bool,
    playbook_root:    Path,
    api_key:          str,
) -> WorkerResult:
    """
    단일 Phase 3 태스크를 실행하고 WorkerResult를 반환한다.

    - eco_mode=True 이면 compact_threshold를 50% 줄여 페이로드를 축소한다.
    - 실패 시 WorkerResult(success=False, error=...)를 반환한다.
    """
    compact_threshold = ECO_COMPACT_THRESHOLD if eco_mode else NORMAL_COMPACT_THRESHOLD
    log.info(
        "[Worker:%s] 시작 (eco=%s, compact_threshold=%d)",
        task_id, eco_mode, compact_threshold,
    )

    client = anthropic.Anthropic(api_key=api_key)

    try:
        prompt   = _build_prompt(task_id, state_dir, source_dir, compact_threshold, playbook_root)
        response = _call_claude(client, model, prompt)

        # 응답 텍스트 파싱
        raw_text = ""
        for block in response.content:
            if hasattr(block, "text"):
                raw_text += block.text

        # JSON 블록 추출 시도
        payload: dict[str, Any] = {"raw_text": raw_text, "task_id": task_id}
        json_start = raw_text.find("```json")
        json_end   = raw_text.rfind("```")
        if json_start != -1 and json_end > json_start + 7:
            try:
                payload = json.loads(raw_text[json_start + 7: json_end].strip())
            except json.JSONDecodeError:
                pass  # raw_text 폴백 유지

        metrics = UsageMetrics.from_response(task_id, response.usage, model, eco_mode)
        log.info(
            "[Worker:%s] 완료 — in=%d out=%d cache_r=%d cost=%.6f$",
            task_id, metrics.input_tokens, metrics.output_tokens,
            metrics.cache_read_input_tokens, metrics.cost_usd,
        )
        return WorkerResult(task_id=task_id, success=True, payload=payload, metrics=metrics)

    except Exception as exc:  # pylint: disable=broad-except
        log.error("[Worker:%s] 실패: %s", task_id, exc)
        return WorkerResult(
            task_id=task_id,
            success=False,
            error=str(exc),
            metrics=UsageMetrics(task_id=task_id, eco_mode_active=eco_mode),
        )


# ─────────────────────────────────────────────────────────────────────────────
# 5. 효율성 리포트 생성
# ─────────────────────────────────────────────────────────────────────────────

def generate_usage_summary(
    results:    list[WorkerResult],
    safeguard:  SessionSafeguard,
    output_path: Path,
) -> None:
    """state/<prefix>/usage_summary.json 생성."""
    total_in  = sum(r.metrics.input_tokens             for r in results)
    total_out = sum(r.metrics.output_tokens            for r in results)
    total_cr  = sum(r.metrics.cache_read_input_tokens  for r in results)
    total_cw  = sum(r.metrics.cache_creation_input_tokens for r in results)
    total_tokens = total_in + total_out + total_cr + total_cw

    cache_hit_rate = (
        round(total_cr / max(total_in + total_cr, 1) * 100, 2)
        if total_cr > 0 else 0.0
    )

    task_costs = [
        {
            "task_id":              r.task_id,
            "success":              r.success,
            "input_tokens":         r.metrics.input_tokens,
            "output_tokens":        r.metrics.output_tokens,
            "cache_read_tokens":    r.metrics.cache_read_input_tokens,
            "cache_write_tokens":   r.metrics.cache_creation_input_tokens,
            "cost_usd":             round(r.metrics.cost_usd, 6),
            "eco_mode_active":      r.metrics.eco_mode_active,
            "error":                r.error or None,
        }
        for r in results
    ]

    summary = {
        "generated_at":          datetime.now(timezone.utc).isoformat(),
        "tokens": {
            "total_input":         total_in,
            "total_output":        total_out,
            "total_cache_read":    total_cr,
            "total_cache_write":   total_cw,
            "total":               total_tokens,
            "cache_hit_rate_pct":  cache_hit_rate,
        },
        "cost": {
            "task_breakdown":      task_costs,
            "total_cost_usd":      round(sum(r.metrics.cost_usd for r in results), 6),
        },
        "safeguard": safeguard.status_snapshot(),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    log.info("[Report] usage_summary 저장: %s", output_path)

    # 콘솔 요약 출력
    snap = safeguard.status_snapshot()
    print("\n" + "=" * 60)
    print("  Phase 3 효율성 리포트")
    print("=" * 60)
    print(f"  총 토큰       : {total_tokens:,}")
    print(f"  캐시 적중률   : {cache_hit_rate:.1f}%")
    print(f"  총 비용       : ${snap['cumulative_cost_usd']:.6f}")
    print(f"  시간당 소모율 : ${snap['hourly_rate_usd_per_hr']:.4f}/hr")
    print(f"  에코 모드     : {'활성화됨' if snap['eco_mode_triggered'] else '해당없음'}")
    print(f"  세이프가드    : {'발동됨' if snap['safeguard_halted'] else '정상'}")
    print("=" * 60 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# 6. 코디네이터 메인 루프
# ─────────────────────────────────────────────────────────────────────────────

def run_coordinator(
    prefix:             str,
    source_dir:         Path,
    tasks:              list[str],
    model:              str,
    max_workers:        int,
    session_budget:     float,
    weekly_budget:      float,
    playbook_root:      Path,
    api_key:            str,
) -> list[WorkerResult]:
    """
    병렬 워커 풀을 관리하고 결과를 수집한다.

    as_completed 방식으로 결과를 처리하며:
      - 각 결과 수신 후 safeguard.record_cost() 호출
      - safeguard.halted == True 이면 대기 중인 Future를 즉시 취소
    """
    state_dir         = playbook_root / "state" / prefix
    weekly_usage_path = playbook_root / "state" / "weekly_usage.json"
    state_dir.mkdir(parents=True, exist_ok=True)

    safeguard = SessionSafeguard(
        max_session_budget=session_budget,
        weekly_budget=weekly_budget,
        weekly_usage_path=weekly_usage_path,
    )

    all_results: list[WorkerResult] = []
    # Future → task_id 역매핑 (취소 로그용)
    future_map: dict[Future, str] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # ── 워커 제출 ──────────────────────────────────────────────────────────
        for task_id in tasks:
            if safeguard.halted:
                log.warning("[Coordinator] 세이프가드 발동 — '%s' 워커 제출 취소.", task_id)
                all_results.append(WorkerResult(
                    task_id=task_id, success=False,
                    error="cancelled by safeguard before submission",
                ))
                continue

            # 에코 모드 여부는 제출 시점 기준 (이후 상태 변동 반영 안 됨 — 의도적)
            eco = safeguard.eco_mode
            future = executor.submit(
                run_worker,
                task_id=task_id,
                state_dir=state_dir,
                source_dir=source_dir,
                model=model,
                eco_mode=eco,
                playbook_root=playbook_root,
                api_key=api_key,
            )
            future_map[future] = task_id
            log.info(
                "[Coordinator] 워커 제출: %s (eco=%s, 총 %d개 대기)",
                task_id, eco, len(future_map),
            )

        # ── 결과 수집 ──────────────────────────────────────────────────────────
        for future in as_completed(future_map):
            task_id = future_map[future]
            try:
                result: WorkerResult = future.result()
            except Exception as exc:  # pylint: disable=broad-except
                result = WorkerResult(
                    task_id=task_id, success=False, error=str(exc),
                    metrics=UsageMetrics(task_id=task_id),
                )

            all_results.append(result)
            safeguard.record_cost(result.metrics.cost_usd)

            log.info(
                "[Coordinator] 수신: %s  success=%s  cost=%.6f$  누적=%.6f$",
                task_id, result.success,
                result.metrics.cost_usd,
                safeguard.status_snapshot()["cumulative_cost_usd"],
            )

            # 결과 파일 저장
            if result.success and result.payload:
                out_file = state_dir / TASK_OUTPUT_MAP.get(task_id, f"{task_id}_llm.json")
                out_file.write_text(
                    json.dumps(result.payload, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                log.info("[Coordinator] 결과 저장: %s", out_file)

            # 세이프가드 발동 시 나머지 Future 취소
            if safeguard.halted:
                cancelled = 0
                for pending_future, pending_id in future_map.items():
                    if not pending_future.done():
                        pending_future.cancel()
                        cancelled += 1
                        log.warning(
                            "[Coordinator] 세이프가드 — '%s' 워커 취소 요청.", pending_id,
                        )
                if cancelled:
                    log.error(
                        "[Coordinator] %d개 워커 취소 완료. 이후 결과는 수집하지 않습니다.", cancelled,
                    )
                break  # as_completed 루프 종료

    return all_results


# ─────────────────────────────────────────────────────────────────────────────
# 7. CLI 진입점
# ─────────────────────────────────────────────────────────────────────────────

def _load_env(playbook_root: Path) -> None:
    """playbook_root/.env 에서 환경변수를 로드한다."""
    env_path = playbook_root / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 3 LLM 병렬 워커 코디네이터 (비용 추적 + 세이프가드 + 에코 모드)"
    )
    parser.add_argument("--prefix",      required=True,  help="상태 디렉터리 prefix (예: 0331_comm_api)")
    parser.add_argument("--source-dir",  required=True,  type=Path, help="분석 대상 소스코드 루트")
    parser.add_argument(
        "--tasks", nargs="+",
        choices=list(TASK_OUTPUT_MAP.keys()),
        default=list(TASK_OUTPUT_MAP.keys()),
        help="실행할 Phase 3 태스크 목록 (기본: 전체)",
    )
    parser.add_argument("--model",          default="claude-sonnet-4-6", help="사용할 Claude 모델")
    parser.add_argument("--max-workers",    type=int,   default=3,    help="최대 병렬 워커 수")
    parser.add_argument("--session-budget", type=float, default=10.0, help="세션 예산 한도 (USD)")
    parser.add_argument("--weekly-budget",  type=float, default=50.0, help="주간 예산 한도 (USD)")
    parser.add_argument("--playbook-root",  type=Path,  default=None, help="플레이북 루트 경로 (기본: 스크립트 위치 기준)")
    args = parser.parse_args()

    # 플레이북 루트: tools/scripts/phase3_coordinator.py → 두 단계 상위
    playbook_root: Path = (
        args.playbook_root.resolve()
        if args.playbook_root
        else Path(__file__).resolve().parent.parent.parent
    )
    _load_env(playbook_root)

    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY", "")
    if not api_key:
        sys.exit(
            "[Error] ANTHROPIC_API_KEY 환경변수가 없습니다. "
            ".env에 ANTHROPIC_API_KEY=<key> 를 추가하거나 export 하십시오."
        )

    log.info(
        "[Coordinator] 시작 — prefix=%s  tasks=%s  model=%s  workers=%d",
        args.prefix, args.tasks, args.model, args.max_workers,
    )

    results = run_coordinator(
        prefix=args.prefix,
        source_dir=args.source_dir.resolve(),
        tasks=args.tasks,
        model=args.model,
        max_workers=args.max_workers,
        session_budget=args.session_budget,
        weekly_budget=args.weekly_budget,
        playbook_root=playbook_root,
        api_key=api_key,
    )

    # ── 사후 처리 ──────────────────────────────────────────────────────────────
    state_dir = playbook_root / "state" / args.prefix

    # 세이프가드 인스턴스를 재구성 없이 결과에서 직접 산출
    # (run_coordinator 내부 safeguard를 밖으로 꺼내기 위해 래핑 가능하나,
    #  간결성 유지를 위해 결과에서 재계산)
    weekly_usage_path = playbook_root / "state" / "weekly_usage.json"
    safeguard = SessionSafeguard(
        max_session_budget=args.session_budget,
        weekly_budget=args.weekly_budget,
        weekly_usage_path=weekly_usage_path,
    )
    for r in results:
        safeguard.record_cost(r.metrics.cost_usd)

    generate_usage_summary(
        results=results,
        safeguard=safeguard,
        output_path=state_dir / "usage_summary.json",
    )
    safeguard.persist_weekly()

    # 실패한 태스크 요약
    failed = [r for r in results if not r.success]
    if failed:
        log.warning(
            "[Coordinator] %d개 태스크 실패: %s",
            len(failed), [r.task_id for r in failed],
        )
        sys.exit(1)

    log.info("[Coordinator] 완료 — 전체 %d개 태스크 성공.", len(results))


if __name__ == "__main__":
    main()
