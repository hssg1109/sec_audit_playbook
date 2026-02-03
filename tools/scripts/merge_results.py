#!/usr/bin/env python3
"""
작업 결과 병합 스크립트
state/ 폴더의 모든 작업 결과를 통합하여 최종 보고서를 생성합니다.

사용법:
    python merge_results.py [--state-dir <dir>] [--output <file>] [--glob <pattern>]
    python merge_results.py
    python merge_results.py --state-dir state/ --output state/final_report.json
    python merge_results.py --glob "pcona_task_*_result.json" --output state/pcona_final_report.json
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone


def load_results(state_dir: Path, glob_pattern: str = "task_*_result.json") -> list[dict]:
    """state 폴더에서 결과 파일을 로드합니다.

    Args:
        state_dir: state 폴더 경로
        glob_pattern: 파일 매칭 glob 패턴 (기본: task_*_result.json)
    """
    results = []
    for json_file in sorted(state_dir.glob(glob_pattern)):
        try:
            with open(json_file, encoding="utf-8") as f:
                data = json.load(f)
                data["_source_file"] = str(json_file.name)
                results.append(data)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: {json_file} 로드 실패: {e}")
    return results


def calculate_summary(results: list[dict]) -> dict:
    """전체 결과의 요약 통계를 계산합니다."""
    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }
    total_findings = 0
    tasks_completed = 0
    tasks_failed = 0

    for result in results:
        status = result.get("status", "")
        if status == "completed":
            tasks_completed += 1
        elif status == "failed":
            tasks_failed += 1

        findings = result.get("findings", [])
        for finding in findings:
            severity = finding.get("severity")
            if severity in severity_count:
                severity_count[severity] += 1
                total_findings += 1

    return {
        "total_tasks": len(results),
        "tasks_completed": tasks_completed,
        "tasks_failed": tasks_failed,
        "total_findings": total_findings,
        "severity_distribution": severity_count,
        "risk_score": (
            severity_count["Critical"] * 10
            + severity_count["High"] * 7
            + severity_count["Medium"] * 4
            + severity_count["Low"] * 1
        ),
    }


def merge_findings(results: list[dict]) -> list[dict]:
    """모든 결과에서 findings를 추출하고 심각도 순으로 정렬합니다."""
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    all_findings = []

    for result in results:
        task_id = result.get("task_id", "unknown")
        for finding in result.get("findings", []):
            finding["source_task"] = task_id
            all_findings.append(finding)

    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "Info"), 5))
    return all_findings


def generate_report(results: list[dict]) -> dict:
    """최종 보고서를 생성합니다."""
    summary = calculate_summary(results)
    merged_findings = merge_findings(results)

    report = {
        "report_type": "AI Security Audit Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": {
            "total_vulnerabilities": summary["total_findings"],
            "risk_score": summary["risk_score"],
            "critical_count": summary["severity_distribution"]["Critical"],
            "high_count": summary["severity_distribution"]["High"],
            "recommendation": "",
        },
        "summary": summary,
        "findings": merged_findings,
        "task_results": [
            {
                "task_id": r.get("task_id"),
                "status": r.get("status"),
                "findings_count": len(r.get("findings", [])),
                "source_file": r.get("_source_file"),
            }
            for r in results
        ],
    }

    # 경영진 권고문 생성
    critical = summary["severity_distribution"]["Critical"]
    high = summary["severity_distribution"]["High"]
    if critical > 0:
        report["executive_summary"]["recommendation"] = (
            f"즉시 조치 필요: Critical 취약점 {critical}건이 발견되었습니다. "
            "해당 취약점은 시스템 전체 보안에 심각한 위협이 될 수 있으므로 "
            "즉각적인 패치 및 보안 강화가 필요합니다."
        )
    elif high > 0:
        report["executive_summary"]["recommendation"] = (
            f"조속한 조치 권고: High 취약점 {high}건이 발견되었습니다. "
            "단기 내 조치 계획을 수립하시기 바랍니다."
        )
    else:
        report["executive_summary"]["recommendation"] = (
            "전반적으로 양호한 보안 수준입니다. "
            "발견된 중/저 위험 항목에 대한 개선을 권고합니다."
        )

    return report


def main():
    parser = argparse.ArgumentParser(description="작업 결과 병합 및 최종 보고서 생성")
    parser.add_argument(
        "--state-dir", "-d",
        help="state 폴더 경로",
        default="state/",
    )
    parser.add_argument(
        "--output", "-o",
        help="출력 파일 경로",
        default="state/final_report.json",
    )
    parser.add_argument(
        "--glob", "-g",
        help="파일 매칭 glob 패턴 (예: pcona_task_*_result.json)",
        default="task_*_result.json",
    )
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    if not state_dir.exists():
        print(f"Error: state 폴더를 찾을 수 없습니다: {state_dir}")
        sys.exit(1)

    # 결과 로드
    results = load_results(state_dir, args.glob)
    if not results:
        print("Warning: 병합할 결과 파일이 없습니다.")
        sys.exit(0)

    print(f"로드된 결과 파일: {len(results)}건")

    # 보고서 생성
    report = generate_report(results)

    # 저장
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"최종 보고서 생성 완료: {output_path}")
    print(f"\n요약:")
    print(f"  - 전체 작업: {report['summary']['total_tasks']}건")
    print(f"  - 발견 취약점: {report['summary']['total_findings']}건")
    print(f"  - 위험 점수: {report['summary']['risk_score']}")
    print(f"  - 심각도 분포: {report['summary']['severity_distribution']}")


if __name__ == "__main__":
    main()
