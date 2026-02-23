#!/usr/bin/env python3
"""
DTO/타입 카탈로그 자동 추출 스크립트

소스코드에서 Java/Kotlin 클래스 정의를 파싱하여
DTO, Entity, 데이터 클래스의 필드 구조를 추출합니다.

사용법:
    python scan_dto.py <source_dir> [--output <file>]
    python scan_dto.py testbed/4-ocb-community-api-dev@d4d8affd8a1/
    python scan_dto.py testbed/4-ocb-community-api-dev@d4d8affd8a1/ -o state/dto_catalog.json

출력 필드:
    - class_name: 클래스 단순명
    - qualified_name: 정규화 이름 (OuterClass.InnerClass)
    - package: 패키지명
    - kind: class, data_class, enum, interface
    - fields: 필드 목록 (name, data_type, annotations, nullable)
    - parent_class: 부모 클래스
    - annotations: 클래스 레벨 어노테이션
    - nested_in: 포함 클래스명
    - file_path: 소스 파일 상대 경로
    - line: 선언 라인
    - language: java / kotlin
"""

import json
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ============================================================
#  데이터 모델
# ============================================================

@dataclass
class FieldInfo:
    name: str
    data_type: str
    annotations: list = field(default_factory=list)
    nullable: bool = False


@dataclass
class TypeInfo:
    class_name: str          # "LoginRequest"
    qualified_name: str      # "AuthDTO.LoginRequest"
    package: str             # "com.skp.ocb.api.dto"
    kind: str                # "class", "data_class", "enum", "interface"
    fields: list = field(default_factory=list)           # list[FieldInfo]
    parent_class: str = ""
    interfaces: list = field(default_factory=list)
    annotations: list = field(default_factory=list)      # class-level
    nested_in: str = ""
    file_path: str = ""
    line: int = 0
    language: str = ""       # "java" / "kotlin"


# ============================================================
#  Java 타입 패턴
# ============================================================

# Java 제네릭 타입: String, List<User>, ResponseEntity<List<User>>, byte[]
_JTYPE = r'[\w.]+(?:<[\w<>,.?\s\[\]]+>)?(?:\[\])*'

# Java 필드: [annotations] [modifiers] Type fieldName [= ...];
JAVA_FIELD_PATTERN = re.compile(
    r'^(\s*(?:@\w+(?:\([^)]*\))?\s*)*)'  # 어노테이션
    r'(?:private|protected|public)\s+'     # 접근 제어자
    r'(?:static\s+)?(?:final\s+)?'         # 기타 제어자
    r'(?:volatile\s+)?(?:transient\s+)?'
    rf'({_JTYPE})'                          # 타입
    r'\s+(\w+)\s*'                          # 필드명
    r'(?:=|;)',                              # 초기화 또는 세미콜론
    re.MULTILINE
)

# serialVersionUID 등 상수 제외 패턴
SKIP_FIELD_NAMES = {'serialVersionUID', 'log', 'logger'}


def extract_java_field_annotations(anno_text: str) -> list[str]:
    """필드 어노테이션 목록 추출"""
    annos = re.findall(r'@(\w+(?:\([^)]*\))?)', anno_text)
    return [f"@{a}" for a in annos] if annos else []


def scan_java_file(filepath: Path, source_dir: Path) -> list[TypeInfo]:
    """Java 파일에서 클래스/인터페이스/enum 정의와 필드를 추출"""
    types = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
    except (IOError, UnicodeDecodeError):
        return types

    rel_path = str(filepath.relative_to(source_dir))

    # 패키지 추출
    pkg_match = re.search(r'^package\s+([\w.]+)\s*;', content, re.MULTILINE)
    package = pkg_match.group(1) if pkg_match else ""

    # 클래스 선언 탐색 (중첩 클래스 포함)
    # brace depth 추적으로 중첩 관계 파악
    class_stack = []  # [(class_name, brace_depth, TypeInfo)]
    brace_depth = 0
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # 빈 줄, import, package 스킵
        if not stripped or stripped.startswith('import ') or stripped.startswith('package '):
            i += 1
            continue

        # 클래스/인터페이스/enum 선언 감지
        # 어노테이션 블록 수집 (현재 줄 포함, 이전 줄들도)
        class_match = re.search(
            r'(?:(?:public|protected|private)\s+)?'
            r'(?:static\s+)?(?:abstract\s+)?(?:final\s+)?'
            r'(class|interface|enum)\s+(\w+)'
            r'(?:\s+extends\s+([\w.]+))?'
            r'(?:\s+implements\s+([\w.,\s]+))?',
            stripped
        )

        if class_match:
            kind_raw = class_match.group(1)
            class_name = class_match.group(2)
            parent = class_match.group(3) or ""
            impl_raw = class_match.group(4) or ""
            interfaces = [x.strip() for x in impl_raw.split(',') if x.strip()]

            # 클래스 레벨 어노테이션 수집 (현재 줄 위 연속 어노테이션)
            class_annos = []
            j = i - 1
            while j >= 0:
                prev = lines[j].strip()
                if prev.startswith('@'):
                    anno_name = re.match(r'@(\w+(?:\([^)]*\))?)', prev)
                    if anno_name:
                        class_annos.insert(0, f"@{anno_name.group(1)}")
                    j -= 1
                elif not prev:
                    j -= 1
                else:
                    break

            # kind 결정
            kind = kind_raw
            if kind == 'class':
                if any('@Data' in a for a in class_annos):
                    kind = 'data_class'  # Lombok @Data
                elif any('@Entity' in a for a in class_annos):
                    kind = 'entity'

            # qualified name 계산
            nested_in = ""
            if class_stack:
                nested_in = class_stack[-1][2].qualified_name
                qualified = f"{nested_in}.{class_name}"
            else:
                qualified = class_name

            line_num = i + 1
            type_info = TypeInfo(
                class_name=class_name,
                qualified_name=qualified,
                package=package,
                kind=kind,
                parent_class=parent,
                interfaces=interfaces,
                annotations=class_annos,
                nested_in=nested_in,
                file_path=rel_path,
                line=line_num,
                language="java",
            )

            # brace depth 기록
            open_count = stripped.count('{')
            close_count = stripped.count('}')
            brace_depth += open_count - close_count

            class_stack.append((class_name, brace_depth, type_info))
            types.append(type_info)
            i += 1
            continue

        # 필드 감지 (현재 클래스 스택이 비어있지 않을 때)
        if class_stack:
            current_type = class_stack[-1][2]

            # Java 필드 패턴: private Type name;  또는  private Type name = ...;
            field_match = re.search(
                r'((?:@\w+(?:\([^)]*\))?\s*)*)'
                r'(?:private|protected|public)\s+'
                r'(?:static\s+final\s+|static\s+|final\s+|volatile\s+|transient\s+)*'
                rf'({_JTYPE})\s+(\w+)\s*(?:=|;)',
                stripped
            )
            if field_match and 'static final' not in stripped:
                anno_text = field_match.group(1)
                data_type = field_match.group(2)
                field_name = field_match.group(3)

                if field_name not in SKIP_FIELD_NAMES:
                    annos = extract_java_field_annotations(anno_text)
                    current_type.fields.append(asdict(FieldInfo(
                        name=field_name,
                        data_type=data_type,
                        annotations=annos,
                        nullable=False,
                    )))

        # brace depth 추적
        open_count = stripped.count('{')
        close_count = stripped.count('}')
        if not class_match:  # class_match는 이미 위에서 처리
            brace_depth += open_count - close_count

        # 클래스 스택 정리 (brace depth가 클래스 진입 시보다 낮아지면 pop)
        while class_stack and brace_depth < class_stack[-1][1]:
            class_stack.pop()

        i += 1

    return types


# ============================================================
#  Kotlin 파싱
# ============================================================

def scan_kotlin_file(filepath: Path, source_dir: Path) -> list[TypeInfo]:
    """Kotlin 파일에서 class/data class/enum/interface 정의와 필드를 추출"""
    types = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
    except (IOError, UnicodeDecodeError):
        return types

    rel_path = str(filepath.relative_to(source_dir))

    # 패키지 추출
    pkg_match = re.search(r'^package\s+([\w.]+)', content, re.MULTILINE)
    package = pkg_match.group(1) if pkg_match else ""

    class_stack = []  # [(class_name, brace_depth, TypeInfo)]
    brace_depth = 0
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped or stripped.startswith('import ') or stripped.startswith('package '):
            i += 1
            continue

        # Kotlin class 선언 감지
        # data class Foo(val x: String, var y: Int) : Base(), Interface
        # class Foo : Base() { ... }
        # open class Foo { ... }
        # enum class Foo { ... }
        class_match = re.search(
            r'(?:(?:open|abstract|sealed|inner|private|internal|public)\s+)*'
            r'(data\s+class|class|interface|enum\s+class|object)\s+(\w+)'
            r'(?:\s*<[^>]*>)?'  # 제네릭 파라미터
            r'(?:\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)?)?'  # primary constructor
            r'(?:\s*:\s*([\w.,\s<>()]+?))?'  # 상속/구현
            r'\s*(?:\{|$)',
            stripped
        )

        if class_match:
            kind_raw = class_match.group(1).strip()
            class_name = class_match.group(2)
            constructor_params = class_match.group(3) or ""
            inheritance_raw = class_match.group(4) or ""

            # kind 결정
            if 'data' in kind_raw:
                kind = 'data_class'
            elif 'enum' in kind_raw:
                kind = 'enum'
            elif kind_raw == 'interface':
                kind = 'interface'
            elif kind_raw == 'object':
                kind = 'object'
            else:
                kind = 'class'

            # 상속 파싱
            parent_class = ""
            interfaces = []
            if inheritance_raw:
                parts = [p.strip() for p in inheritance_raw.split(',')]
                for p in parts:
                    # 괄호가 있으면 클래스 (생성자 호출), 없으면 인터페이스
                    name = re.match(r'([\w.]+)', p)
                    if name:
                        if '(' in p:
                            parent_class = name.group(1)
                        else:
                            interfaces.append(name.group(1))

            # 클래스 레벨 어노테이션
            class_annos = []
            j = i - 1
            while j >= 0:
                prev = lines[j].strip()
                if prev.startswith('@'):
                    anno_name = re.match(r'@(\w+(?:\([^)]*\))?)', prev)
                    if anno_name:
                        class_annos.insert(0, f"@{anno_name.group(1)}")
                    j -= 1
                elif not prev:
                    j -= 1
                else:
                    break

            # qualified name
            nested_in = ""
            if class_stack:
                nested_in = class_stack[-1][2].qualified_name
                qualified = f"{nested_in}.{class_name}"
            else:
                qualified = class_name

            line_num = i + 1
            type_info = TypeInfo(
                class_name=class_name,
                qualified_name=qualified,
                package=package,
                kind=kind,
                parent_class=parent_class,
                interfaces=interfaces,
                annotations=class_annos,
                nested_in=nested_in,
                file_path=rel_path,
                line=line_num,
                language="kotlin",
            )

            # data class: primary constructor 파라미터에서 필드 추출
            if constructor_params and kind == 'data_class':
                params_text = constructor_params
                # 여러 줄에 걸쳐 있을 수 있음 - 괄호가 닫히지 않았으면 다음 줄 합치기
                if params_text.count('(') > params_text.count(')'):
                    while i + 1 < len(lines):
                        i += 1
                        params_text += ' ' + lines[i].strip()
                        if ')' in lines[i]:
                            break

                for param in split_kotlin_params(params_text):
                    fi = parse_kotlin_field(param)
                    if fi:
                        type_info.fields.append(asdict(fi))

            # brace depth 추적
            open_count = stripped.count('{')
            close_count = stripped.count('}')
            brace_depth += open_count - close_count

            class_stack.append((class_name, brace_depth, type_info))
            types.append(type_info)
            i += 1
            continue

        # 클래스 본문 내 val/var 프로퍼티 (data class가 아닌 일반 class)
        if class_stack:
            current_type = class_stack[-1][2]
            if current_type.kind != 'data_class':  # data class는 constructor에서 추출
                prop_match = re.search(
                    r'((?:@\w+(?:\([^)]*\))?\s*)*)'  # 어노테이션
                    r'(?:(?:open|override|private|protected|internal|public|lateinit)\s+)*'
                    r'(val|var)\s+(\w+)\s*:\s*([\w.]+(?:<[\w<>,.?\s\[\]]+>)?(?:\?)?)',
                    stripped
                )
                if prop_match:
                    anno_text = prop_match.group(1)
                    field_name = prop_match.group(3)
                    data_type = prop_match.group(4)
                    if field_name not in SKIP_FIELD_NAMES:
                        annos = extract_java_field_annotations(anno_text)
                        nullable = data_type.endswith('?')
                        current_type.fields.append(asdict(FieldInfo(
                            name=field_name,
                            data_type=data_type,
                            annotations=annos,
                            nullable=nullable,
                        )))

        # brace depth 추적
        if not class_match:
            open_count = stripped.count('{')
            close_count = stripped.count('}')
            brace_depth += open_count - close_count

        while class_stack and brace_depth < class_stack[-1][1]:
            class_stack.pop()

        i += 1

    return types


def split_kotlin_params(params_text: str) -> list[str]:
    """Kotlin primary constructor 파라미터 분리 (중첩 괄호/제네릭 고려)"""
    params = []
    depth = 0
    angle = 0
    current = []

    for char in params_text:
        if char in '([':
            depth += 1
            current.append(char)
        elif char in ')]':
            depth -= 1
            current.append(char)
        elif char == '<':
            angle += 1
            current.append(char)
        elif char == '>':
            angle -= 1
            current.append(char)
        elif char == ',' and depth == 0 and angle == 0:
            params.append(''.join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        last = ''.join(current).strip()
        if last:
            params.append(last)

    return params


def parse_kotlin_field(param_text: str) -> Optional[FieldInfo]:
    """Kotlin constructor 파라미터에서 FieldInfo 추출
    예: 'val name: String = ""'
    예: '@NotEmpty var eventType: String? = null'
    """
    param_text = param_text.strip()
    if not param_text:
        return None

    # 어노테이션 추출
    annos = []
    for m in re.finditer(r'@(\w+(?:\([^)]*\))?)', param_text):
        annos.append(f"@{m.group(1)}")

    # val/var fieldName: Type [= default]
    match = re.search(
        r'(?:val|var)\s+(\w+)\s*:\s*([\w.]+(?:<[\w<>,.?\s\[\]]+>)?(?:\?)?)',
        param_text
    )
    if match:
        name = match.group(1)
        data_type = match.group(2)
        nullable = data_type.endswith('?')
        return FieldInfo(
            name=name,
            data_type=data_type,
            annotations=annos,
            nullable=nullable,
        )

    # var 없이 타입만: fieldName: Type (일부 패턴)
    match2 = re.search(r'(\w+)\s*:\s*([\w.]+(?:<[\w<>,.?\s\[\]]+>)?(?:\?))', param_text)
    if match2:
        return FieldInfo(
            name=match2.group(1),
            data_type=match2.group(2),
            annotations=annos,
            nullable=match2.group(2).endswith('?'),
        )

    return None


# ============================================================
#  상속 해석
# ============================================================

def resolve_inheritance(types: dict[str, dict]) -> None:
    """부모 클래스의 필드를 자식에 병합 (inherited 마킹)"""
    # 이름 → qualified_name 역색인
    name_index: dict[str, list[str]] = {}
    for qname, info in types.items():
        simple = info['class_name']
        name_index.setdefault(simple, []).append(qname)
        name_index.setdefault(qname, []).append(qname)

    resolved = set()

    def resolve(qname: str):
        if qname in resolved:
            return
        resolved.add(qname)

        info = types.get(qname)
        if not info or not info.get('parent_class'):
            return

        parent_name = info['parent_class']
        # 부모 찾기: qualified name 우선, 없으면 simple name
        parent_candidates = name_index.get(parent_name, [])

        # 같은 파일 내 nested class 우선
        if not parent_candidates and info.get('nested_in'):
            combined = f"{info['nested_in']}.{parent_name}"
            parent_candidates = name_index.get(combined, [])

        if not parent_candidates:
            return

        parent_qname = parent_candidates[0]
        resolve(parent_qname)  # 부모도 먼저 해석

        parent_info = types.get(parent_qname)
        if not parent_info:
            return

        # 자식에 없는 부모 필드만 추가 (inherited 마킹)
        existing_names = {f['name'] for f in info.get('fields', [])}
        for pf in parent_info.get('fields', []):
            if pf['name'] not in existing_names:
                inherited_field = dict(pf)
                inherited_field['inherited'] = True
                inherited_field['inherited_from'] = parent_qname
                info['fields'].append(inherited_field)

    for qname in types:
        resolve(qname)


# ============================================================
#  디렉토리 스캔
# ============================================================

EXCLUDE_DIRS = {"node_modules", ".idea", "target", "build", ".git", "test",
                "tests", "__pycache__", ".gradle"}


def scan_directory(source_dir: Path) -> dict:
    """디렉토리 전체를 스캔하여 DTO/타입 카탈로그 생성"""

    all_types: list[TypeInfo] = []
    scanned = 0

    # Java 파일
    for f in source_dir.rglob("*.java"):
        if any(ex in f.parts for ex in EXCLUDE_DIRS):
            continue
        scanned += 1
        all_types.extend(scan_java_file(f, source_dir))

    # Kotlin 파일
    for f in source_dir.rglob("*.kt"):
        if any(ex in f.parts for ex in EXCLUDE_DIRS):
            continue
        scanned += 1
        all_types.extend(scan_kotlin_file(f, source_dir))

    # qualified_name → TypeInfo dict
    types_dict = {}
    for t in all_types:
        types_dict[t.qualified_name] = asdict(t)

    # 상속 해석
    resolve_inheritance(types_dict)

    # 역색인: simple name / qualified name → [qualified_name]
    type_index: dict[str, list[str]] = {}
    for qname, info in types_dict.items():
        simple = info['class_name']
        type_index.setdefault(simple, []).append(qname)
        type_index.setdefault(qname, []).append(qname)

    # 통계
    kind_stats = {}
    for info in types_dict.values():
        k = info['kind']
        kind_stats[k] = kind_stats.get(k, 0) + 1

    return {
        "source_dir": str(source_dir),
        "total_files_scanned": scanned,
        "total_types": len(types_dict),
        "kind_stats": kind_stats,
        "types": types_dict,
        "type_index": type_index,
    }


# ============================================================
#  메인
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="DTO/타입 카탈로그 자동 추출 (Java/Kotlin 클래스)"
    )
    parser.add_argument(
        "source_dir",
        help="스캔 대상 소스코드 디렉토리",
    )
    parser.add_argument(
        "--output", "-o",
        help="결과 출력 JSON 파일 경로",
        default=None,
    )
    parser.add_argument(
        "--quiet", "-q",
        help="요약만 출력",
        action="store_true",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"Error: 디렉토리를 찾을 수 없습니다: {source_dir}")
        sys.exit(1)

    print(f"스캔 대상: {source_dir}")
    result = scan_directory(source_dir)

    # 요약 출력
    print(f"\n스캔 완료: {result['total_files_scanned']}개 파일, "
          f"{result['total_types']}개 타입")

    print(f"\n타입 종류별:")
    for kind, count in sorted(result["kind_stats"].items()):
        print(f"  {kind}: {count}개")

    if not args.quiet:
        # 필드가 있는 타입 상위 20개
        types_with_fields = [
            (qn, info) for qn, info in result["types"].items()
            if info.get("fields")
        ]
        types_with_fields.sort(key=lambda x: len(x[1]["fields"]), reverse=True)

        print(f"\n필드 보유 타입 (상위 20개):")
        for qn, info in types_with_fields[:20]:
            field_count = len(info["fields"])
            inherited = sum(1 for f in info["fields"] if f.get("inherited"))
            inh_str = f" (+{inherited} inherited)" if inherited else ""
            parent = f" extends {info['parent_class']}" if info['parent_class'] else ""
            print(f"  {qn}{parent}: {field_count}개 필드{inh_str}")

    # 파일 출력
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n결과 저장: {output_path}")
    elif not args.quiet:
        print("\n(--output 옵션으로 JSON 파일 저장 가능)")


if __name__ == "__main__":
    main()
