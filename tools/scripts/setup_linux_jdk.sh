#!/usr/bin/env bash
# =============================================================================
# setup_linux_jdk.sh — WSL2/Linux 환경 Linux 네이티브 JDK 자동 설치
#
# 특징
#   - sudo 불필요 (사용자 홈 ~/.local/share/jdk/ 에 설치)
#   - 다중 CDN fallback (Corretto → OpenJDK.net → Zulu)
#   - 이미 설치된 경우 재설치 없이 JAVA_HOME 설정만 수행
#   - ~/.bashrc 에 영구 JAVA_HOME 등록
#   - 인수 없이 실행 가능, --version JDK 버전 지정 가능
#
# 사용법
#   bash setup_linux_jdk.sh              # JDK 17 설치 (기본)
#   bash setup_linux_jdk.sh --version 21 # JDK 21 설치
#   bash setup_linux_jdk.sh --check-only # 설치 없이 JDK 경로 출력만
#   source setup_linux_jdk.sh            # 설치 후 현재 셸에 즉시 적용
# =============================================================================
set -euo pipefail

# ── 인수 파싱 ────────────────────────────────────────────────────────────────
JDK_VERSION="17"
CHECK_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) JDK_VERSION="$2"; shift 2 ;;
    --check-only) CHECK_ONLY=true; shift ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done

# ── 설치 경로 ────────────────────────────────────────────────────────────────
INSTALL_BASE="${HOME}/.local/share/jdk"
MARKER_FILE="${INSTALL_BASE}/.installed_jdk${JDK_VERSION}"

# ── 색상 출력 ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*" >&2; }

# ── 이미 설치된 JDK 탐색 ──────────────────────────────────────────────────
find_existing_java() {
  # 1) 마커 파일 (이전 설치)
  if [[ -f "$MARKER_FILE" ]]; then
    local java_path
    java_path=$(cat "$MARKER_FILE")
    if [[ -x "$java_path" ]]; then
      echo "$java_path"; return 0
    fi
  fi

  # 2) JAVA_HOME 환경변수
  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
    echo "${JAVA_HOME}/bin/java"; return 0
  fi

  # 3) 설치 디렉토리 탐색 (Linux 바이너리 — .exe 제외)
  if [[ -d "$INSTALL_BASE" ]]; then
    while IFS= read -r -d '' bin; do
      [[ "$bin" == *.exe ]] && continue
      if "$bin" -version &>/dev/null; then
        echo "$bin"; return 0
      fi
    done < <(find "$INSTALL_BASE" -name "java" -not -name "*.exe" -print0 2>/dev/null | sort -zr)
  fi

  # 4) 시스템 PATH
  if command -v java &>/dev/null; then
    java_path=$(command -v java)
    # Windows .exe 는 제외
    if [[ "$java_path" != *.exe ]]; then
      echo "$java_path"; return 0
    fi
  fi

  return 1
}

# ── JDK 버전 정보 (CDN별) ─────────────────────────────────────────────────
declare -A CORRETTO_URLS=(
  [17]="https://corretto.aws/downloads/latest/amazon-corretto-17-x64-linux-jdk.tar.gz"
  [21]="https://corretto.aws/downloads/latest/amazon-corretto-21-x64-linux-jdk.tar.gz"
  [11]="https://corretto.aws/downloads/latest/amazon-corretto-11-x64-linux-jdk.tar.gz"
)
declare -A OPENJDK_URLS=(
  [17]="https://download.java.net/java/GA/jdk17/0d483333a00540d886896bac774ff48b/35/GPL/openjdk-17_linux-x64_bin.tar.gz"
  [21]="https://download.java.net/java/GA/jdk21/fd2272bbf8e04c3dbaee13770090416c/35/GPL/openjdk-21_linux-x64_bin.tar.gz"
  [11]="https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-x64_bin.tar.gz"
)
declare -A ZULU_URLS=(
  [17]="https://cdn.azul.com/zulu/bin/zulu17.56.15-ca-jdk17.0.14-linux_x64.tar.gz"
  [21]="https://cdn.azul.com/zulu/bin/zulu21.42.19-ca-jdk21.0.7-linux_x64.tar.gz"
  [11]="https://cdn.azul.com/zulu/bin/zulu11.78.15-ca-jdk11.0.26-linux_x64.tar.gz"
)

# ── 다운로드 함수 (진행률 표시) ───────────────────────────────────────────
download_with_progress() {
  local url="$1"
  local dest="$2"
  local label="$3"

  info "$label 다운로드 중..."
  info "URL: $url"

  # curl 사용 (진행률 표시, redirect 따라가기)
  if curl -L --max-time 600 --retry 2 --retry-delay 3 \
       -# -o "$dest" "$url" 2>&1; then
    if [[ -f "$dest" && -s "$dest" ]]; then
      success "다운로드 완료: $(du -sh "$dest" | cut -f1)"
      return 0
    fi
  fi

  error "다운로드 실패: $label"
  rm -f "$dest"
  return 1
}

# ── 압축 해제 함수 ─────────────────────────────────────────────────────────
extract_jdk() {
  local tarball="$1"
  local dest_dir="$2"

  info "압축 해제 중 → $dest_dir"
  mkdir -p "$dest_dir"
  tar -xzf "$tarball" -C "$dest_dir" --strip-components=1 2>&1 | tail -1 || {
    # strip-components 실패 시 subdirectory 생성 방식 fallback
    tar -xzf "$tarball" -C "$dest_dir" 2>&1 | tail -1
    # 단일 서브디렉토리로 추출된 경우 파일 이동
    local sub
    sub=$(find "$dest_dir" -maxdepth 1 -mindepth 1 -type d | head -1)
    if [[ -n "$sub" && "$sub" != "$dest_dir" ]]; then
      mv "$sub"/* "$dest_dir"/ 2>/dev/null || true
      rmdir "$sub" 2>/dev/null || true
    fi
  }

  if [[ -x "$dest_dir/bin/java" ]]; then
    success "압축 해제 완료"
    return 0
  fi
  error "압축 해제 후 java 바이너리 없음: $dest_dir/bin/java"
  return 1
}

# ── JAVA_HOME 영구 등록 ───────────────────────────────────────────────────
persist_java_home() {
  local java_home="$1"
  local rc_file="${HOME}/.bashrc"

  # 기존 JAVA_HOME 설정 제거 후 재등록 (중복 방지)
  if grep -q "# setup_linux_jdk" "$rc_file" 2>/dev/null; then
    sed -i '/# setup_linux_jdk/,/# end setup_linux_jdk/d' "$rc_file"
  fi

  cat >> "$rc_file" << EOF

# setup_linux_jdk — auto-configured $(date +%Y-%m-%d)
export JAVA_HOME="${java_home}"
export PATH="\${JAVA_HOME}/bin:\${PATH}"
# end setup_linux_jdk
EOF

  success "~/.bashrc 에 JAVA_HOME=${java_home} 등록 완료"
  info "새 터미널에서는 자동 적용됩니다. 현재 셸 적용: source ~/.bashrc"
}

# ─────────────────────────────────────────────────────────────────────────────
# 메인 로직
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  Linux JDK ${JDK_VERSION} 설치 (WSL2 네이티브)"
echo "========================================================"

# ── Step 1: 기존 JDK 확인 ────────────────────────────────────────────────
if java_bin=$(find_existing_java 2>/dev/null); then
  java_home=$(dirname "$(dirname "$java_bin")")
  version_str=$("$java_bin" -version 2>&1 | head -1)
  success "기존 Linux JDK 발견: $java_bin"
  info    "버전: $version_str"

  if [[ "$CHECK_ONLY" == true ]]; then
    echo ""
    echo "JAVA_HOME=$java_home"
    echo "JAVA_BIN=$java_bin"
    exit 0
  fi

  # 현재 셸에 적용
  export JAVA_HOME="$java_home"
  export PATH="${JAVA_HOME}/bin:${PATH}"
  success "JAVA_HOME=${JAVA_HOME} (현재 셸 적용 완료)"
  persist_java_home "$JAVA_HOME"
  exit 0
fi

if [[ "$CHECK_ONLY" == true ]]; then
  warn "Linux JDK ${JDK_VERSION} 없음"
  echo "설치 명령: bash $(basename "$0") --version ${JDK_VERSION}"
  exit 1
fi

# ── Step 2: CDN 순서대로 다운로드 시도 ───────────────────────────────────
info "Linux 네이티브 JDK ${JDK_VERSION}을 다운로드합니다."
info "설치 경로: ${INSTALL_BASE}/jdk-${JDK_VERSION}/"
mkdir -p "$INSTALL_BASE"
TARBALL="${INSTALL_BASE}/jdk${JDK_VERSION}.tar.gz"
DEST_DIR="${INSTALL_BASE}/jdk-${JDK_VERSION}"

# CDN 우선순위: Corretto(AWS S3) > OpenJDK.net(Akamai) > Zulu(Azul CDN)
DOWNLOAD_SUCCESS=false
for cdn_name in "Corretto" "OpenJDK.net" "Zulu"; do
  case "$cdn_name" in
    "Corretto")  url="${CORRETTO_URLS[$JDK_VERSION]:-}" ;;
    "OpenJDK.net") url="${OPENJDK_URLS[$JDK_VERSION]:-}" ;;
    "Zulu")      url="${ZULU_URLS[$JDK_VERSION]:-}" ;;
  esac

  [[ -z "$url" ]] && { warn "JDK ${JDK_VERSION}: ${cdn_name} URL 없음 — 스킵"; continue; }

  info "[$cdn_name] 접근 가능 여부 확인..."
  http_code=$(curl -sI --max-time 8 -L -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
  if [[ "$http_code" != "200" && "$http_code" != "302" ]]; then
    warn "[$cdn_name] HTTP $http_code — 스킵"
    continue
  fi
  success "[$cdn_name] 접근 가능 (HTTP $http_code)"

  # 다운로드 시도
  if download_with_progress "$url" "$TARBALL" "$cdn_name JDK ${JDK_VERSION}"; then
    DOWNLOAD_SUCCESS=true
    break
  fi
  warn "[$cdn_name] 다운로드 실패 — 다음 CDN 시도"
done

if [[ "$DOWNLOAD_SUCCESS" != true ]]; then
  error "모든 CDN에서 다운로드 실패."
  echo ""
  echo "수동 설치 방법:"
  echo "  1) sudo apt-get install -y openjdk-${JDK_VERSION}-jdk"
  echo "  2) 또는 https://adoptium.net 에서 수동 다운로드 후"
  echo "     tar -xzf jdk.tar.gz -C ${INSTALL_BASE}/jdk-${JDK_VERSION}/ --strip-components=1"
  exit 1
fi

# ── Step 3: 압축 해제 ────────────────────────────────────────────────────
mkdir -p "$DEST_DIR"
if ! extract_jdk "$TARBALL" "$DEST_DIR"; then
  error "압축 해제 실패"
  exit 1
fi
rm -f "$TARBALL"

# ── Step 4: 검증 ─────────────────────────────────────────────────────────
JAVA_BIN="${DEST_DIR}/bin/java"
if [[ ! -x "$JAVA_BIN" ]]; then
  error "java 바이너리 없음: $JAVA_BIN"
  exit 1
fi

VERSION_OUT=$("$JAVA_BIN" -version 2>&1 | head -1)
success "설치 완료: $VERSION_OUT"
success "경로: $JAVA_BIN"

# ── Step 5: 마커 파일 + 영구 등록 ───────────────────────────────────────
echo "$JAVA_BIN" > "$MARKER_FILE"
export JAVA_HOME="$DEST_DIR"
export PATH="${JAVA_HOME}/bin:${PATH}"
persist_java_home "$JAVA_HOME"

echo ""
echo "========================================================"
success "JDK ${JDK_VERSION} 설치 완료"
echo ""
echo "  현재 셸 적용:  source ~/.bashrc  또는  export JAVA_HOME=${DEST_DIR}"
echo "  다음 실행 시:  자동 적용 (~/.bashrc)"
echo "========================================================"
echo ""
