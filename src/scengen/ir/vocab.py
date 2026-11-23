"""IR 어휘 사전: 보안 설정 키 (스펙 5.7).

규칙은 이 키들만 읽는다. 새 키가 필요하면 여기와 스펙 표를 함께 추가하고,
완화책 대조표(mitigation_map.yaml)에서 어떤 완화책을 표현하는지 연결한다.

applies_to: 이 키를 붙일 수 있는 곳.
  자산 타입(host, service, identity, data_store, network_device, business_service),
  "group"(그룹), "context"(context.defaults = 조직 전체 기본값).
사전에 없는 키, 맞지 않는 곳에 붙인 키는 검증 경고.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ConfigKey:
    kind: str                         # "bool" | "enum" | "set"
    values: tuple[str, ...] = ()      # enum/set 허용값
    applies_to: tuple[str, ...] = ()
    description: str = ""

    def check(self, value: Any) -> str | None:
        """값이 형식에 맞지 않으면 오류 메시지를 돌려준다. None 값(모름)은 허용."""
        if value is None:
            return None
        if self.kind == "bool":
            return None if isinstance(value, bool) else "true/false 여야 함"
        if self.kind == "enum":
            if isinstance(value, bool):
                return (f"허용값: {list(self.values)} (YAML은 따옴표 없는 on/off/yes/no를 "
                        "참/거짓으로 읽습니다. 허용값을 쓰거나 따옴표로 감싸세요)")
            return None if value in self.values else f"허용값: {list(self.values)}"
        if self.kind == "set":
            if not isinstance(value, list):
                return "목록이어야 함"
            bad = [v for v in value if v not in self.values]
            return f"허용되지 않는 값 {bad} (허용: {list(self.values)})" if bad else None
        return None


LEVELS = ("none", "optional", "required")
HOST_SCOPE = ("host", "group", "context")
NET_SCOPE = ("group", "network_device", "context")


def _b(applies: tuple[str, ...], desc: str) -> ConfigKey:
    return ConfigKey("bool", (), applies, desc)


def _e(values: tuple[str, ...], applies: tuple[str, ...], desc: str) -> ConfigKey:
    return ConfigKey("enum", values, applies, desc)


CONFIG_KEYS: dict[str, ConfigKey] = {
    # ---- 인증
    "auth.methods": ConfigKey(
        "set", ("password", "key", "certificate", "kerberos", "ntlm", "oauth", "saml", "biometric", "none"),
        ("service", "host", "network_device", "group", "context"), "허용되는 인증 방식"),
    "auth.mfa": _b(("service", "identity", "network_device", "group", "context"), "다중 인증 강제"),
    "auth.default_credentials": _b(("service", "network_device"), "제조사 기본 계정 사용 중"),
    "auth.password_policy": _e(("none", "weak", "standard", "strong"),
                               ("identity", "service", "group", "context"), "비밀번호 정책 강도"),
    "auth.lockout": _b(("identity", "service", "host", "group", "context"), "반복 실패 시 계정·단말 잠금"),
    "auth.mfa_strength": _e(("otp", "push", "phishing_resistant"),
                            ("identity", "service", "group", "context"),
                            "다중 인증 방식의 강도 (일회용 코드 / 푸시 승인 / 피싱 방지형)"),
    "auth.token_binding": _b(("service", "context"), "토큰을 발급받은 기기·연결에 묶음 (탈취 토큰 재사용 방지)"),
    "auth.credential_rotation": _e(("none", "periodic", "automatic"),
                                   ("identity", "credential", "service", "group", "context"), "자격증명 주기적 교체"),
    # ---- 계정
    "account.enabled": _b(("identity",), "계정 활성 상태 (false = 비활성화됨)"),
    "account.dormant": _b(("identity", "credential"), "장기간 사용되지 않은 계정·자격증명"),
    "account.password_empty": _b(("identity",), "비밀번호가 비어 있는 계정"),
    "account.service_principal": _b(("identity",), "서비스 주체 이름(SPN)이 등록된 계정"),
    "account.kerberos_preauth": _b(("identity",), "Kerberos 사전 인증 요구 (false = 요구하지 않음)"),
    # ---- 접근, 전송
    "access.anonymous": _b(("service", "data_store", "credential"),
                           "인증 없이 접근 가능 (공개 저장소·공개 키 포함). 읽기/쓰기 구분은 external → has_permission"),
    "transport.encryption": _e(LEVELS, ("service", "group", "context"), "전송 구간 암호화"),
    "transport.signing": _e(LEVELS, ("service", "group", "context"), "메시지 서명"),
    "transport.certificate_pinning": _b(("service",), "인증서 고정 (중간자 차단)"),
    # ---- 디렉터리
    "directory.hardening": _e(("none", "partial", "baseline"), ("group", "context"),
                              "디렉터리 서비스 보안 기준 적용 수준 (그룹 정책 등)"),
    # ---- 호스트
    "host.firewall": _e(("disabled", "partial", "enabled"), HOST_SCOPE, "호스트 방화벽"),
    "host.endpoint_protection": _b(HOST_SCOPE, "백신/악성코드 방지 동작"),
    "host.behavior_prevention": _b(HOST_SCOPE, "행위 기반 차단 동작"),
    "host.patch_currency": _e(("current", "lagging", "unsupported"),
                              ("host", "service", "network_device", "group", "context"), "패치 수준"),
    "host.local_admin_shared": _b(HOST_SCOPE, "여러 호스트가 같은 로컬 관리자 자격증명 공유"),
    "host.os_hardening": _e(("none", "partial", "baseline"), HOST_SCOPE, "운영체제 보안 기준 적용 수준"),
    "host.registry_permissions_restricted": _b(HOST_SCOPE, "시스템 설정 저장소 권한 제한"),
    "host.env_permissions_restricted": _b(HOST_SCOPE, "환경 변수 변경 권한 제한"),
    "host.privileged_process_protection": _b(HOST_SCOPE, "권한 높은 프로세스 보호"),
    "host.credential_protection": _b(HOST_SCOPE, "메모리 속 자격증명 보호 기능"),
    "host.execution_control": _e(("none", "audit", "enforce"), HOST_SCOPE, "허용된 프로그램만 실행"),
    "host.software_install_restricted": _b(HOST_SCOPE, "사용자 임의 소프트웨어 설치 제한"),
    "host.removable_media_restricted": _b(HOST_SCOPE, "이동식 장치 사용 제한"),
    "host.library_loading_restricted": _b(HOST_SCOPE, "신뢰된 라이브러리만 로드"),
    "host.code_signing_enforced": _b(HOST_SCOPE, "서명된 코드만 실행"),
    "host.boot_integrity": _b(HOST_SCOPE, "부팅 무결성 검증"),
    "host.application_isolation": _b(("host", "service", "group", "context"), "애플리케이션 격리·샌드박스"),
    "host.exploit_protection": _b(HOST_SCOPE, "익스플로잇 방지 기능"),
    "host.elevation_prompt": _e(("disabled", "default", "strict"), HOST_SCOPE, "권한 상승 시 확인 절차"),
    "host.session_lock": _b(HOST_SCOPE, "자리 비움 시 자동 화면 잠금"),
    "host.metadata_service_protection": _b(HOST_SCOPE, "클라우드 인스턴스 메타데이터 서비스 보호 (토큰 요구 등)"),
    # ---- 컨테이너 (role: container 인 host, 또는 클러스터 그룹)
    "container.privileged": _b(("host", "group", "context"), "특권 모드로 실행"),
    "container.host_mounts": _b(("host", "group", "context"), "호스트 디렉터리·소켓을 마운트"),
    "container.pod_security_level": _e(("privileged", "baseline", "restricted"), ("host", "group", "context"),
                                       "컨테이너 보안 수준 (쿠버네티스 Pod Security Standards 단계)"),
    "container.service_account_token": _b(("host", "group", "context"), "플랫폼 API 토큰 자동 탑재"),
    # ---- 네트워크
    "network.legacy_name_resolution": _b(("host", "group", "context"), "브로드캐스트 기반 이름 해석 사용"),
    "network.intrusion_prevention": _b(NET_SCOPE, "네트워크 침입 차단"),
    "network.tls_inspection": _b(NET_SCOPE, "암호화 트래픽 검사"),
    "network.web_filtering": _b(NET_SCOPE, "웹 콘텐츠 필터링"),
    "network.dlp": _b(NET_SCOPE, "데이터 유출 방지 (외부 전송 통제)"),
    "network.trusted_dns": _b(("host", "group", "context"), "신뢰된 DNS 서버만 사용"),
    "network.port_access_control": _b(("group", "network_device", "context"), "포트 단위 접속 통제 (장비 인증 후 연결)"),
    "network.application_filtering": _b(("service", "group", "network_device", "context"), "애플리케이션 계층 필터링 (웹 방화벽 등)"),
    "network.ddos_protection": _b(("service", "group", "network_device", "context"), "대규모 트래픽 공격 방어"),
    # ---- 로깅
    "logging.centralized": _b(("host", "service", "group", "context"), "중앙 로그 수집 (원격 보관)"),
    "logging.audit": _e(("none", "partial", "full"), ("host", "service", "data_store", "group", "context"), "감사 로그 수준"),
    # ---- 저장소, 백업
    "storage.immutable": _b(("data_store",), "변경·삭제 불가 보관 (백업 보호)"),
    "storage.offsite": _b(("data_store",), "원본과 분리된 위치에 보관"),
    # ---- 산업 제어 (role: plc, hmi, scada_server)
    "ot.operating_mode_locked": _b(("host", "group", "context"), "제어기 운전 모드 변경 잠금"),
    "ot.variable_write_restricted": _b(("host", "group", "context"), "제어 변수 쓰기 제한"),
    # ---- 메일
    "mail.sender_authentication": _b(("service", "context"), "발신 도메인 인증 (위조 메일 차단)"),
    "mail.content_filtering": _b(("service", "context"), "첨부 파일 형식 차단·악성코드 검사"),
    # ---- 애플리케이션
    "app.secure_development": _b(("service", "business_service", "context"), "보안 개발 지침 적용"),
    # ---- 조직 (context.defaults 전용)
    "org.user_training": _e(("none", "basic", "regular"), ("context",), "보안 인식 교육"),
    "org.vulnerability_scanning": _e(("none", "periodic", "continuous"), ("context",), "취약점 점검"),
    "org.threat_intel": _b(("context",), "위협 인텔리전스 운영"),
    "org.attack_surface_management": _b(("context",), "외부 노출 정보·자산 관리 (공격 전 단계 대응)"),
}


def render_markdown() -> str:
    lines = [
        "# 설정 키 사전",
        "",
        "> 생성된 문서다. 직접 고치지 말고 `src/scengen/ir/vocab.py`를 고친 뒤",
        "> `.venv/bin/scengen vocab --markdown > docs/config-keys.md`로 다시 만든다.",
        "",
        f"키 {len(CONFIG_KEYS)}개. 붙일 수 있는 곳: 자산 타입, `group`(그룹), `context`(`context.defaults`, 조직 전체 기본값).",
        "",
        "YAML 주의: 따옴표 없는 `on`/`off`/`yes`/`no`는 참/거짓으로 읽힌다. 그래서 허용값에 이 단어들을 쓰지 않는다.",
        "",
        "| 키 | 값 | 붙일 수 있는 곳 | 의미 |",
        "|---|---|---|---|",
    ]
    for key, spec in CONFIG_KEYS.items():
        if spec.kind == "bool":
            values = "true / false"
        elif spec.kind == "enum":
            values = " / ".join(spec.values)
        else:
            values = "목록: " + ", ".join(spec.values)
        lines.append(f"| `{key}` | {values} | {', '.join(spec.applies_to)} | {spec.description} |")
    return "\n".join(lines)
