# 설정 키 사전

> 생성된 문서다. 직접 고치지 말고 `src/scengen/ir/vocab.py`를 고친 뒤
> `.venv/bin/scengen vocab --markdown > docs/config-keys.md`로 다시 만든다.

키 65개. 붙일 수 있는 곳: 자산 타입, `group`(그룹), `context`(`context.defaults`, 조직 전체 기본값).

YAML 주의: 따옴표 없는 `on`/`off`/`yes`/`no`는 참/거짓으로 읽힌다. 그래서 허용값에 이 단어들을 쓰지 않는다.

| 키 | 값 | 붙일 수 있는 곳 | 의미 |
|---|---|---|---|
| `auth.methods` | 목록: password, key, certificate, kerberos, ntlm, oauth, saml, biometric, none | service, host, network_device, group, context | 허용되는 인증 방식 |
| `auth.mfa` | true / false | service, identity, network_device, group, context | 다중 인증 강제 |
| `auth.default_credentials` | true / false | service, network_device | 제조사 기본 계정 사용 중 |
| `auth.password_policy` | none / weak / standard / strong | identity, service, group, context | 비밀번호 정책 강도 |
| `auth.lockout` | true / false | identity, service, host, group, context | 반복 실패 시 계정·단말 잠금 |
| `auth.mfa_strength` | otp / push / phishing_resistant | identity, service, group, context | 다중 인증 방식의 강도 (일회용 코드 / 푸시 승인 / 피싱 방지형) |
| `auth.token_binding` | true / false | service, context | 토큰을 발급받은 기기·연결에 묶음 (탈취 토큰 재사용 방지) |
| `auth.credential_rotation` | none / periodic / automatic | identity, credential, service, group, context | 자격증명 주기적 교체 |
| `account.enabled` | true / false | identity | 계정 활성 상태 (false = 비활성화됨) |
| `account.dormant` | true / false | identity, credential | 장기간 사용되지 않은 계정·자격증명 |
| `account.password_empty` | true / false | identity | 비밀번호가 비어 있는 계정 |
| `account.service_principal` | true / false | identity | 서비스 주체 이름(SPN)이 등록된 계정 |
| `account.kerberos_preauth` | true / false | identity | Kerberos 사전 인증 요구 (false = 요구하지 않음) |
| `access.anonymous` | true / false | service, data_store, credential | 인증 없이 접근 가능 (공개 저장소·공개 키 포함). 읽기/쓰기 구분은 external → has_permission |
| `transport.encryption` | none / optional / required | service, group, context | 전송 구간 암호화 |
| `transport.signing` | none / optional / required | service, group, context | 메시지 서명 |
| `transport.certificate_pinning` | true / false | service | 인증서 고정 (중간자 차단) |
| `directory.hardening` | none / partial / baseline | group, context | 디렉터리 서비스 보안 기준 적용 수준 (그룹 정책 등) |
| `host.firewall` | disabled / partial / enabled | host, group, context | 호스트 방화벽 |
| `host.endpoint_protection` | true / false | host, group, context | 백신/악성코드 방지 동작 |
| `host.behavior_prevention` | true / false | host, group, context | 행위 기반 차단 동작 |
| `host.patch_currency` | current / lagging / unsupported | host, service, network_device, group, context | 패치 수준 |
| `host.local_admin_shared` | true / false | host, group, context | 여러 호스트가 같은 로컬 관리자 자격증명 공유 |
| `host.os_hardening` | none / partial / baseline | host, group, context | 운영체제 보안 기준 적용 수준 |
| `host.registry_permissions_restricted` | true / false | host, group, context | 시스템 설정 저장소 권한 제한 |
| `host.env_permissions_restricted` | true / false | host, group, context | 환경 변수 변경 권한 제한 |
| `host.privileged_process_protection` | true / false | host, group, context | 권한 높은 프로세스 보호 |
| `host.credential_protection` | true / false | host, group, context | 메모리 속 자격증명 보호 기능 |
| `host.execution_control` | none / audit / enforce | host, group, context | 허용된 프로그램만 실행 |
| `host.software_install_restricted` | true / false | host, group, context | 사용자 임의 소프트웨어 설치 제한 |
| `host.removable_media_restricted` | true / false | host, group, context | 이동식 장치 사용 제한 |
| `host.library_loading_restricted` | true / false | host, group, context | 신뢰된 라이브러리만 로드 |
| `host.code_signing_enforced` | true / false | host, group, context | 서명된 코드만 실행 |
| `host.boot_integrity` | true / false | host, group, context | 부팅 무결성 검증 |
| `host.application_isolation` | true / false | host, service, group, context | 애플리케이션 격리·샌드박스 |
| `host.exploit_protection` | true / false | host, group, context | 익스플로잇 방지 기능 |
| `host.elevation_prompt` | disabled / default / strict | host, group, context | 권한 상승 시 확인 절차 |
| `host.session_lock` | true / false | host, group, context | 자리 비움 시 자동 화면 잠금 |
| `host.metadata_service_protection` | true / false | host, group, context | 클라우드 인스턴스 메타데이터 서비스 보호 (토큰 요구 등) |
| `container.privileged` | true / false | host, group, context | 특권 모드로 실행 |
| `container.host_mounts` | true / false | host, group, context | 호스트 디렉터리·소켓을 마운트 |
| `container.pod_security_level` | privileged / baseline / restricted | host, group, context | 컨테이너 보안 수준 (쿠버네티스 Pod Security Standards 단계) |
| `container.service_account_token` | true / false | host, group, context | 플랫폼 API 토큰 자동 탑재 |
| `network.legacy_name_resolution` | true / false | host, group, context | 브로드캐스트 기반 이름 해석 사용 |
| `network.intrusion_prevention` | true / false | group, network_device, context | 네트워크 침입 차단 |
| `network.tls_inspection` | true / false | group, network_device, context | 암호화 트래픽 검사 |
| `network.web_filtering` | true / false | group, network_device, context | 웹 콘텐츠 필터링 |
| `network.dlp` | true / false | group, network_device, context | 데이터 유출 방지 (외부 전송 통제) |
| `network.trusted_dns` | true / false | host, group, context | 신뢰된 DNS 서버만 사용 |
| `network.port_access_control` | true / false | group, network_device, context | 포트 단위 접속 통제 (장비 인증 후 연결) |
| `network.application_filtering` | true / false | service, group, network_device, context | 애플리케이션 계층 필터링 (웹 방화벽 등) |
| `network.ddos_protection` | true / false | service, group, network_device, context | 대규모 트래픽 공격 방어 |
| `logging.centralized` | true / false | host, service, group, context | 중앙 로그 수집 (원격 보관) |
| `logging.audit` | none / partial / full | host, service, data_store, group, context | 감사 로그 수준 |
| `storage.immutable` | true / false | data_store | 변경·삭제 불가 보관 (백업 보호) |
| `storage.offsite` | true / false | data_store | 원본과 분리된 위치에 보관 |
| `ot.operating_mode_locked` | true / false | host, group, context | 제어기 운전 모드 변경 잠금 |
| `ot.variable_write_restricted` | true / false | host, group, context | 제어 변수 쓰기 제한 |
| `mail.sender_authentication` | true / false | service, context | 발신 도메인 인증 (위조 메일 차단) |
| `mail.content_filtering` | true / false | service, context | 첨부 파일 형식 차단·악성코드 검사 |
| `app.secure_development` | true / false | service, business_service, context | 보안 개발 지침 적용 |
| `org.user_training` | none / basic / regular | context | 보안 인식 교육 |
| `org.vulnerability_scanning` | none / periodic / continuous | context | 취약점 점검 |
| `org.threat_intel` | true / false | context | 위협 인텔리전스 운영 |
| `org.attack_surface_management` | true / false | context | 외부 노출 정보·자산 관리 (공격 전 단계 대응) |
