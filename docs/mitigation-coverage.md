# MITRE ATT&CK 완화책 대조표

> 이 파일은 생성된 문서다. 직접 고치지 말고 `src/scengen/ir/mitigation_map.yaml`을 고친 뒤
> `.venv/bin/scengen mitigations --markdown > docs/mitigation-coverage.md`로 다시 만든다.

질문: **"이 완화책이 적용되어 있는지를 IR로 표현할 수 있는가?"**

- 기준: MITRE ATT&CK Enterprise (attack-stix-data), ATT&CK v20.1 (가져온 날 2026-11-21), 활성 완화책 44개
- 첫 대조 (IR v0.2, 보강 전): ✅ 표현 가능 11 · ⚠️ 일부 5 · ❌ 불가 26 · ➖ 범위 밖 2
- 현재: ✅ 표현 가능 40 · ⚠️ 일부 2 · ❌ 불가 0 · ➖ 범위 밖 2
- M0.5 통과 조건 (표현 불가 0, 범위 밖은 사유 기록): **통과**

막는 기법 수 = 이 완화책이 막는 ATT&CK 기법·하위 기법의 수. 많을수록 표현이 중요하다.

| 완화책 | 이름 | 막는 기법 수 | 처음 | 현재 | IR 표현 | 설명 |
|---|---|---|---|---|---|---|
| [M1018](https://attack.mitre.org/mitigations/M1018) | User Account Management | 123 | ❌ 불가 | ✅ 표현 가능 | `config:account.enabled`, `config:account.dormant`, `relation:member_of`, `relation:has_permission` | 계정 활성/장기 미사용 상태 + 소속과 권한 |
| [M1026](https://attack.mitre.org/mitigations/M1026) | Privileged Account Management | 115 | ✅ 표현 가능 | ✅ 표현 가능 | `relation:has_permission`, `relation:member_of`, `relation:session`, `relation:runs` | 누가 관리자 권한을 갖는지(권한·소속) + 관리자 계정이 어디에 로그인해 있는지(세션) + 어떤 계정으로 서비스가 도는지 |
| [M1047](https://attack.mitre.org/mitigations/M1047) | Audit | 111 | ⚠️ 일부 | ✅ 표현 가능 | `config:logging.audit`, `config:logging.centralized` | 감사 로그 수준 + 중앙 수집 |
| [M1056](https://attack.mitre.org/mitigations/M1056) | Pre-compromise | 89 | ❌ 불가 | ✅ 표현 가능 | `config:org.attack_surface_management`, `field:attacker_profile.knowledge` | 외부 노출 관리 여부 + 공격자 사전 지식 변형(informed/uninformed) |
| [M1038](https://attack.mitre.org/mitigations/M1038) | Execution Prevention | 82 | ❌ 불가 | ✅ 표현 가능 | `config:host.execution_control` | 허용 프로그램 실행 통제 수준 |
| [M1042](https://attack.mitre.org/mitigations/M1042) | Disable or Remove Feature or Program | 72 | ✅ 표현 가능 | ✅ 표현 가능 | `relation:runs`, `config:network.legacy_name_resolution`, `config:access.anonymous` | 서비스·소프트웨어 노드의 유무 + 기능별 설정 키 |
| [M1017](https://attack.mitre.org/mitigations/M1017) | User Training | 64 | ❌ 불가 | ✅ 표현 가능 | `config:org.user_training` | 조직 단위 보안 인식 교육 수준 (사용자 상호작용이 필요한 단계의 확률) |
| [M1022](https://attack.mitre.org/mitigations/M1022) | Restrict File and Directory Permissions | 63 | ✅ 표현 가능 | ⚠️ 일부 | `relation:has_permission`, `relation:contains` | 데이터·저장소 단위 권한 엣지 **한계:** 개별 파일·디렉터리 단위 권한은 표현하지 않음 (데이터 노드 단위로 묶음). 세밀한 단위는 L3 범위 |
| [M1031](https://attack.mitre.org/mitigations/M1031) | Network Intrusion Prevention | 62 | ❌ 불가 | ✅ 표현 가능 | `config:network.intrusion_prevention` | 네트워크 구간·경계 장비의 침입 차단 |
| [M1037](https://attack.mitre.org/mitigations/M1037) | Filter Network Traffic | 52 | ✅ 표현 가능 | ✅ 표현 가능 | `relation:reaches`, `config:host.firewall` | 유입·내부·유출 방향의 도달 규칙(외부로 가는 reaches 포함) + 호스트 방화벽 |
| [M1040](https://attack.mitre.org/mitigations/M1040) | Behavior Prevention on Endpoint | 51 | ❌ 불가 | ✅ 표현 가능 | `config:host.behavior_prevention` | 호스트 단위 행위 기반 차단 |
| [M1032](https://attack.mitre.org/mitigations/M1032) | Multi-factor Authentication | 48 | ✅ 표현 가능 | ✅ 표현 가능 | `config:auth.mfa` | 계정·서비스·그룹·조직 단위 다중 인증 |
| [M1027](https://attack.mitre.org/mitigations/M1027) | Password Policies | 47 | ❌ 불가 | ✅ 표현 가능 | `config:auth.password_policy` | 계정·서비스·그룹·조직 단위 비밀번호 정책 강도 |
| [M1051](https://attack.mitre.org/mitigations/M1051) | Update Software | 42 | ✅ 표현 가능 | ✅ 표현 가능 | `config:host.patch_currency`, `field:asset.service+network_device.version` | 패치 수준 + 서비스 버전 |
| [M1028](https://attack.mitre.org/mitigations/M1028) | Operating System Configuration | 39 | ⚠️ 일부 | ✅ 표현 가능 | `config:host.os_hardening`, `config:host.firewall`, `config:network.legacy_name_resolution` | 운영체제 보안 기준 적용 수준 + 개별 설정 키 |
| [M1030](https://attack.mitre.org/mitigations/M1030) | Network Segmentation | 38 | ✅ 표현 가능 | ✅ 표현 가능 | `field:asset.groups`, `field:group.parent`, `relation:reaches` | 네트워크 그룹 계층과 그룹 단위 도달 규칙 |
| [M1054](https://attack.mitre.org/mitigations/M1054) | Software Configuration | 36 | ✅ 표현 가능 | ⚠️ 일부 | `field:asset.config`, `config:auth.methods`, `config:access.anonymous`, `config:transport.signing` | 서비스 단위 설정 키 **한계:** 제품별 세부 설정은 설정 키 사전에 있는 것만 표현됨. 규칙이 필요로 하는 키는 P2에서 추가 |
| [M1041](https://attack.mitre.org/mitigations/M1041) | Encrypt Sensitive Information | 33 | ✅ 표현 가능 | ✅ 표현 가능 | `field:relation.contains.encrypted`, `field:relation.contains.key_ref`, `config:transport.encryption` | 저장 데이터 암호화(키 위치 포함) + 전송 구간 암호화 |
| [M1021](https://attack.mitre.org/mitigations/M1021) | Restrict Web-Based Content | 31 | ❌ 불가 | ✅ 표현 가능 | `config:network.web_filtering` | 네트워크 구간·경계 장비의 웹 콘텐츠 필터링 |
| [M1049](https://attack.mitre.org/mitigations/M1049) | Antivirus/Antimalware | 23 | ✅ 표현 가능 | ✅ 표현 가능 | `config:host.endpoint_protection` | 호스트 단위 백신 |
| [M1045](https://attack.mitre.org/mitigations/M1045) | Code Signing | 22 | ❌ 불가 | ✅ 표현 가능 | `config:host.code_signing_enforced` | 호스트 단위 서명 코드만 실행 |
| [M1024](https://attack.mitre.org/mitigations/M1024) | Restrict Registry Permissions | 20 | ❌ 불가 | ✅ 표현 가능 | `config:host.registry_permissions_restricted` | 호스트 단위 시스템 설정 저장소 권한 제한 여부 |
| [M1035](https://attack.mitre.org/mitigations/M1035) | Limit Access to Resource Over Network | 19 | ✅ 표현 가능 | ✅ 표현 가능 | `relation:reaches`, `relation:authenticates_to`, `relation:has_permission` | 네트워크 도달 규칙 + 접근 가능한 주체 |
| [M1013](https://attack.mitre.org/mitigations/M1013) | Application Developer Guidance | 17 | ❌ 불가 | ✅ 표현 가능 | `config:app.secure_development` | 자체 개발 서비스에 보안 개발 지침 적용 여부 |
| [M1033](https://attack.mitre.org/mitigations/M1033) | Limit Software Installation | 17 | ❌ 불가 | ✅ 표현 가능 | `config:host.software_install_restricted` | 호스트 단위 설치 제한 |
| [M1015](https://attack.mitre.org/mitigations/M1015) | Active Directory Configuration | 15 | ⚠️ 일부 | ✅ 표현 가능 | `config:directory.hardening`, `config:auth.methods`, `config:transport.signing`, `relation:has_permission`, `relation:trusts` | 도메인 그룹의 보안 기준 적용 수준 + 개별 설정(인증 방식, 서명) + 위임·권한 엣지(delegate 행위) + 신뢰 관계 |
| [M1048](https://attack.mitre.org/mitigations/M1048) | Application Isolation and Sandboxing | 15 | ❌ 불가 | ✅ 표현 가능 | `config:host.application_isolation` | 호스트·서비스 단위 격리 |
| [M1046](https://attack.mitre.org/mitigations/M1046) | Boot Integrity | 14 | ❌ 불가 | ✅ 표현 가능 | `config:host.boot_integrity` | 호스트 단위 부팅 무결성 |
| [M1036](https://attack.mitre.org/mitigations/M1036) | Account Use Policies | 12 | ❌ 불가 | ✅ 표현 가능 | `config:auth.lockout`, `relation:authenticates_to` | 잠금 정책 + 계정이 로그인할 수 있는 곳(엣지로 제한) |
| [M1050](https://attack.mitre.org/mitigations/M1050) | Exploit Protection | 12 | ❌ 불가 | ✅ 표현 가능 | `config:host.exploit_protection` | 호스트 단위 익스플로잇 방지 |
| [M1057](https://attack.mitre.org/mitigations/M1057) | Data Loss Prevention | 12 | ❌ 불가 | ✅ 표현 가능 | `config:network.dlp`, `field:attacker_profile.egress` | 외부 전송 통제 + 유출 경로 변형(from_ir에서 반영) |
| [M1029](https://attack.mitre.org/mitigations/M1029) | Remote Data Storage | 11 | ⚠️ 일부 | ✅ 표현 가능 | `config:logging.centralized`, `config:storage.offsite`, `relation:contains` | 로그 원격 보관 + 데이터 사본이 분리된 저장소에 있는지 |
| [M1043](https://attack.mitre.org/mitigations/M1043) | Credential Access Protection | 10 | ❌ 불가 | ✅ 표현 가능 | `config:host.credential_protection` | 호스트 단위 자격증명 보호 기능 |
| [M1053](https://attack.mitre.org/mitigations/M1053) | Data Backup | 10 | ⚠️ 일부 | ✅ 표현 가능 | `relation:contains`, `config:storage.immutable`, `config:storage.offsite` | 데이터 사본이 백업 저장소에 있는지 + 변경 불가·분리 보관 여부 |
| [M1025](https://attack.mitre.org/mitigations/M1025) | Privileged Process Integrity | 7 | ❌ 불가 | ✅ 표현 가능 | `config:host.privileged_process_protection` | 호스트 단위 권한 높은 프로세스 보호 여부 |
| [M1034](https://attack.mitre.org/mitigations/M1034) | Limit Hardware Installation | 7 | ❌ 불가 | ✅ 표현 가능 | `config:host.removable_media_restricted` | 호스트 단위 이동식 장치 제한 |
| [M1052](https://attack.mitre.org/mitigations/M1052) | User Account Control | 7 | ❌ 불가 | ✅ 표현 가능 | `config:host.elevation_prompt` | 권한 상승 확인 절차 수준 |
| [M1060](https://attack.mitre.org/mitigations/M1060) | Out-of-Band Communications Channel | 7 | ➖ 범위 밖 | ➖ 범위 밖 | — | 사유: 사고 대응 중 의사소통 수단. 공격 단계의 성공 여부를 바꾸지 않음 |
| [M1016](https://attack.mitre.org/mitigations/M1016) | Vulnerability Scanning | 5 | ❌ 불가 | ✅ 표현 가능 | `config:org.vulnerability_scanning`, `config:host.patch_currency`, `field:asset.service+network_device.version` | 조직의 점검 주기(버전 정보가 없을 때 사전분포에 영향) + 점검 결과인 패치 수준·버전 |
| [M1019](https://attack.mitre.org/mitigations/M1019) | Threat Intelligence Program | 5 | ❌ 불가 | ✅ 표현 가능 | `config:org.threat_intel` | 조직 단위 위협 인텔리전스 운영 여부 |
| [M1020](https://attack.mitre.org/mitigations/M1020) | SSL/TLS Inspection | 4 | ❌ 불가 | ✅ 표현 가능 | `config:network.tls_inspection` | 네트워크 구간·경계 장비의 암호화 트래픽 검사 |
| [M1044](https://attack.mitre.org/mitigations/M1044) | Restrict Library Loading | 3 | ❌ 불가 | ✅ 표현 가능 | `config:host.library_loading_restricted` | 호스트 단위 라이브러리 로드 제한 |
| [M1055](https://attack.mitre.org/mitigations/M1055) | Do Not Mitigate | 3 | ➖ 범위 밖 | ➖ 범위 밖 | — | 사유: 보안 조치가 아니라 "조치하지 말 것"을 알리는 분류 |
| [M1039](https://attack.mitre.org/mitigations/M1039) | Environment Variable Permissions | 2 | ❌ 불가 | ✅ 표현 가능 | `config:host.env_permissions_restricted` | 호스트 단위 환경 변수 변경 제한 |

## 완화책에 연결되지 않은 설정 키

`account.kerberos_preauth`, `account.password_empty`, `account.service_principal`, `auth.credential_rotation`, `auth.default_credentials`, `auth.mfa_strength`, `auth.token_binding`, `container.host_mounts`, `container.pod_security_level`, `container.privileged`, `container.service_account_token`, `host.local_admin_shared`, `host.metadata_service_protection`, `host.session_lock`, `mail.content_filtering`, `mail.sender_authentication`, `network.application_filtering`, `network.ddos_protection`, `network.port_access_control`, `network.trusted_dns`, `ot.operating_mode_locked`, `ot.variable_write_restricted`, `transport.certificate_pinning` — 완화책이 아니라 공격 표면(취약 상태)을 나타내는 키

