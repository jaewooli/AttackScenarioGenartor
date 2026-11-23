# CIS Critical Security Controls 대조표

> 생성된 문서다. 원본 `src/scengen/ir/crosswalk/cis-controls-v8.1.yaml`을 고친 뒤
> `.venv/bin/scengen crosswalk cis-controls-v8.1 --markdown > docs/crosswalk/cis-controls-v8.1.md`로 다시 만든다.

질문: **이 세이프가드가 적용되어 있는지를 IR로 표현할 수 있는가?**

- 기준: CIS Critical Security Controls 8.1.2 — CIS 공식 OSCAL 카탈로그 (bitbucket.org/cis-it-workspace/cis-controls-v8.1_oscal), 2026-11-21 확인
- 항목 153개: ✅ 표현 가능 91 · ⚠️ 일부 11 · ❌ 불가 0 · ➖ 범위 밖 51
- 통과 조건 (표현 불가 0): **통과**

> 라이선스(CC BY-NC-ND 4.0) 때문에 원문 제목은 싣지 않는다. '요약'은 이 프로젝트가 쓴 짧은 설명이다.
> 세이프가드 번호 153개와 보안 기능(fn) 분류는 공식 OSCAL 카탈로그와 일치함을 2026-11-21에 확인했다.

## 대조 중 발견해서 보강한 빈틈

| 빈틈 | 보강 | 관련 항목 |
|---|---|---|
| 신뢰된 DNS 서버 사용 여부 없음 | config network.trusted_dns | 4.9 |
| 자동 화면 잠금 없음 | config host.session_lock | 4.3 |
| 휴대 단말을 표현할 역할 없음 | role mobile_device | 4.10, 4.12 |
| 메일 발신 도메인 인증, 첨부·악성코드 필터링 없음 | config mail.sender_authentication, mail.content_filtering | 9.5, 9.6, 9.7 |
| 포트 단위 접속 통제 없음 | config network.port_access_control | 13.9 |
| 애플리케이션 계층 필터링(웹 방화벽) 없음 | config network.application_filtering | 13.10 |
| 네트워크 장비에 다중 인증·인증 방식을 붙일 수 없음 | auth.mfa, auth.methods 의 applies_to 에 network_device 추가 | 12.3 |
| 서비스(애플리케이션) 단위 패치 수준을 붙일 수 없음 | host.patch_currency 의 applies_to 에 service 추가 | 7.4 |
| 단말(host)에 잠금 정책을 붙일 수 없었음 (대조표는 표현 가능이라 했지만 샘플에 써보니 붙일 곳이 없었음) | auth.lockout 의 applies_to 에 host 추가 | 4.10 |
| 저장소에 감사 로그 수준을 붙일 수 없음 | logging.audit 의 applies_to 에 data_store 추가 | 3.14 |

## 범위 밖 사유 코드

| 코드 | 의미 |
|---|---|
| 절차 | 절차·거버넌스 항목. 그 결과는 다른 IR 값(설정, 권한, 패치 수준 등)으로 나타난다 |
| 탐지 | 탐지·모니터링 항목. 현재 모델은 탐지와 시간을 다루지 않는다 |
| 사후 | 사고 이후 대응·복구 항목. 공격 단계의 성공 여부를 바꾸지 않는다 |

## 항목

| 항목 | 요약 | fn | 상태 | IR 표현 | 설명 |
|---|---|---|---|---|---|
| 1.1 | 기업 자산 목록 유지 | identify | ✅ 표현 가능 | `field:asset.role`, `field:asset.groups` | IR 자체가 자산 목록 |
| 1.2 | 미승인 자산 처리 | respond | ➖ 범위 밖 | — | 사유: 절차 |
| 1.3 | 능동 자산 탐색 도구 | detect | ➖ 범위 밖 | — | 사유: 절차 |
| 1.4 | DHCP 기록으로 목록 갱신 | identify | ➖ 범위 밖 | — | 사유: 절차 |
| 1.5 | 수동 자산 탐색 도구 | detect | ➖ 범위 밖 | — | 사유: 절차 |
| 2.1 | 소프트웨어 목록 유지 | identify | ✅ 표현 가능 | `relation:runs`, `field:asset.software.version` |  |
| 2.2 | 지원되는 소프트웨어만 사용 | identify | ✅ 표현 가능 | `config:host.patch_currency` | patch_currency=unsupported |
| 2.3 | 미승인 소프트웨어 처리 | respond | ➖ 범위 밖 | — | 사유: 절차 |
| 2.4 | 소프트웨어 목록 자동화 도구 | detect | ➖ 범위 밖 | — | 사유: 절차 |
| 2.5 | 허용 소프트웨어 목록 | protect | ✅ 표현 가능 | `config:host.execution_control` |  |
| 2.6 | 허용 라이브러리 목록 | protect | ✅ 표현 가능 | `config:host.library_loading_restricted` |  |
| 2.7 | 허용 스크립트 목록 | protect | ✅ 표현 가능 | `config:host.execution_control` |  |
| 3.1 | 데이터 관리 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 3.2 | 데이터 목록 유지 | identify | ✅ 표현 가능 | `field:asset.data.categories`, `relation:contains` |  |
| 3.3 | 데이터 접근 제어 목록 | protect | ✅ 표현 가능 | `relation:has_permission` |  |
| 3.4 | 데이터 보존 기간 적용 | protect | ⚠️ 일부 | `field:asset.data.volume` |  **한계:** 보존 기간 자체는 표현하지 않고 그 결과(남아 있는 데이터의 양)로 근사 |
| 3.5 | 데이터 안전 폐기 | protect | ✅ 표현 가능 | `relation:contains` | 폐기된 데이터는 IR에 없음 |
| 3.6 | 사용자 단말 데이터 암호화 | protect | ✅ 표현 가능 | `field:relation.contains.encrypted` |  |
| 3.7 | 데이터 분류 체계 | identify | ✅ 표현 가능 | `field:asset.data.categories` |  |
| 3.8 | 데이터 흐름 문서화 | identify | ⚠️ 일부 | `relation:depends_on`, `relation:contains` |  **한계:** 데이터가 시스템 사이를 이동하는 흐름은 의존 관계로만 근사 (데이터 흐름 엣지 없음) |
| 3.9 | 이동식 매체 데이터 암호화 | protect | ⚠️ 일부 | `config:host.removable_media_restricted` |  **한계:** 매체 암호화 여부 자체는 없고 매체 사용 제한으로 근사 |
| 3.10 | 전송 중 민감 데이터 암호화 | protect | ✅ 표현 가능 | `config:transport.encryption` |  |
| 3.11 | 저장된 민감 데이터 암호화 | protect | ✅ 표현 가능 | `field:relation.contains.encrypted`, `field:relation.contains.key_ref` |  |
| 3.12 | 민감도에 따른 처리·저장 분리 | protect | ✅ 표현 가능 | `field:asset.groups`, `relation:reaches` |  |
| 3.13 | 데이터 유출 방지 도구 | protect | ✅ 표현 가능 | `config:network.dlp` |  |
| 3.14 | 민감 데이터 접근 기록 | detect | ✅ 표현 가능 | `config:logging.audit` | 저장소에 logging.audit |
| 4.1 | 보안 설정 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 4.2 | 네트워크 장비 보안 설정 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 4.3 | 자동 세션 잠금 | protect | ✅ 표현 가능 | `config:host.session_lock` |  |
| 4.4 | 서버 방화벽 | protect | ✅ 표현 가능 | `config:host.firewall` |  |
| 4.5 | 사용자 단말 방화벽 | protect | ✅ 표현 가능 | `config:host.firewall` |  |
| 4.6 | 자산·소프트웨어 안전 관리 | protect | ✅ 표현 가능 | `config:transport.encryption`, `config:auth.methods` |  |
| 4.7 | 기본 계정 관리 | protect | ✅ 표현 가능 | `config:auth.default_credentials` |  |
| 4.8 | 불필요 서비스 제거·비활성 | protect | ✅ 표현 가능 | `relation:runs` | 서비스 노드의 유무 |
| 4.9 | 신뢰된 DNS 서버 사용 | protect | ✅ 표현 가능 | `config:network.trusted_dns` |  |
| 4.10 | 휴대 단말 자동 잠금 | protect | ✅ 표현 가능 | `config:auth.lockout`, `field:asset.role` | role mobile_device |
| 4.11 | 휴대 단말 원격 삭제 | protect | ➖ 범위 밖 | — | 사유: 사후 |
| 4.12 | 휴대 단말 업무 공간 분리 | protect | ✅ 표현 가능 | `config:host.application_isolation` |  |
| 5.1 | 계정 목록 유지 | identify | ✅ 표현 가능 | `field:asset.identity.kind` |  |
| 5.2 | 계정마다 다른 비밀번호 | protect | ✅ 표현 가능 | `relation:grants`, `config:host.local_admin_shared` | 한 자격증명이 여러 주체를 grants 하면 재사용 |
| 5.3 | 휴면 계정 비활성화 | protect | ✅ 표현 가능 | `config:account.dormant`, `config:account.enabled` |  |
| 5.4 | 관리자 권한은 전용 계정에만 | protect | ✅ 표현 가능 | `relation:has_permission`, `relation:session` |  |
| 5.5 | 서비스 계정 목록 | identify | ✅ 표현 가능 | `field:asset.identity.kind`, `relation:runs` |  |
| 5.6 | 계정 중앙 관리 | govern | ✅ 표현 가능 | `field:asset.identity.kind`, `field:asset.groups` | 디렉터리 계정 vs 로컬 계정 |
| 6.1 | 접근 권한 부여 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 6.2 | 접근 권한 회수 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 6.3 | 외부 노출 앱 다중 인증 | protect | ✅ 표현 가능 | `config:auth.mfa` |  |
| 6.4 | 원격 접속 다중 인증 | protect | ✅ 표현 가능 | `config:auth.mfa` |  |
| 6.5 | 관리자 접근 다중 인증 | protect | ✅ 표현 가능 | `config:auth.mfa` |  |
| 6.6 | 인증·인가 시스템 목록 | identify | ✅ 표현 가능 | `field:asset.role` | role identity_provider |
| 6.7 | 접근 통제 중앙화 | protect | ✅ 표현 가능 | `field:asset.role`, `relation:trusts` |  |
| 6.8 | 역할 기반 접근 통제 | govern | ✅ 표현 가능 | `relation:member_of`, `relation:has_permission` |  |
| 7.1 | 취약점 관리 절차 | govern | ✅ 표현 가능 | `config:org.vulnerability_scanning` |  |
| 7.2 | 조치 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 7.3 | 운영체제 패치 자동화 | protect | ✅ 표현 가능 | `config:host.patch_currency` |  |
| 7.4 | 애플리케이션 패치 자동화 | protect | ✅ 표현 가능 | `config:host.patch_currency`, `field:asset.service+network_device.version` | 서비스에도 patch_currency |
| 7.5 | 내부 자산 취약점 스캔 | identify | ✅ 표현 가능 | `config:org.vulnerability_scanning` |  |
| 7.6 | 외부 노출 자산 취약점 스캔 | identify | ✅ 표현 가능 | `config:org.vulnerability_scanning` |  |
| 7.7 | 발견된 취약점 조치 | respond | ✅ 표현 가능 | `config:host.patch_currency` |  |
| 8.1 | 로그 관리 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 8.2 | 감사 로그 수집 | detect | ✅ 표현 가능 | `config:logging.audit` |  |
| 8.3 | 로그 저장 공간 확보 | protect | ➖ 범위 밖 | — | 사유: 탐지 |
| 8.4 | 시간 동기화 | protect | ➖ 범위 밖 | — | 사유: 탐지 |
| 8.5 | 상세 감사 로그 | detect | ✅ 표현 가능 | `config:logging.audit` | logging.audit=full |
| 8.6 | DNS 질의 로그 | detect | ⚠️ 일부 | `config:logging.audit` |  **한계:** 로그 종류(DNS |
| 8.7 | URL 요청 로그 | detect | ⚠️ 일부 | `config:logging.audit` |  **한계:** 로그 종류 구분 없음 |
| 8.8 | 명령줄 로그 | detect | ⚠️ 일부 | `config:logging.audit` |  **한계:** 로그 종류 구분 없음 |
| 8.9 | 로그 중앙화 | detect | ✅ 표현 가능 | `config:logging.centralized` |  |
| 8.10 | 로그 보존 | protect | ➖ 범위 밖 | — | 사유: 탐지 |
| 8.11 | 로그 검토 | detect | ➖ 범위 밖 | — | 사유: 탐지 |
| 8.12 | 서비스 제공자 로그 수집 | detect | ✅ 표현 가능 | `config:logging.audit` | 외부 서비스 노드에 logging.audit |
| 9.1 | 지원되는 브라우저·메일 클라이언트만 | protect | ✅ 표현 가능 | `config:host.patch_currency` |  |
| 9.2 | DNS 필터링 | protect | ✅ 표현 가능 | `config:network.web_filtering` |  |
| 9.3 | URL 필터링 | protect | ✅ 표현 가능 | `config:network.web_filtering` |  |
| 9.4 | 브라우저·메일 확장 제한 | protect | ✅ 표현 가능 | `config:host.software_install_restricted` |  |
| 9.5 | 발신 도메인 인증 | protect | ✅ 표현 가능 | `config:mail.sender_authentication` |  |
| 9.6 | 불필요한 파일 형식 차단 | protect | ✅ 표현 가능 | `config:mail.content_filtering` |  |
| 9.7 | 메일 서버 악성코드 방지 | protect | ✅ 표현 가능 | `config:mail.content_filtering` |  |
| 10.1 | 백신 배포·유지 | detect | ✅ 표현 가능 | `config:host.endpoint_protection` |  |
| 10.2 | 백신 자동 업데이트 | protect | ✅ 표현 가능 | `config:host.endpoint_protection` | endpoint_protection=true 는 최신 유지를 포함 |
| 10.3 | 이동식 매체 자동 실행 끄기 | protect | ✅ 표현 가능 | `config:host.removable_media_restricted` |  |
| 10.4 | 이동식 매체 자동 검사 | detect | ✅ 표현 가능 | `config:host.removable_media_restricted`, `config:host.endpoint_protection` |  |
| 10.5 | 익스플로잇 방지 기능 | protect | ✅ 표현 가능 | `config:host.exploit_protection` |  |
| 10.6 | 백신 중앙 관리 | protect | ➖ 범위 밖 | — | 사유: 절차 |
| 10.7 | 행위 기반 악성코드 방지 | detect | ✅ 표현 가능 | `config:host.behavior_prevention` |  |
| 11.1 | 복구 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 11.2 | 자동 백업 | recover | ✅ 표현 가능 | `relation:contains` | 백업 저장소가 데이터를 contains |
| 11.3 | 복구 데이터 보호 | protect | ✅ 표현 가능 | `config:storage.immutable`, `field:relation.contains.encrypted` |  |
| 11.4 | 격리된 복구 사본 | recover | ✅ 표현 가능 | `config:storage.offsite` |  |
| 11.5 | 복구 시험 | recover | ➖ 범위 밖 | — | 사유: 사후 |
| 12.1 | 네트워크 장비 최신 유지 | protect | ✅ 표현 가능 | `config:host.patch_currency` |  |
| 12.2 | 안전한 네트워크 구조 | protect | ✅ 표현 가능 | `field:asset.groups`, `field:group.parent`, `relation:reaches` |  |
| 12.3 | 네트워크 장비 안전 관리 | protect | ✅ 표현 가능 | `config:auth.mfa`, `config:auth.methods`, `config:auth.default_credentials` |  |
| 12.4 | 구성도 유지 | govern | ✅ 표현 가능 | `field:asset.groups`, `relation:reaches` | IR 자체가 구성도 |
| 12.5 | 네트워크 인증·인가·감사 중앙화 | protect | ✅ 표현 가능 | `field:asset.role`, `relation:authenticates_to` |  |
| 12.6 | 안전한 관리 프로토콜 | protect | ✅ 표현 가능 | `config:transport.encryption` |  |
| 12.7 | 원격 단말은 VPN과 중앙 인증 경유 | protect | ✅ 표현 가능 | `relation:reaches`, `field:asset.role`, `config:auth.mfa` | role vpn_gateway 경유 reaches |
| 12.8 | 관리 작업 전용 장비 | protect | ✅ 표현 가능 | `relation:session`, `field:asset.role` | 관리자 세션이 전용 장비(jump_host)에만 있는지 |
| 13.1 | 보안 이벤트 경보 중앙화 | detect | ➖ 범위 밖 | — | 사유: 탐지 |
| 13.2 | 호스트 침입 탐지 | detect | ➖ 범위 밖 | — | 사유: 탐지 |
| 13.3 | 네트워크 침입 탐지 | detect | ➖ 범위 밖 | — | 사유: 탐지 |
| 13.4 | 구간 간 트래픽 필터링 | protect | ✅ 표현 가능 | `relation:reaches` |  |
| 13.5 | 원격 자산 접근 통제 | protect | ✅ 표현 가능 | `relation:reaches`, `relation:authenticates_to` |  |
| 13.6 | 트래픽 흐름 기록 | detect | ➖ 범위 밖 | — | 사유: 탐지 |
| 13.7 | 호스트 침입 차단 | protect | ✅ 표현 가능 | `config:host.behavior_prevention` |  |
| 13.8 | 네트워크 침입 차단 | protect | ✅ 표현 가능 | `config:network.intrusion_prevention` |  |
| 13.9 | 포트 단위 접속 통제 | protect | ✅ 표현 가능 | `config:network.port_access_control` |  |
| 13.10 | 애플리케이션 계층 필터링 | protect | ✅ 표현 가능 | `config:network.application_filtering` |  |
| 13.11 | 경보 임계값 조정 | detect | ➖ 범위 밖 | — | 사유: 탐지 |
| 14.1 | 보안 인식 프로그램 | govern | ✅ 표현 가능 | `config:org.user_training` |  |
| 14.2 | 사회공학 인식 교육 | protect | ✅ 표현 가능 | `config:org.user_training` |  |
| 14.3 | 인증 관련 교육 | protect | ⚠️ 일부 | `config:org.user_training` |  **한계:** 교육 주제별 구분 없이 수준으로만 표현 |
| 14.4 | 데이터 취급 교육 | protect | ⚠️ 일부 | `config:org.user_training` |  **한계:** 주제 구분 없음 |
| 14.5 | 의도치 않은 노출 교육 | protect | ⚠️ 일부 | `config:org.user_training` |  **한계:** 주제 구분 없음 |
| 14.6 | 사고 인지·보고 교육 | protect | ➖ 범위 밖 | — | 사유: 탐지 |
| 14.7 | 보안 업데이트 누락 보고 교육 | protect | ➖ 범위 밖 | — | 사유: 절차 |
| 14.8 | 안전하지 않은 네트워크 사용 교육 | protect | ⚠️ 일부 | `config:org.user_training` |  **한계:** 주제 구분 없음 |
| 14.9 | 역할별 교육 | protect | ⚠️ 일부 | `config:org.user_training` |  **한계:** 역할별 교육 수준 구분 없음 (조직 단위) |
| 15.1 | 서비스 제공자 목록 | identify | ✅ 표현 가능 | `field:asset.external.trust_level`, `relation:trusts` |  |
| 15.2 | 제공자 관리 정책 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 15.3 | 제공자 분류 | govern | ✅ 표현 가능 | `field:asset.external.trust_level` |  |
| 15.4 | 계약에 보안 요구사항 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 15.5 | 제공자 평가 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 15.6 | 제공자 모니터링 | govern | ➖ 범위 밖 | — | 사유: 탐지 |
| 15.7 | 제공자 연결 안전 해지 | protect | ✅ 표현 가능 | `relation:trusts`, `config:account.dormant` | 해지 후 남은 신뢰·계정 |
| 16.1 | 보안 개발 절차 | govern | ✅ 표현 가능 | `config:app.secure_development` |  |
| 16.2 | 취약점 접수·처리 절차 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 16.3 | 취약점 근본 원인 분석 | detect | ➖ 범위 밖 | — | 사유: 사후 |
| 16.4 | 외부 구성요소 목록 | identify | ✅ 표현 가능 | `relation:runs`, `field:asset.software.version` |  |
| 16.5 | 최신·신뢰 구성요소 사용 | protect | ✅ 표현 가능 | `field:asset.software.version` |  |
| 16.6 | 앱 취약점 심각도 체계 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 16.7 | 앱 인프라 표준 보안 설정 | protect | ✅ 표현 가능 | `config:host.os_hardening` |  |
| 16.8 | 운영·비운영 분리 | protect | ✅ 표현 가능 | `field:asset.groups`, `field:asset.data.environment` |  |
| 16.9 | 개발자 보안 교육 | protect | ✅ 표현 가능 | `config:app.secure_development` |  |
| 16.10 | 보안 설계 원칙 | protect | ✅ 표현 가능 | `config:app.secure_development` |  |
| 16.11 | 검증된 보안 모듈 사용 | protect | ✅ 표현 가능 | `config:app.secure_development` |  |
| 16.12 | 코드 수준 보안 점검 | protect | ✅ 표현 가능 | `config:app.secure_development` |  |
| 16.13 | 앱 침투 테스트 | detect | ➖ 범위 밖 | — | 사유: 절차 |
| 16.14 | 위협 모델링 | protect | ➖ 범위 밖 | — | 사유: 절차 |
| 17.1 | 사고 처리 담당자 | respond | ➖ 범위 밖 | — | 사유: 사후 |
| 17.2 | 사고 보고 연락처 | govern | ➖ 범위 밖 | — | 사유: 사후 |
| 17.3 | 사고 보고 절차 | govern | ➖ 범위 밖 | — | 사유: 사후 |
| 17.4 | 사고 대응 절차 | govern | ➖ 범위 밖 | — | 사유: 사후 |
| 17.5 | 역할과 책임 지정 | respond | ➖ 범위 밖 | — | 사유: 사후 |
| 17.6 | 대응 중 의사소통 수단 | respond | ➖ 범위 밖 | — | 사유: 사후 |
| 17.7 | 대응 훈련 | recover | ➖ 범위 밖 | — | 사유: 사후 |
| 17.8 | 사후 검토 | recover | ➖ 범위 밖 | — | 사유: 사후 |
| 17.9 | 사고 판단 기준 | recover | ➖ 범위 밖 | — | 사유: 사후 |
| 18.1 | 침투 테스트 프로그램 | govern | ➖ 범위 밖 | — | 사유: 절차 |
| 18.2 | 외부 침투 테스트 | detect | ➖ 범위 밖 | — | 사유: 절차 |
| 18.3 | 침투 테스트 결과 조치 | protect | ➖ 범위 밖 | — | 사유: 절차 |
| 18.4 | 보안 조치 검증 | protect | ➖ 범위 밖 | — | 사유: 절차 |
| 18.5 | 내부 침투 테스트 | detect | ➖ 범위 밖 | — | 사유: 절차 |
