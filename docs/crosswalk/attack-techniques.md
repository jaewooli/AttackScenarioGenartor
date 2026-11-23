# MITRE ATT&CK 공격 기법 대조표 (WBS 1.6.1)

> 생성된 문서다. 직접 고치지 말고 `src/scengen/ir/technique_map.yaml`을 고친 뒤
> `.venv/bin/scengen techniques --markdown > docs/crosswalk/attack-techniques.md`로 다시 만든다.

질문: **"이 기법이 가능하려면 필요한 인프라 상태를 IR로 표현할 수 있는가?"**
추상 수준만 다룬다. 전제가 되는 인프라 상태만 적고 실행 방법은 적지 않는다.

- 기준: MITRE ATT&CK Enterprise (attack-stix-data), ATT&CK v20.1, 상위 기법 227개
- 개별 대조 89개, 나머지는 전술별 기본 분류
- 역할: 상태 전이 66 · 목표(피해) 15 · 발견 33 · 거점 내 행위 28 · 상태 불변 64 · 공격 전 21
- 상태: ✅ 표현 가능 207 · ⚠️ 일부 11 · ❌ 불가 0 · ➖ 범위 밖 9
- 통과 조건 (표현 불가 0): **통과**

## 대조 중 발견해서 보강한 빈틈

| 빈틈 | 보강 | 관련 기법 |
|---|---|---|
| 여러 자산에 한꺼번에 적용되는 정책 객체가 없음 | asset type policy + manages(정책 → 적용 대상) | T1484, T1037 |
| 웹·SaaS 서비스 세션을 표현할 수 없음 (세션이 서버에만 붙음) | session 도착 노드에 service 허용 | T1185, T1539 |
| 다중 인증 방식의 강도 구분 없음 | config auth.mfa_strength | T1111, T1621 |
| 클라우드 저장소 공개 여부를 표현할 수 없음 | access.anonymous 를 data_store 에도 허용 | T1530 |
| 클라우드 메타데이터 서비스 보호 설정 없음 | config host.metadata_service_protection | T1552 |
| Kerberos 관련 계정 속성 없음 | config account.service_principal, account.kerberos_preauth | T1558 |
| 컨테이너 설정 없음 | config container.privileged, container.host_mounts, container.service_account_token | T1611 |
| 무선 네트워크 구간을 표현할 수 없음 | group kind wireless | T1669 |
| 대규모 트래픽 방어 설정 없음 | config network.ddos_protection | T1498, T1499 |
| 방어 무력화 상태를 공격자 상태로 표현할 수 없음 (IR이 아니라 공격자 상태 모델의 빈틈) | P2에서 결정 (attacker-state.md 후보) | — |

## 전술별 기본 분류

| 전술 | 역할 | 상태 | IR 표현 | 설명 |
|---|---|---|---|---|
| discovery | 발견 | ✅ 표현 가능 | `field:attacker_profile.knowledge` | 거점에서 닿는 범위의 정보를 얻음. uninformed 변형에서 knows 사실로 반영 |
| execution | 거점 내 행위 | ✅ 표현 가능 | `relation:runs` | 거점 안에서 코드를 실행하는 수단. 원격 실행은 원격 서비스(T1021)와 같은 조건(도달 + 로그인 가능) |
| persistence | 상태 불변 | ✅ 표현 가능 | — | 단조성 가정상 이미 얻은 상태를 유지하는 행위는 상태를 바꾸지 않음. 시간·탐지 모델이 생기면 다시 봄 |
| stealth | 상태 불변 | ✅ 표현 가능 | — | 탐지를 피하는 행위. 탐지는 현재 모델 밖 |
| defense-impairment | 상태 불변 | ✅ 표현 가능 | — | 방어를 끄는 행위. 방어 설정 자체는 IR에 있으나, "방어를 무력화한 상태"는 공격자 상태 후보 (P2에서 결정) |
| command-and-control | 상태 불변 | ✅ 표현 가능 | `relation:reaches` | 외부와의 통신 경로. 외부로 닿는 reaches로 표현 (egress 변형과 같은 조건) |
| reconnaissance | 공격 전 | ✅ 표현 가능 | `field:attacker_profile.knowledge`, `config:org.attack_surface_management` | 공격 전 정보 수집. 지식 변형과 외부 노출 관리 키로 표현 |
| resource-development | 공격 전 | ➖ 범위 밖 | — | 사유: 공격자 쪽 준비 행위. 대상 인프라 상태와 무관 |

## 개별 대조 (공격자 상태를 바꾸거나 피해를 내는 기법)

사용 기록 = 이 기법을 쓴 것으로 ATT&CK에 기록된 그룹·소프트웨어·캠페인 관계 수.

| 기법 | 이름 | 사용 기록 | 역할 | 상태 | IR 표현 | 설명 |
|---|---|---|---|---|---|---|
| [T1005](https://attack.mitre.org/techniques/T1005) | Data from Local System | 236 | 상태 전이 | ✅ 표현 가능 | `relation:hosts`, `relation:contains` | 서버 위 저장소의 데이터 |
| [T1041](https://attack.mitre.org/techniques/T1041) | Exfiltration Over C2 Channel | 211 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `config:network.dlp`, `field:attacker_profile.egress` | 외부로 닿는 경로 + 유출 통제 |
| [T1055](https://attack.mitre.org/techniques/T1055) | Process Injection | 88 | 상태 전이 | ✅ 표현 가능 | `relation:runs`, `config:host.privileged_process_protection`, `config:host.behavior_prevention` | 다른 계정으로 도는 프로세스 |
| [T1190](https://attack.mitre.org/techniques/T1190) | Exploit Public-Facing Application | 77 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `field:asset.service+network_device.version`, `config:app.secure_development`, `config:host.patch_currency` | 외부에서 닿는 서비스의 취약점 |
| [T1078](https://attack.mitre.org/techniques/T1078) | Valid Accounts | 68 | 상태 전이 | ✅ 표현 가능 | `relation:authenticates_to`, `relation:grants`, `config:account.dormant`, `config:auth.mfa` | 유효한 계정으로 로그인 |
| [T1189](https://attack.mitre.org/techniques/T1189) | Drive-by Compromise | 45 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `config:network.web_filtering`, `config:host.exploit_protection`, `config:org.user_training` | 사용자 단말의 웹 접속 |
| [T1068](https://attack.mitre.org/techniques/T1068) | Exploitation for Privilege Escalation | 44 | 상태 전이 | ✅ 표현 가능 | `config:host.patch_currency`, `field:asset.host.os`, `config:host.exploit_protection` | 호스트 취약점 |
| [T1133](https://attack.mitre.org/techniques/T1133) | External Remote Services | 43 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `relation:authenticates_to`, `config:auth.mfa`, `field:asset.role` | 외부에서 닿는 원격 접속 서비스(VPN 등) |
| [T1555](https://attack.mitre.org/techniques/T1555) | Credentials from Password Stores | 42 | 상태 전이 | ✅ 표현 가능 | `relation:stores` | 비밀번호 저장소 (stores.location) |
| [T1020](https://attack.mitre.org/techniques/T1020) | Automated Exfiltration | 32 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `config:network.dlp` | 자동 유출 (경로 조건 동일) |
| [T1539](https://attack.mitre.org/techniques/T1539) | Steal Web Session Cookie | 30 | 상태 전이 | ✅ 표현 가능 | `relation:session` | 웹·SaaS 서비스 세션 (session → service) |
| [T1091](https://attack.mitre.org/techniques/T1091) | Replication Through Removable Media | 28 | 상태 전이 | ✅ 표현 가능 | `config:host.removable_media_restricted`, `field:attacker_profile.start` | 이동식 매체 |
| [T1040](https://attack.mitre.org/techniques/T1040) | Network Sniffing | 28 | 상태 전이 | ✅ 표현 가능 | `field:asset.groups`, `config:transport.encryption` | 같은 구간 + 암호화되지 않은 통신 |
| [T1110](https://attack.mitre.org/techniques/T1110) | Brute Force | 26 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `config:auth.password_policy`, `config:auth.lockout`, `config:auth.mfa` | 로그인 서비스 + 비밀번호 정책·잠금·다중 인증 |
| [T1210](https://attack.mitre.org/techniques/T1210) | Exploitation of Remote Services | 26 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `field:asset.service+network_device.version`, `config:host.patch_currency` | 내부 서비스 취약점 |
| [T1025](https://attack.mitre.org/techniques/T1025) | Data from Removable Media | 24 | 상태 전이 | ✅ 표현 가능 | `config:host.removable_media_restricted` | 이동식 매체 |
| [T1134](https://attack.mitre.org/techniques/T1134) | Access Token Manipulation | 23 | 상태 전이 | ✅ 표현 가능 | `relation:session`, `relation:runs`, `config:host.privileged_process_protection` | 같은 호스트의 다른 주체 세션·프로세스 |
| [T1030](https://attack.mitre.org/techniques/T1030) | Data Transfer Size Limits | 21 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `config:network.dlp` | 분할 전송 (경로 조건 동일) |
| [T1003](https://attack.mitre.org/techniques/T1003) | OS Credential Dumping | 20 | 상태 전이 | ✅ 표현 가능 | `relation:session`, `relation:runs`, `relation:stores`, `config:host.credential_protection` | 호스트의 세션·서비스 계정·저장된 자격증명 + 보호 기능 |
| [T1567](https://attack.mitre.org/techniques/T1567) | Exfiltration Over Web Service | 18 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `config:network.web_filtering`, `config:network.dlp` | 외부 웹 서비스로 가는 경로 |
| [T1029](https://attack.mitre.org/techniques/T1029) | Scheduled Transfer | 18 | 상태 전이 | ✅ 표현 가능 | `relation:reaches` | 예약 전송 (경로 조건 동일) |
| [T1185](https://attack.mitre.org/techniques/T1185) | Browser Session Hijacking | 16 | 상태 전이 | ✅ 표현 가능 | `relation:session` | 브라우저 세션 → 웹 서비스 세션 |
| [T1199](https://attack.mitre.org/techniques/T1199) | Trusted Relationship | 15 | 상태 전이 | ✅ 표현 가능 | `relation:trusts`, `relation:reaches`, `relation:authenticates_to`, `field:asset.external.trust_level` | 협력사 연결과 신뢰 관계 |
| [T1528](https://attack.mitre.org/techniques/T1528) | Steal Application Access Token | 14 | 상태 전이 | ✅ 표현 가능 | `relation:stores`, `relation:grants`, `field:asset.credential.kind` | 저장된 토큰 |
| [T1039](https://attack.mitre.org/techniques/T1039) | Data from Network Shared Drive | 14 | 상태 전이 | ✅ 표현 가능 | `relation:contains`, `relation:has_permission` | 파일 공유 저장소 |
| [T1056](https://attack.mitre.org/techniques/T1056) | Input Capture | 12 | 상태 전이 | ✅ 표현 가능 | `relation:session` | 대화형 세션 |
| [T1072](https://attack.mitre.org/techniques/T1072) | Software Deployment Tools | 12 | 상태 전이 | ✅ 표현 가능 | `relation:manages`, `relation:has_permission` | 배포 도구 → 관리 대상 (R11) |
| [T1080](https://attack.mitre.org/techniques/T1080) | Taint Shared Content | 12 | 상태 전이 | ⚠️ 일부 | `relation:has_permission`, `relation:contains`, `relation:authenticates_to` | 공유 저장소 쓰기 권한 + 다른 사용자 접근 **한계:** 공유 콘텐츠를 실제로 누가 여는지는 로그인 가능 관계로만 근사 |
| [T1530](https://attack.mitre.org/techniques/T1530) | Data from Cloud Storage | 12 | 상태 전이 | ✅ 표현 가능 | `relation:contains`, `relation:has_permission`, `config:access.anonymous` | 클라우드 저장소 권한·공개 여부 |
| [T1566](https://attack.mitre.org/techniques/T1566) | Phishing | 11 | 상태 전이 | ✅ 표현 가능 | `config:org.user_training`, `config:network.web_filtering`, `relation:session`, `field:asset.role` | 사용자 단말·메일 서비스 + 사용자 교육 |
| [T1098](https://attack.mitre.org/techniques/T1098) | Account Manipulation | 10 | 상태 전이 | ✅ 표현 가능 | `relation:has_permission` | 계정 변경 권한 (reset_credential |
| [T1543](https://attack.mitre.org/techniques/T1543) | Create or Modify System Process | 9 | 상태 전이 | ✅ 표현 가능 | `relation:runs`, `relation:has_permission` | 시스템 서비스 + 실행 계정 + 수정 권한 |
| [T1111](https://attack.mitre.org/techniques/T1111) | Multi-Factor Authentication Interception | 9 | 상태 전이 | ✅ 표현 가능 | `config:auth.mfa`, `config:auth.mfa_strength` | 다중 인증 방식의 강도 |
| [T1557](https://attack.mitre.org/techniques/T1557) | Adversary-in-the-Middle | 9 | 상태 전이 | ✅ 표현 가능 | `config:transport.signing`, `config:transport.encryption`, `config:network.legacy_name_resolution` | 서명·암호화·이름 해석 설정 |
| [T1534](https://attack.mitre.org/techniques/T1534) | Internal Spearphishing | 9 | 상태 전이 | ✅ 표현 가능 | `relation:session`, `config:org.user_training` | 메일·협업 서비스 세션 + 사용자 교육 |
| [T1048](https://attack.mitre.org/techniques/T1048) | Exfiltration Over Alternative Protocol | 9 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `config:network.dlp` | 다른 프로토콜의 외부 경로 |
| [T1037](https://attack.mitre.org/techniques/T1037) | Boot or Logon Initialization Scripts | 8 | 상태 전이 | ✅ 표현 가능 | `field:asset.policy.kind`, `relation:manages`, `relation:has_permission` | 로그온 스크립트를 배포하는 정책 객체 + 수정 권한 |
| [T1552](https://attack.mitre.org/techniques/T1552) | Unsecured Credentials | 8 | 상태 전이 | ✅ 표현 가능 | `relation:stores`, `config:host.metadata_service_protection` | 파일·설정·메타데이터 서비스 속 자격증명 |
| [T1021](https://attack.mitre.org/techniques/T1021) | Remote Services | 8 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `relation:authenticates_to`, `config:auth.methods` | 원격 접속 서비스 + 로그인 가능 |
| [T1556](https://attack.mitre.org/techniques/T1556) | Modify Authentication Process | 7 | 상태 전이 | ✅ 표현 가능 | `field:asset.role`, `relation:has_permission` | 인증 서비스·신원 공급자에 대한 관리 권한 |
| [T1547](https://attack.mitre.org/techniques/T1547) | Boot or Logon Autostart Execution | 6 | 상태 전이 | ⚠️ 일부 | `relation:runs`, `relation:session`, `relation:has_permission` | 다른 사용자의 로그온 시 실행 **한계:** 자동 실행 위치 단위는 표현하지 않음 (세션 + 수정 권한으로 근사) |
| [T1114](https://attack.mitre.org/techniques/T1114) | Email Collection | 6 | 상태 전이 | ✅ 표현 가능 | `relation:contains`, `relation:has_permission`, `relation:session` | 메일 저장소 |
| [T1213](https://attack.mitre.org/techniques/T1213) | Data from Information Repositories | 6 | 상태 전이 | ✅ 표현 가능 | `relation:contains`, `relation:has_permission` | 업무 저장소(위키 |
| [T1195](https://attack.mitre.org/techniques/T1195) | Supply Chain Compromise | 5 | 상태 전이 | ⚠️ 일부 | `relation:manages`, `relation:depends_on`, `relation:trusts`, `field:asset.software.version` | 공급자·배포 경로 **한계:** 외부 공급자 내부의 상태는 표현 대상 밖. 공급 경로(관리·의존 관계)까지만 |
| [T1546](https://attack.mitre.org/techniques/T1546) | Event Triggered Execution | 5 | 상태 전이 | ⚠️ 일부 | `relation:runs`, `relation:has_permission` | 다른 계정으로 실행되는 이벤트 트리거 **한계:** 개별 트리거 설정은 표현하지 않음 (실행 계정과 수정 권한으로 근사) |
| [T1611](https://attack.mitre.org/techniques/T1611) | Escape to Host | 5 | 상태 전이 | ✅ 표현 가능 | `relation:hosts`, `config:container.privileged`, `config:container.host_mounts` | 컨테이너 → 노드 (hosts) + 컨테이너 설정 |
| [T1649](https://attack.mitre.org/techniques/T1649) | Steal or Forge Authentication Certificates | 5 | 상태 전이 | ⚠️ 일부 | `field:asset.role`, `relation:has_permission`, `relation:grants` | 인증서 발급 서비스 + 발급 권한 **한계:** 인증서 템플릿 단위의 세부 설정은 credential 노드와 권한으로 근사. 템플릿 노드 타입이 필요할 수 있음 (P2에서 판단) |
| [T1621](https://attack.mitre.org/techniques/T1621) | Multi-Factor Authentication Request Generation | 4 | 상태 전이 | ✅ 표현 가능 | `config:auth.mfa`, `config:auth.mfa_strength`, `config:org.user_training` | 푸시 방식 + 사용자 교육 |
| [T1187](https://attack.mitre.org/techniques/T1187) | Forced Authentication | 4 | 상태 전이 | ✅ 표현 가능 | `config:auth.methods`, `config:transport.signing`, `config:network.legacy_name_resolution`, `relation:reaches` | 인증 방식·서명·이름 해석 설정 |
| [T1537](https://attack.mitre.org/techniques/T1537) | Transfer Data to Cloud Account | 3 | 상태 전이 | ✅ 표현 가능 | `relation:has_permission`, `relation:trusts` | 클라우드 계정 간 권한·신뢰 |
| [T1659](https://attack.mitre.org/techniques/T1659) | Content Injection | 2 | 상태 전이 | ⚠️ 일부 | `relation:reaches`, `config:transport.encryption` | 통신 경로 중간 위치 **한계:** 공격자가 경로 중간(통신사 등)에 있는 상황은 시작점으로만 근사 |
| [T1669](https://attack.mitre.org/techniques/T1669) | Wi-Fi Networks | 2 | 상태 전이 | ✅ 표현 가능 | `field:group.kind`, `relation:reaches`, `field:attacker_profile.start` | 무선 구간(group kind wireless)과 그 구간의 도달 규칙 |
| [T1548](https://attack.mitre.org/techniques/T1548) | Abuse Elevation Control Mechanism | 2 | 상태 전이 | ✅ 표현 가능 | `config:host.elevation_prompt` | 권한 상승 확인 절차 |
| [T1053](https://attack.mitre.org/techniques/T1053) | Scheduled Task/Job | 2 | 상태 전이 | ✅ 표현 가능 | `relation:runs`, `relation:has_permission`, `field:asset.service+network_device.kind` | 예약 작업(kind scheduled_task) + 실행 계정 + 수정 권한 |
| [T1212](https://attack.mitre.org/techniques/T1212) | Exploitation for Credential Access | 2 | 상태 전이 | ✅ 표현 가능 | `field:asset.service+network_device.version`, `config:host.patch_currency` | 서비스 취약점 |
| [T1558](https://attack.mitre.org/techniques/T1558) | Steal or Forge Kerberos Tickets | 2 | 상태 전이 | ✅ 표현 가능 | `config:account.service_principal`, `config:account.kerberos_preauth`, `config:auth.password_policy`, `relation:has_permission` | Kerberos 계정 속성·비밀번호 정책·위임 권한(delegate) |
| [T1550](https://attack.mitre.org/techniques/T1550) | Use Alternate Authentication Material | 2 | 상태 전이 | ✅ 표현 가능 | `relation:grants`, `config:auth.methods` | 해시·티켓·토큰(credential) → 주체 |
| [T1200](https://attack.mitre.org/techniques/T1200) | Hardware Additions | 1 | 상태 전이 | ✅ 표현 가능 | `field:attacker_profile.start`, `config:host.removable_media_restricted` | 물리 접근은 공격자 시작점을 해당 구간으로 두어 표현 |
| [T1697](https://attack.mitre.org/techniques/T1697) | Steal Application Specific Passwords | 1 | 상태 전이 | ✅ 표현 가능 | `relation:grants`, `field:asset.credential.kind`, `config:auth.mfa` | 앱 전용 비밀번호 (다중 인증 우회 자격증명) |
| [T1484](https://attack.mitre.org/techniques/T1484) | Domain or Tenant Policy Modification | 0 | 상태 전이 | ✅ 표현 가능 | `field:asset.policy.kind`, `relation:manages`, `relation:has_permission` | 정책 객체에 대한 쓰기 권한 → 정책이 적용되는 대상 |
| [T1606](https://attack.mitre.org/techniques/T1606) | Forge Web Credentials | 0 | 상태 전이 | ✅ 표현 가능 | `relation:grants`, `relation:trusts`, `field:asset.credential.kind` | 서명 키(credential) → 신원 연동 |
| [T1563](https://attack.mitre.org/techniques/T1563) | Remote Service Session Hijacking | 0 | 상태 전이 | ✅ 표현 가능 | `relation:session` | 다른 주체의 원격 세션 |
| [T1602](https://attack.mitre.org/techniques/T1602) | Data from Configuration Repository | 0 | 상태 전이 | ✅ 표현 가능 | `field:asset.role`, `config:access.anonymous`, `config:auth.default_credentials` | 네트워크 장비 설정 저장소 |
| [T1011](https://attack.mitre.org/techniques/T1011) | Exfiltration Over Other Network Medium | 0 | 상태 전이 | ⚠️ 일부 | `field:group.kind`, `config:host.removable_media_restricted` | 다른 네트워크 매체 **한계:** 호스트에 달린 무선·블루투스 인터페이스 존재는 표현하지 않음 |
| [T1052](https://attack.mitre.org/techniques/T1052) | Exfiltration Over Physical Medium | 0 | 상태 전이 | ✅ 표현 가능 | `config:host.removable_media_restricted` | 물리 매체 |
| [T1700](https://attack.mitre.org/techniques/T1700) | AI-Enabled Exfiltration | 0 | 상태 전이 | ✅ 표현 가능 | `relation:reaches`, `config:network.dlp` | AI 서비스 경유 유출 (외부 경로 조건 동일) |
| [T1486](https://attack.mitre.org/techniques/T1486) | Data Encrypted for Impact | 87 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:contains`, `config:storage.immutable` | 데이터 암호화 (destroy/disrupt) + 백업 보호 |
| [T1489](https://attack.mitre.org/techniques/T1489) | Service Stop | 57 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:depends_on` | 서비스 중단 (disrupt) |
| [T1490](https://attack.mitre.org/techniques/T1490) | Inhibit System Recovery | 57 | 목표(피해) | ✅ 표현 가능 | `config:storage.immutable`, `config:storage.offsite`, `relation:contains` | 복구 수단(백업) 무력화 |
| [T1485](https://attack.mitre.org/techniques/T1485) | Data Destruction | 40 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:contains` | 데이터 파괴 (destroy) |
| [T1529](https://attack.mitre.org/techniques/T1529) | System Shutdown/Reboot | 32 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:depends_on` | 시스템 종료 (disrupt) |
| [T1657](https://attack.mitre.org/techniques/T1657) | Financial Theft | 28 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:has_permission` | 금전 권한 오용 (misuse) |
| [T1531](https://attack.mitre.org/techniques/T1531) | Account Access Removal | 6 | 목표(피해) | ✅ 표현 가능 | `relation:has_permission`, `field:impact_goal.harm` | 계정 접근 제거 (reset_credential 권한 → disrupt) |
| [T1495](https://attack.mitre.org/techniques/T1495) | Firmware Corruption | 3 | 목표(피해) | ✅ 표현 가능 | `config:host.boot_integrity` | 펌웨어 손상 |
| [T1498](https://attack.mitre.org/techniques/T1498) | Network Denial of Service | 3 | 목표(피해) | ✅ 표현 가능 | `config:network.ddos_protection`, `relation:depends_on` | 네트워크 서비스 거부 |
| [T1499](https://attack.mitre.org/techniques/T1499) | Endpoint Denial of Service | 3 | 목표(피해) | ✅ 표현 가능 | `config:network.ddos_protection`, `relation:depends_on` | 엔드포인트 서비스 거부 |
| [T1565](https://attack.mitre.org/techniques/T1565) | Data Manipulation | 2 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:contains` | 데이터 조작 (tamper) |
| [T1667](https://attack.mitre.org/techniques/T1667) | Email Bombing | 1 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:depends_on` | 메일함 마비 (disrupt) |
| [T1491](https://attack.mitre.org/techniques/T1491) | Defacement | 0 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:contains` | 공개 콘텐츠 변조 (tamper) |
| [T1496](https://attack.mitre.org/techniques/T1496) | Resource Hijacking | 0 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm` | 자원 탈취 (misuse) |
| [T1561](https://attack.mitre.org/techniques/T1561) | Disk Wipe | 0 | 목표(피해) | ✅ 표현 가능 | `field:impact_goal.harm`, `relation:hosts` | 디스크 삭제 (destroy) |
| [T1113](https://attack.mitre.org/techniques/T1113) | Screen Capture | 172 | 거점 내 행위 | ⚠️ 일부 | `relation:session` | 화면 캡처 **한계:** 화면·입력 내용은 데이터 노드 단위 밖 |
| [T1119](https://attack.mitre.org/techniques/T1119) | Automated Collection | 78 | 거점 내 행위 | ✅ 표현 가능 | — | 수집 자동화 |
| [T1560](https://attack.mitre.org/techniques/T1560) | Archive Collected Data | 57 | 거점 내 행위 | ✅ 표현 가능 | — | 압축·암호화 |
| [T1570](https://attack.mitre.org/techniques/T1570) | Lateral Tool Transfer | 55 | 거점 내 행위 | ✅ 표현 가능 | `relation:reaches` | 도달 경로만 필요 |
| [T1115](https://attack.mitre.org/techniques/T1115) | Clipboard Data | 46 | 거점 내 행위 | ⚠️ 일부 | `relation:session` | 클립보드 **한계:** 데이터 노드 단위 밖 |
| [T1125](https://attack.mitre.org/techniques/T1125) | Video Capture | 35 | 거점 내 행위 | ⚠️ 일부 | `relation:session` | 영상 **한계:** 데이터 노드 단위 밖 |
| [T1123](https://attack.mitre.org/techniques/T1123) | Audio Capture | 32 | 거점 내 행위 | ⚠️ 일부 | `relation:session` | 음성 **한계:** 데이터 노드 단위 밖 |
| [T1074](https://attack.mitre.org/techniques/T1074) | Data Staged | 10 | 거점 내 행위 | ✅ 표현 가능 | — | 수집한 데이터를 모으는 중간 단계 |
