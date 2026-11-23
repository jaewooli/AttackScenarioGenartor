# MITRE D3FEND 대조표 (WBS 1.6.3)

> 생성된 문서다. 원본 `src/scengen/ir/crosswalk_d3fend.yaml`을 고친 뒤
> `.venv/bin/scengen crosswalk d3fend --markdown > docs/crosswalk/d3fend.md`로 다시 만든다.

질문: **"이 방어 기법이 적용되어 있는지를 IR로 표현할 수 있는가?"**

- 기준: MITRE D3FEND 기법 271개 (전술별: Model 27, Harden 55, Detect 90, Isolate 57, Deceive 11, Evict 19, Restore 12)
- Model·Harden·Isolate 의 0·1단계는 개별 대조, 2단계는 상위 기법을 물려받음, Detect·Deceive·Evict·Restore 는 전술 기본값
- 상태: ✅ 표현 가능 127 · ⚠️ 일부 7 · ❌ 불가 0 · ➖ 범위 밖 137
- 통과 조건 (표현 불가 0): **통과**

## 대조 중 발견해서 보강한 빈틈

| 빈틈 | 보강 | 관련 기법 |
|---|---|---|
| 생체 인증을 인증 방식으로 표현할 수 없음 | auth.methods 에 biometric 추가 | D3-BAN |
| 토큰을 기기·연결에 묶는 설정 없음 | config auth.token_binding | D3-TB |
| 자격증명 주기적 교체 없음 | config auth.credential_rotation | D3-CRO |
| 인증서 고정 없음 | config transport.certificate_pinning | D3-CP |
| 산업 제어기의 운전 모드 잠금·변수 쓰기 제한 없음 | config ot.operating_mode_locked, ot.variable_write_restricted | D3-OPR, D3-OVAR |

## 범위 밖 사유 코드

| 코드 | 의미 |
|---|---|
| 탐지 | 탐지·분석 기법. 현재 모델은 탐지와 시간을 다루지 않는다 |
| 기만 | 미끼 기법. 주목적이 탐지이며 현재 모델 밖 |
| 사후 | 침입 이후 제거·복구 기법. 공격 단계의 성공 여부를 바꾸지 않는다 |
| 물리 | 물리 환경(방사선, 외함, 출입) 보호. 물리 접근은 공격자 시작점으로만 표현한다 |

## 기법별 결과

| 기법 | 이름 | 전술 | 단계 | 근거 | 상태 | IR 표현 | 설명 |
|---|---|---|---|---|---|---|---|
| D3-OAM | Operational Activity Mapping | Model | 0 | 개별 | ⚠️ 일부 | `field:context.organization`, `relation:depends_on` | 조직 활동 지도 **한계:** 조직 활동·업무 절차는 업무 서비스와 의존 관계로만 근사 |
| D3-OM | Organization Mapping | Model | 1 | 개별 | ✅ 표현 가능 | `relation:member_of`, `field:asset.identity.kind` | 사람·역할·그룹 |
| D3-ORA | Operational Risk Assessment | Model | 1 | 개별 | ✅ 표현 가능 | `field:impact_goal.impact`, `field:asset.criticality` | 위험 평가 결과가 곧 목표의 영향도 |
| D3-ODM | Operational Dependency Mapping | Model | 1 | 개별 | ✅ 표현 가능 | `relation:depends_on` | 업무 의존 |
| D3-AM | Access Modeling | Model | 1 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `relation:authenticates_to` | 접근 모델 |
| D3-NM | Network Mapping | Model | 0 | 개별 | ✅ 표현 가능 | `field:asset.groups`, `relation:reaches` | 네트워크 지도 |
| D3-PLM | Physical Link Mapping | Model | 1 | 개별 | ⚠️ 일부 | `relation:reaches` | 물리 연결 **한계:** 케이블·스위치 포트 단위 물리 연결은 표현하지 않고 논리 도달로 근사 |
| D3-DPLM | Direct Physical Link Mapping | Model | 2 | 상위(D3-PLM) | ⚠️ 일부 | `relation:reaches` | 물리 연결 **한계:** 케이블·스위치 포트 단위 물리 연결은 표현하지 않고 논리 도달로 근사 |
| D3-APLM | Active Physical Link Mapping | Model | 2 | 상위(D3-PLM) | ⚠️ 일부 | `relation:reaches` | 물리 연결 **한계:** 케이블·스위치 포트 단위 물리 연결은 표현하지 않고 논리 도달로 근사 |
| D3-NVA | Network Vulnerability Assessment | Model | 1 | 개별 | ✅ 표현 가능 | `config:org.vulnerability_scanning`, `config:host.patch_currency` |  |
| D3-NTPM | Network Traffic Policy Mapping | Model | 1 | 개별 | ✅ 표현 가능 | `relation:reaches` | 트래픽 정책 = 도달 규칙 |
| D3-LLM | Logical Link Mapping | Model | 1 | 개별 | ✅ 표현 가능 | `relation:reaches`, `relation:routes_via` | 논리 연결 |
| D3-PLLM | Passive Logical Link Mapping | Model | 2 | 상위(D3-LLM) | ✅ 표현 가능 | `relation:reaches`, `relation:routes_via` | 논리 연결 |
| D3-ALLM | Active Logical Link Mapping | Model | 2 | 상위(D3-LLM) | ✅ 표현 가능 | `relation:reaches`, `relation:routes_via` | 논리 연결 |
| D3-AI | Asset Inventory | Model | 0 | 개별 | ✅ 표현 가능 | `field:asset.role` | IR 자체가 자산 목록 |
| D3-SWI | Software Inventory | Model | 1 | 개별 | ✅ 표현 가능 | `relation:runs`, `field:asset.software.version` |  |
| D3-NNI | Network Node Inventory | Model | 1 | 개별 | ✅ 표현 가능 | `field:asset.role`, `field:asset.groups` | 네트워크 노드 |
| D3-HCI | Hardware Component Inventory | Model | 1 | 개별 | ⚠️ 일부 | `config:host.boot_integrity` | 하드웨어 구성요소 **한계:** 하드웨어 부품 단위 목록은 표현하지 않음 (펌웨어 무결성만) |
| D3-DI | Data Inventory | Model | 1 | 개별 | ✅ 표현 가능 | `field:asset.data.categories`, `relation:contains` |  |
| D3-CI | Configuration Inventory | Model | 1 | 개별 | ✅ 표현 가능 | `field:asset.config` | 설정 키 사전 |
| D3-AVE | Asset Vulnerability Enumeration | Model | 1 | 개별 | ✅ 표현 가능 | `field:asset.service+network_device.version`, `config:host.patch_currency` |  |
| D3-CIA | Container Image Analysis | Model | 2 | 상위(D3-AVE) | ✅ 표현 가능 | `field:asset.service+network_device.version`, `config:host.patch_currency` |  |
| D3-SYSM | System Mapping | Model | 0 | 개별 | ✅ 표현 가능 | `relation:hosts`, `relation:runs`, `relation:depends_on` |  |
| D3-SYSVA | System Vulnerability Assessment | Model | 1 | 개별 | ✅ 표현 가능 | `config:host.patch_currency`, `config:host.os_hardening` |  |
| D3-SYSDM | System Dependency Mapping | Model | 1 | 개별 | ✅ 표현 가능 | `relation:depends_on` |  |
| D3-SVCDM | Service Dependency Mapping | Model | 1 | 개별 | ✅ 표현 가능 | `relation:depends_on` |  |
| D3-DEM | Data Exchange Mapping | Model | 1 | 개별 | ⚠️ 일부 | `relation:depends_on`, `relation:contains` |  **한계:** 시스템 간 데이터 교환 흐름 엣지가 없음 (CIS 3.8과 같은 한계) |
| D3-SCH | Source Code Hardening | Harden | 0 | 개별 | ✅ 표현 가능 | `config:app.secure_development` | 소스 코드 강화 (하위 기법은 코드 수준이라 묶음 키로 표현) |
| D3-VTV | Variable Type Validation | Harden | 1 | 개별 | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-VI | Variable Initialization | Harden | 1 | 개별 | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-TL | Trusted Library | Harden | 1 | 개별 | ✅ 표현 가능 | `config:app.secure_development`, `field:asset.software.version` |  |
| D3-RN | Reference Nullification | Harden | 1 | 개별 | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-PV | Pointer Validation | Harden | 1 | 개별 | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-NPC | Null Pointer Checking | Harden | 2 | 상위(D3-PV) | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-MBSV | Memory Block Start Validation | Harden | 2 | 상위(D3-PV) | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-IRV | Integer Range Validation | Harden | 1 | 개별 | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-DLV | Domain Logic Validation | Harden | 1 | 개별 | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-OLV | Operational Logic Validation | Harden | 2 | 상위(D3-DLV) | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-CS | Credential Scrubbing | Harden | 1 | 개별 | ✅ 표현 가능 | `relation:stores` | 코드·설정에서 자격증명 제거 = stores 관계 없음 |
| D3-AA | Agent Authentication | Harden | 0 | 개별 | ✅ 표현 가능 | `config:auth.methods` |  |
| D3-TBA | Token-based Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:auth.methods` |  |
| D3-PWA | Password Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:auth.methods`, `config:auth.password_policy` |  |
| D3-MFA | Multi-factor Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:auth.mfa`, `config:auth.mfa_strength` |  |
| D3-CBAN | Certificate-based Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:auth.methods` |  |
| D3-BAN | Biometric Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:auth.methods` | auth.methods 의 biometric |
| D3-MH | Message Hardening | Harden | 0 | 개별 | ✅ 표현 가능 | `config:transport.encryption`, `config:transport.signing` |  |
| D3-TAAN | Transfer Agent Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:mail.sender_authentication` |  |
| D3-MENCR | Message Encryption | Harden | 1 | 개별 | ✅ 표현 가능 | `config:transport.encryption` |  |
| D3-MAN | Message Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:transport.signing` |  |
| D3-BMA | Bus Message Authentication | Harden | 2 | 상위(D3-MAN) | ✅ 표현 가능 | `config:transport.signing` |  |
| D3-CH | Credential Hardening | Harden | 0 | 개별 | ✅ 표현 가능 | `config:auth.password_policy`, `config:auth.credential_rotation` |  |
| D3-TB | Token Binding | Harden | 1 | 개별 | ✅ 표현 가능 | `config:auth.token_binding` |  |
| D3-SPP | Strong Password Policy | Harden | 1 | 개별 | ✅ 표현 가능 | `config:auth.password_policy` |  |
| D3-CDP | Change Default Password | Harden | 2 | 상위(D3-SPP) | ✅ 표현 가능 | `config:auth.password_policy` |  |
| D3-CRO | Credential Rotation | Harden | 1 | 개별 | ✅ 표현 가능 | `config:auth.credential_rotation` |  |
| D3-PR | Password Rotation | Harden | 2 | 상위(D3-CRO) | ✅ 표현 가능 | `config:auth.credential_rotation` |  |
| D3-OTP | One-time Password | Harden | 2 | 상위(D3-CRO) | ✅ 표현 가능 | `config:auth.credential_rotation` |  |
| D3-CERO | Certificate Rotation | Harden | 2 | 상위(D3-CRO) | ✅ 표현 가능 | `config:auth.credential_rotation` |  |
| D3-CP | Certificate Pinning | Harden | 1 | 개별 | ✅ 표현 가능 | `config:transport.certificate_pinning` |  |
| D3-PH | Platform Hardening | Harden | 0 | 개별 | ✅ 표현 가능 | `config:host.os_hardening` |  |
| D3-RH | Radiation Hardening | Harden | 1 | 개별 | ➖ 범위 밖 | — | 사유: 물리 |
| D3-EMH | Electromagnetic Radiation Hardening | Harden | 2 | 상위(D3-RH) | ➖ 범위 밖 | — | 사유: 물리 |
| D3-RFS | RF Shielding | Harden | 2 | 상위(D3-RH) | ➖ 범위 밖 | — | 사유: 물리 |
| D3-DENCR | Disk Encryption | Harden | 1 | 개별 | ✅ 표현 가능 | `field:relation.contains.encrypted` | 디스크 암호화 = 호스트가 담은 데이터의 암호화 |
| D3-TBI | TPM Boot Integrity | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.boot_integrity` |  |
| D3-HBWP | Hardware-based Write Protection | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.boot_integrity` |  |
| D3-BA | Bootloader Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.boot_integrity` |  |
| D3-SCP | System Configuration Permissions | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.registry_permissions_restricted`, `relation:has_permission` |  |
| D3-FE | File Encryption | Harden | 1 | 개별 | ✅ 표현 가능 | `field:relation.contains.encrypted` |  |
| D3-SU | Software Update | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.patch_currency` |  |
| D3-DLIC | Driver Load Integrity Checking | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.code_signing_enforced` |  |
| D3-PEH | Physical Enclosure Hardening | Harden | 1 | 개별 | ➖ 범위 밖 | — | 사유: 물리 |
| D3-AH | Application Hardening | Harden | 0 | 개별 | ✅ 표현 가능 | `config:host.exploit_protection`, `config:app.secure_development` |  |
| D3-EHPV | Exception Handler Pointer Validation | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.exploit_protection` | 메모리 보호 기법들은 묶음 키로 표현 |
| D3-ACH | Application Configuration Hardening | Harden | 1 | 개별 | ✅ 표현 가능 | `field:asset.config` |  |
| D3-DRA | Disable Remote Access | Harden | 2 | 상위(D3-ACH) | ✅ 표현 가능 | `field:asset.config` |  |
| D3-PAN | Pointer Authentication | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.exploit_protection` |  |
| D3-DCE | Dead Code Elimination | Harden | 1 | 개별 | ✅ 표현 가능 | `config:app.secure_development` |  |
| D3-PSEP | Process Segment Execution Prevention | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.exploit_protection` |  |
| D3-SAOR | Segment Address Offset Randomization | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.exploit_protection` |  |
| D3-SFCV | Stack Frame Canary Validation | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.exploit_protection` |  |
| D3-CFI | Control Flow Integrity | Harden | 1 | 개별 | ✅ 표현 가능 | `config:host.exploit_protection` |  |
| D3-NTA | Network Traffic Analysis | Detect | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-RTA | RPC Traffic Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-IPCTA | IPC Traffic Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-RTSD | Remote Terminal Session Detection | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-RPA | Relay Pattern Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PMAD | Protocol Metadata Anomaly Detection | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PHDURA | Per Host Download-Upload Ratio Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-DNSTA | DNS Traffic Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FC | File Carving | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-APCA | Application Protocol Command Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-RFUM | Remote Firmware Update Monitoring | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-ISVA | Inbound Session Volume Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-NTCD | Network Traffic Community Deviation | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-CSPP | Client-server Payload Profiling | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-ANAA | Administrative Network Activity Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-CAA | Connection Attempt Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-NTSA | Network Traffic Signature Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-BSE | Byte Sequence Emulation | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-CA | Certificate Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PCA | Passive Certificate Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-ACA | Active Certificate Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-MA | Message Analysis | Detect | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SRA | Sender Reputation Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SMRA | Sender MTA Reputation Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PA | Process Analysis | Detect | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FAPA | File Access Pattern Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-DQSA | Database Query String Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SSC | Shadow Stack Comparisons | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SEA | Script Execution Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PSA | Process Spawn Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PLA | Process Lineage Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-IBCA | Indirect Branch Call Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SCA | System Call Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FCA | File Creation Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PSMD | Process Self-Modification Detection | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PCSV | Process Code Segment Verification | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PHAM | Physical Access Monitoring | Detect | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-VS | Video Surveillance | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PSM | Proximity Sensor Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-MSM | Motion Sensor Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-ELM | Electronic Lock Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FA | File Analysis | Detect | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FH | File Hashing | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FCOA | File Content Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FCR | File Content Rules | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-EFA | Emulated File Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-DA | Dynamic Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-UBA | User Behavior Analysis | Detect | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-DAM | Domain Account Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SDA | Session Duration Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-UGLPA | User Geolocation Logon Pattern Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-WSAA | Web Session Activity Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-JFAPA | Job Function Access Pattern Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-CCSA | Credential Compromise Scope Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-AZET | Authorization Event Thresholding | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-ANET | Authentication Event Thresholding | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-RAPA | Resource Access Pattern Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-LAM | Local Account Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-UDTA | User Data Transfer Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-ID | Identifier Analysis | Detect | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-UA | URL Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-IRA | Identifier Reputation Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-URA | URL Reputation Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-IPRA | IP Reputation Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FHRA | File Hash Reputation Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-DNRA | Domain Name Reputation Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-IAA | Identifier Activity Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-HD | Homoglyph Detection | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PM | Platform Monitoring | Detect | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FEMC | Firmware Embedded Monitoring Code | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-APM | Application Performance Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-AEM | Application Exception Monitoring | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-OSM | Operating System Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-USICA | User Session Init Config Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SICA | System Init Config Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SFA | System File Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SBV | Service Binary Verification | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SDM | System Daemon Monitoring | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SJA | Scheduled Job Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-MBT | Memory Boundary Tracking | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-IDA | Input Device Analysis | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-EHB | Endpoint Health Beacon | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PUM | Platform Uptime Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-OPM | Operational Process Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FV | Firmware Verification | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-SFV | System Firmware Verification | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-PFV | Peripheral Firmware Verification | Detect | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FBA | Firmware Behavior Analysis | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-FIM | File Integrity Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-OMM | Operating Mode Monitoring | Detect | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 탐지 |
| D3-AMED | Access Mediation | Isolate | 0 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `relation:reaches` |  |
| D3-SCF | System Call Filtering | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:host.application_isolation` |  |
| D3-LFAM | Local File Access Mediation | Isolate | 2 | 상위(D3-SCF) | ✅ 표현 가능 | `config:host.application_isolation` |  |
| D3-PAM | Physical Access Mediation | Isolate | 1 | 개별 | ➖ 범위 밖 | — | 사유: 물리 |
| D3-EPL | Physical Locking | Isolate | 2 | 상위(D3-PAM) | ➖ 범위 밖 | — | 사유: 물리 |
| D3-OPR | Operating Mode Restriction | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:ot.operating_mode_locked` |  |
| D3-OVAR | OT Variable Access Restriction | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:ot.variable_write_restricted` |  |
| D3-NRAM | Network Resource Access Mediation | Isolate | 1 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `relation:authenticates_to` |  |
| D3-WSAM | Web Session Access Mediation | Isolate | 2 | 상위(D3-NRAM) | ✅ 표현 가능 | `relation:has_permission`, `relation:authenticates_to` |  |
| D3-PBWSAM | Proxy-based Web Server Access Mediation | Isolate | 2 | 상위(D3-NRAM) | ✅ 표현 가능 | `relation:has_permission`, `relation:authenticates_to` |  |
| D3-EBWSAM | Endpoint-based Web Server Access Mediation | Isolate | 2 | 상위(D3-NRAM) | ✅ 표현 가능 | `relation:has_permission`, `relation:authenticates_to` |  |
| D3-RFAM | Remote File Access Mediation | Isolate | 2 | 상위(D3-NRAM) | ✅ 표현 가능 | `relation:has_permission`, `relation:authenticates_to` |  |
| D3-NAM | Network Access Mediation | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:network.port_access_control`, `relation:reaches` |  |
| D3-RAM | Routing Access Mediation | Isolate | 2 | 상위(D3-NAM) | ✅ 표현 가능 | `config:network.port_access_control`, `relation:reaches` |  |
| D3-LAMED | LAN Access Mediation | Isolate | 2 | 상위(D3-NAM) | ✅ 표현 가능 | `config:network.port_access_control`, `relation:reaches` |  |
| D3-IOPR | IO Port Restriction | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:host.removable_media_restricted` |  |
| D3-CTS | Credential Transmission Scoping | Isolate | 1 | 개별 | ✅ 표현 가능 | `relation:grants`, `field:asset.credential.scope` | 자격증명이 통하는 범위 |
| D3-CF | Content Filtering | Isolate | 0 | 개별 | ✅ 표현 가능 | `config:mail.content_filtering`, `config:network.application_filtering`, `config:network.web_filtering` |  |
| D3-CV | Content Validation | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:network.application_filtering` |  |
| D3-FFV | File Format Verification | Isolate | 2 | 상위(D3-CV) | ✅ 표현 가능 | `config:network.application_filtering` |  |
| D3-FMVV | File Metadata Value Verification | Isolate | 2 | 상위(D3-CV) | ✅ 표현 가능 | `config:network.application_filtering` |  |
| D3-FMBV | File Magic Byte Verification | Isolate | 2 | 상위(D3-CV) | ✅ 표현 가능 | `config:network.application_filtering` |  |
| D3-FMCV | File Metadata Consistency Validation | Isolate | 2 | 상위(D3-CV) | ✅ 표현 가능 | `config:network.application_filtering` |  |
| D3-FISV | File Internal Structure Verification | Isolate | 2 | 상위(D3-CV) | ✅ 표현 가능 | `config:network.application_filtering` |  |
| D3-FCDC | File Content Decompression Checking | Isolate | 2 | 상위(D3-CV) | ✅ 표현 가능 | `config:network.application_filtering` |  |
| D3-CQ | Content Quarantine | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:mail.content_filtering` |  |
| D3-CM | Content Modification | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:mail.content_filtering` |  |
| D3-CNS | Content Substitution | Isolate | 2 | 상위(D3-CM) | ✅ 표현 가능 | `config:mail.content_filtering` |  |
| D3-CNR | Content Rebuild | Isolate | 2 | 상위(D3-CM) | ✅ 표현 가능 | `config:mail.content_filtering` |  |
| D3-CFC | Content Format Conversion | Isolate | 2 | 상위(D3-CM) | ✅ 표현 가능 | `config:mail.content_filtering` |  |
| D3-CNE | Content Excision | Isolate | 2 | 상위(D3-CM) | ✅ 표현 가능 | `config:mail.content_filtering` |  |
| D3-EI | Execution Isolation | Isolate | 0 | 개별 | ✅ 표현 가능 | `config:host.application_isolation`, `config:host.execution_control` |  |
| D3-KBPI | Kernel-based Process Isolation | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:host.application_isolation` |  |
| D3-HBPI | Hardware-based Process Isolation | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:host.application_isolation` |  |
| D3-EDL | Executable Denylisting | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:host.execution_control` |  |
| D3-EAL | Executable Allowlisting | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:host.execution_control` |  |
| D3-ABPI | Application-based Process Isolation | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:host.application_isolation` |  |
| D3-APA | Access Policy Administration | Isolate | 0 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `relation:member_of` |  |
| D3-UGPH | User Group Permissions | Isolate | 1 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `relation:member_of` |  |
| D3-UAP | User Account Permissions | Isolate | 1 | 개별 | ✅ 표현 가능 | `relation:has_permission` |  |
| D3-LFP | Local File Permissions | Isolate | 1 | 개별 | ⚠️ 일부 | `relation:has_permission` |  **한계:** 파일 단위 권한은 데이터·서비스 노드 단위로 근사 (ATT&CK M1022와 같은 한계) |
| D3-DTP | Domain Trust Policy | Isolate | 1 | 개별 | ✅ 표현 가능 | `relation:trusts` |  |
| D3-NI | Network Isolation | Isolate | 0 | 개별 | ✅ 표현 가능 | `relation:reaches`, `field:asset.groups` |  |
| D3-NTF | Network Traffic Filtering | Isolate | 1 | 개별 | ✅ 표현 가능 | `relation:reaches`, `config:host.firewall` |  |
| D3-OTF | Outbound Traffic Filtering | Isolate | 2 | 상위(D3-NTF) | ✅ 표현 가능 | `relation:reaches`, `config:host.firewall` |  |
| D3-ITF | Inbound Traffic Filtering | Isolate | 2 | 상위(D3-NTF) | ✅ 표현 가능 | `relation:reaches`, `config:host.firewall` |  |
| D3-EF | Email Filtering | Isolate | 2 | 상위(D3-NTF) | ✅ 표현 가능 | `relation:reaches`, `config:host.firewall` |  |
| D3-ET | Encrypted Tunnels | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:transport.encryption` |  |
| D3-DNL | Directional Network Link | Isolate | 1 | 개별 | ✅ 표현 가능 | `relation:reaches` | 한 방향 도달 규칙 |
| D3-DNSDL | DNS Denylisting | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:network.web_filtering` |  |
| D3-RRID | Reverse Resolution IP Denylisting | Isolate | 2 | 상위(D3-DNSDL) | ✅ 표현 가능 | `config:network.web_filtering` |  |
| D3-FRIDL | Forward Resolution IP Denylisting | Isolate | 2 | 상위(D3-DNSDL) | ✅ 표현 가능 | `config:network.web_filtering` |  |
| D3-FRDDL | Forward Resolution Domain Denylisting | Isolate | 2 | 상위(D3-DNSDL) | ✅ 표현 가능 | `config:network.web_filtering` |  |
| D3-HDL | Homoglyph Denylisting | Isolate | 2 | 상위(D3-DNSDL) | ✅ 표현 가능 | `config:network.web_filtering` |  |
| D3-HDDL | Hierarchical Domain Denylisting | Isolate | 2 | 상위(D3-DNSDL) | ✅ 표현 가능 | `config:network.web_filtering` |  |
| D3-DNSAL | DNS Allowlisting | Isolate | 1 | 개별 | ✅ 표현 가능 | `config:network.trusted_dns`, `config:network.web_filtering` |  |
| D3-BDI | Broadcast Domain Isolation | Isolate | 1 | 개별 | ✅ 표현 가능 | `field:asset.groups`, `config:network.legacy_name_resolution` |  |
| D3-DO | Decoy Object | Deceive | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-DUC | Decoy User Credential | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-DST | Decoy Session Token | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-DPR | Decoy Public Release | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-DP | Decoy Persona | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-DNR | Decoy Network Resource | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-DF | Decoy File | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-DE | Decoy Environment | Deceive | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-SHN | Standalone Honeynet | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-IHN | Integrated Honeynet | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-CHN | Connected Honeynet | Deceive | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 기만 |
| D3-PE | Process Eviction | Evict | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-ST | Session Termination | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-PT | Process Termination | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-PS | Process Suspension | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-HS | Host Shutdown | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-HR | Host Reboot | Evict | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-OE | Object Eviction | Evict | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RKD | Registry Key Deletion | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-FEV | File Eviction | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-ER | Email Removal | Evict | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-DRT | Domain Registration Takedown | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-DKF | Disk Formatting | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-DKP | Disk Partitioning | Evict | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-DKE | Disk Erasure | Evict | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-DNSCE | DNS Cache Eviction | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-CE | Credential Eviction | Evict | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-CR | Credential Revocation | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-ANCI | Authentication Cache Invalidation | Evict | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-AL | Account Locking | Evict | 1 | 개별 | ✅ 표현 가능 | `config:auth.lockout` | 계정 잠금은 반복 시도를 막는 예방 효과도 있음 |
| D3-RO | Restore Object | Restore | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RS | Restore Software | Restore | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RF | Restore File | Restore | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RE | Restore Email | Restore | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RDI | Restore Disk Image | Restore | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RD | Restore Database | Restore | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RC | Restore Configuration | Restore | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RA | Restore Access | Restore | 0 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RUAA | Restore User Account Access | Restore | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-ULA | Unlock Account | Restore | 2 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RNA | Restore Network Access | Restore | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
| D3-RIC | Reissue Credential | Restore | 1 | 전술 기본값 | ➖ 범위 밖 | — | 사유: 사후 |
