# 플랫폼 설정 기준 (샘플) 대조표

> 생성된 문서다. 원본 `src/scengen/ir/crosswalk/platform-baselines.yaml`을 고친 뒤
> `.venv/bin/scengen crosswalk platform-baselines --markdown > docs/crosswalk/platform-baselines.md`로 다시 만든다.

질문: **개별 설정 키가 필요한 설정이 있는가?**

- 기준: 플랫폼 설정 기준 (샘플) 2026-11-21 — 아래 표본 규칙 참고
- 항목 124개: ✅ 표현 가능 100 · ⚠️ 일부 8 · ❌ 불가 0 · ➖ 범위 밖 16
- 통과 조건 (표현 불가 0): **통과**

> 표본 규칙 (재현 가능하도록 고정)
>   리눅스: DISA STIG Ubuntu 24.04 (ComplianceAsCode controls/stig_ubuntu2404.yml) 중 심각도 high(CAT I) 전부 16개
>   쿠버네티스: CIS Kubernetes Benchmark 1.9 (kube-bench cfg/cis-1.9/policies.yaml) 5장 정책 전부 35개. 원문은 CIS 라이선스라 번호와 자체 요약만 싣는다
>   AWS: Security Hub Foundational Security Best Practices 중 IAM, S3, EC2, KMS, EKS, Lambda, Secrets Manager, CloudTrail 통제 전부 69개
> 확보 실패: CIS Benchmarks 원문(등록 필요), DISA Windows STIG(사이트에서 자동 내려받기 불가), KISA 주요정보통신기반시설 가이드(공식 PDF 링크 미확보). 윈도우·국내 기준은 원문을 받으면 같은 방식으로 추가한다

## 대조 중 발견해서 보강한 빈틈

| 빈틈 | 보강 | 관련 항목 |
|---|---|---|
| 비밀번호가 비어 있는 계정을 표현할 수 없음 | config account.password_empty | linux:UBTU-24-300027, linux:UBTU-24-300028 |
| 컨테이너 보안 수준(Pod Security Standards 단계) 없음. 호스트 네임스페이스, root 실행, 권한 상승, 추가 권한(capability)을 하나로 묶는 표준 단계 | config container.pod_security_level | k8s:5.2.3, k8s:5.2.6, k8s:5.2.7, k8s:5.2.9 |
| 공개 저장소의 읽기/쓰기 구분 불가 (access.anonymous 는 참/거짓뿐) | has_permission 의 출발 노드에 external 허용 (external → 저장소, read/write) | aws:S3.2, aws:S3.3 |
| 사용하지 않는 자격증명(접근 키 등)과 공개된 키를 표현할 수 없음 | account.dormant, access.anonymous 의 applies_to 에 credential 추가 | aws:IAM.8, aws:KMS.5, aws:SecretsManager.3 |

## 범위 밖 사유 코드

| 코드 | 의미 |
|---|---|
| 물리 | 콘솔·물리 접근 전제. 물리 접근은 공격자 시작점으로만 표현한다 |
| 탐지 | 탐지·기록 무결성. 현재 모델 밖 |
| 가용성 | 장애 대비·이중화. 공격 성공 여부와 무관 |
| 위생 | 운영 정리 항목. 공격 경로를 바꾸지 않음 |

## 항목

| 항목 | 요약 | 판단 | 상태 | IR 표현 | 설명 |
|---|---|---|---|---|---|
| linux:UBTU-24-100030 | 평문 원격 접속 패키지 미설치 | 개별 | ✅ 표현 가능 | `relation:runs`, `config:transport.encryption` |  |
| linux:UBTU-24-100040 | 구식 원격 실행 서버 미설치 | 개별 | ✅ 표현 가능 | `relation:runs` |  |
| linux:UBTU-24-100050 | 파일 공유 서버 미설치 | 개별 | ✅ 표현 가능 | `relation:runs` |  |
| linux:UBTU-24-100800 | 암호화된 원격 접속 설치 | 개별 | ✅ 표현 가능 | `relation:runs`, `config:auth.methods` |  |
| linux:UBTU-24-100810 | 원격 접속 구간 암호화 | 개별 | ✅ 표현 가능 | `config:transport.encryption` |  |
| linux:UBTU-24-102000 | 단일 사용자 모드 진입 시 인증 | 범위밖 | ➖ 범위 밖 | — | 사유: 물리 |
| linux:UBTU-24-300022 | 원격 그래픽 연결 끄기 | 개별 | ✅ 표현 가능 | `relation:runs` |  |
| linux:UBTU-24-300025 | 그래픽 환경 재부팅 단축키 끄기 | 범위밖 | ➖ 범위 밖 | — | 사유: 물리 |
| linux:UBTU-24-300026 | 재부팅 단축키 끄기 | 범위밖 | ➖ 범위 밖 | — | 사유: 물리 |
| linux:UBTU-24-300027 | 빈 비밀번호 계정 금지 | 추가 | ✅ 표현 가능 | `config:account.password_empty` |  |
| linux:UBTU-24-300028 | 인증 모듈의 빈 비밀번호 허용 금지 | 추가 | ✅ 표현 가능 | `config:account.password_empty` |  |
| linux:UBTU-24-300031 | 원격 접속 자동 로그인 금지 | 개별 | ✅ 표현 가능 | `config:access.anonymous`, `relation:stores` | 자동 로그인 = 인증 없는 접근 또는 저장된 자격증명 |
| linux:UBTU-24-400370 | 인증서 인증 시 계정 매핑 | 묶음 | ✅ 표현 가능 | `config:auth.methods` |  |
| linux:UBTU-24-600030 | 검증된 암호 모듈 사용 | 묶음 | ✅ 표현 가능 | `config:transport.encryption` |  |
| linux:UBTU-24-600130 | 관리자 권한 그룹 최소화 | 개별 | ✅ 표현 가능 | `relation:member_of`, `relation:has_permission` |  |
| linux:UBTU-24-700400 | 지원되는 배포판 | 개별 | ✅ 표현 가능 | `config:host.patch_currency` |  |
| k8s:5.1.1 | 클러스터 관리자 역할 최소 사용 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `relation:member_of` |  |
| k8s:5.1.2 | 비밀 정보 접근 최소화 | 개별 | ✅ 표현 가능 | `relation:has_permission` | credential 에 대한 read |
| k8s:5.1.3 | 와일드카드 권한 최소화 | 묶음 | ✅ 표현 가능 | `relation:has_permission` | 와일드카드는 어댑터가 펼쳐서 권한 엣지로 |
| k8s:5.1.4 | 파드 생성 권한 최소화 | 개별 | ✅ 표현 가능 | `relation:has_permission` | 네임스페이스에 대한 execute |
| k8s:5.1.5 | 기본 서비스 계정 미사용 | 개별 | ✅ 표현 가능 | `relation:runs`, `field:asset.identity.kind` |  |
| k8s:5.1.6 | 서비스 계정 토큰은 필요한 곳에만 | 개별 | ✅ 표현 가능 | `config:container.service_account_token` |  |
| k8s:5.1.7 | 최상위 관리 그룹 미사용 | 개별 | ✅ 표현 가능 | `relation:member_of` |  |
| k8s:5.1.8 | 권한 연결·가장·상승 권한 제한 | 개별 | ✅ 표현 가능 | `relation:has_permission` | delegate |
| k8s:5.1.9 | 영구 볼륨 생성 권한 최소화 | 개별 | ✅ 표현 가능 | `relation:has_permission` |  |
| k8s:5.1.10 | 노드 프록시 권한 최소화 | 개별 | ✅ 표현 가능 | `relation:has_permission` | 노드에 대한 execute |
| k8s:5.1.11 | 인증서 서명 요청 승인 권한 최소화 | 개별 | ⚠️ 일부 | `relation:has_permission`, `relation:grants` |  **한계:** 인증서 발급 권한은 ATT&CK T1649와 같은 한계 (템플릿·발급 대상 단위는 근사) |
| k8s:5.1.12 | 웹훅 설정 접근 최소화 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `field:asset.policy.kind` | 승인 제어 웹훅 = 정책 객체 |
| k8s:5.1.13 | 서비스 계정 토큰 생성 권한 최소화 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `relation:grants` |  |
| k8s:5.2.1 | 정책 통제 장치 적용 | 개별 | ✅ 표현 가능 | `field:asset.policy.kind`, `relation:manages` |  |
| k8s:5.2.2 | 특권 컨테이너 최소화 | 개별 | ✅ 표현 가능 | `config:container.privileged` |  |
| k8s:5.2.3 | 호스트 프로세스 공간 공유 최소화 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.2.4 | 호스트 프로세스 간 통신 공유 최소화 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.2.5 | 호스트 네트워크 공유 최소화 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.2.6 | 권한 상승 허용 최소화 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.2.7 | root 컨테이너 최소화 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.2.8 | 원시 네트워크 권한 최소화 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.2.9 | 추가 권한(capability) 최소화 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.2.10 | 권한이 할당된 컨테이너 최소화 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.2.11 | 윈도우 호스트 프로세스 컨테이너 최소화 | 개별 | ✅ 표현 가능 | `config:container.privileged` |  |
| k8s:5.2.12 | 호스트 경로 볼륨 최소화 | 개별 | ✅ 표현 가능 | `config:container.host_mounts` |  |
| k8s:5.2.13 | 호스트 포트 사용 최소화 | 개별 | ✅ 표현 가능 | `relation:reaches`, `config:container.pod_security_level` |  |
| k8s:5.3.1 | 네트워크 정책을 지원하는 네트워크 플러그인 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| k8s:5.3.2 | 모든 네임스페이스에 네트워크 정책 | 개별 | ✅ 표현 가능 | `relation:reaches`, `field:group.kind` |  |
| k8s:5.4.1 | 비밀 정보는 환경 변수보다 파일로 | 묶음 | ✅ 표현 가능 | `relation:stores` | stores.location |
| k8s:5.4.2 | 외부 비밀 저장소 사용 | 개별 | ✅ 표현 가능 | `relation:stores`, `field:asset.role` | role key_management |
| k8s:5.5.1 | 이미지 출처 검증 | 묶음 | ✅ 표현 가능 | `config:host.code_signing_enforced` |  |
| k8s:5.7.1 | 네임스페이스로 관리 경계 | 개별 | ✅ 표현 가능 | `field:asset.groups`, `field:group.kind` |  |
| k8s:5.7.2 | 시스템 호출 제한 프로필 | 묶음 | ✅ 표현 가능 | `config:host.application_isolation` |  |
| k8s:5.7.3 | 보안 컨텍스트 적용 | 추가 | ✅ 표현 가능 | `config:container.pod_security_level` |  |
| k8s:5.7.4 | 기본 네임스페이스 미사용 | 범위밖 | ➖ 범위 밖 | — | 사유: 위생 |
| aws:CloudTrail.1 | 전 리전 감사 기록 | 개별 | ✅ 표현 가능 | `config:logging.audit` |  |
| aws:CloudTrail.2 | 감사 기록 저장 암호화 | 범위밖 | ➖ 범위 밖 | — | 사유: 탐지 |
| aws:CloudTrail.4 | 감사 기록 무결성 검증 | 범위밖 | ➖ 범위 밖 | — | 사유: 탐지 |
| aws:CloudTrail.5 | 감사 기록 중앙 수집 | 개별 | ✅ 표현 가능 | `config:logging.centralized` |  |
| aws:EC2.1 | 디스크 스냅샷 공개 금지 | 개별 | ✅ 표현 가능 | `config:access.anonymous`, `relation:has_permission` |  |
| aws:EC2.2 | 기본 보안 그룹 트래픽 차단 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| aws:EC2.3 | 연결된 디스크 암호화 | 개별 | ✅ 표현 가능 | `field:relation.contains.encrypted` |  |
| aws:EC2.4 | 중지된 인스턴스 정리 | 범위밖 | ➖ 범위 밖 | — | 사유: 위생 |
| aws:EC2.6 | 네트워크 흐름 기록 | 범위밖 | ➖ 범위 밖 | — | 사유: 탐지 |
| aws:EC2.7 | 디스크 기본 암호화 | 개별 | ✅ 표현 가능 | `field:relation.contains.encrypted` |  |
| aws:EC2.8 | 메타데이터 서비스 보호 버전 사용 | 개별 | ✅ 표현 가능 | `config:host.metadata_service_protection` |  |
| aws:EC2.9 | 인스턴스 공인 IP 금지 | 개별 | ✅ 표현 가능 | `relation:reaches` | 외부에서 닿는 reaches |
| aws:EC2.10 | 서비스 전용 내부 경로 사용 | 묶음 | ⚠️ 일부 | `relation:routes_via` |  **한계:** 클라우드 API로 가는 경로가 내부망인지 인터넷인지는 경유 노드로만 근사 |
| aws:EC2.15 | 서브넷 공인 IP 자동 할당 금지 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| aws:EC2.16 | 사용하지 않는 네트워크 ACL 정리 | 범위밖 | ➖ 범위 밖 | — | 사유: 위생 |
| aws:EC2.17 | 다중 네트워크 인터페이스 금지 | 개별 | ✅ 표현 가능 | `field:asset.groups` | 한 호스트가 여러 서브넷에 속함 |
| aws:EC2.18 | 허가된 포트만 전체 개방 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| aws:EC2.19 | 위험 포트 전체 개방 금지 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| aws:EC2.20 | VPN 터널 이중화 | 범위밖 | ➖ 범위 밖 | — | 사유: 가용성 |
| aws:EC2.21 | 원격 관리 포트 전체 개방 금지 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| aws:EC2.23 | 네트워크 연결 자동 수락 금지 | 개별 | ✅ 표현 가능 | `relation:trusts`, `relation:routes_via` |  |
| aws:EC2.24 | 구형 가상화 유형 미사용 | 범위밖 | ➖ 범위 밖 | — | 사유: 위생 |
| aws:EC2.25 | 실행 템플릿 공인 IP 금지 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| aws:EC2.51 | 클라이언트 VPN 접속 기록 | 범위밖 | ➖ 범위 밖 | — | 사유: 탐지 |
| aws:EC2.55 | 컨테이너 레지스트리 API 내부 경로 | 묶음 | ⚠️ 일부 | `relation:routes_via` |  **한계:** EC2.10과 같음 |
| aws:EC2.56 | 컨테이너 레지스트리 내부 경로 | 묶음 | ⚠️ 일부 | `relation:routes_via` |  **한계:** EC2.10과 같음 |
| aws:EC2.57 | 시스템 관리 서비스 내부 경로 | 묶음 | ⚠️ 일부 | `relation:routes_via` |  **한계:** EC2.10과 같음 |
| aws:EC2.58 | 사고 관리 연락처 서비스 내부 경로 | 범위밖 | ➖ 범위 밖 | — | 사유: 가용성 |
| aws:EC2.60 | 사고 관리 서비스 내부 경로 | 범위밖 | ➖ 범위 밖 | — | 사유: 가용성 |
| aws:EC2.170 | 실행 템플릿 메타데이터 보호 | 개별 | ✅ 표현 가능 | `config:host.metadata_service_protection` |  |
| aws:EC2.171 | VPN 연결 기록 | 범위밖 | ➖ 범위 밖 | — | 사유: 탐지 |
| aws:EC2.172 | 네트워크 공개 접근 차단 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| aws:EC2.173 | 스팟 요청 디스크 암호화 | 개별 | ✅ 표현 가능 | `field:relation.contains.encrypted` |  |
| aws:EC2.180 | 출발지·목적지 확인 | 묶음 | ⚠️ 일부 | `relation:routes_via` |  **한계:** 인스턴스가 다른 주소로 위장해 트래픽을 중계하는 상황은 표현하지 않음 |
| aws:EC2.181 | 실행 템플릿 디스크 암호화 | 개별 | ✅ 표현 가능 | `field:relation.contains.encrypted` |  |
| aws:EC2.182 | 스냅샷 공개 접근 차단 | 개별 | ✅ 표현 가능 | `config:access.anonymous` |  |
| aws:EC2.183 | VPN 최신 키 교환 방식 | 묶음 | ✅ 표현 가능 | `config:transport.encryption` |  |
| aws:EKS.1 | 클러스터 관리 주소 비공개 | 개별 | ✅ 표현 가능 | `relation:reaches` |  |
| aws:EKS.2 | 지원되는 쿠버네티스 버전 | 개별 | ✅ 표현 가능 | `config:host.patch_currency` |  |
| aws:EKS.8 | 클러스터 감사 기록 | 개별 | ✅ 표현 가능 | `config:logging.audit` |  |
| aws:EKS.9 | 노드 그룹 지원 버전 | 개별 | ✅ 표현 가능 | `config:host.patch_currency` |  |
| aws:IAM.1 | 전체 관리자 정책 금지 | 개별 | ✅ 표현 가능 | `relation:has_permission` | action admin |
| aws:IAM.2 | 사용자에게 정책 직접 연결 금지 | 묶음 | ✅ 표현 가능 | `relation:member_of`, `relation:has_permission` |  |
| aws:IAM.3 | 접근 키 주기 교체 | 개별 | ✅ 표현 가능 | `config:auth.credential_rotation` |  |
| aws:IAM.4 | 최상위 계정 접근 키 금지 | 개별 | ✅ 표현 가능 | `relation:grants` | 최상위 계정을 grants 하는 키 credential 의 존재 |
| aws:IAM.5 | 콘솔 사용자 다중 인증 | 개별 | ✅ 표현 가능 | `config:auth.mfa` |  |
| aws:IAM.6 | 최상위 계정 하드웨어 다중 인증 | 개별 | ✅ 표현 가능 | `config:auth.mfa_strength` |  |
| aws:IAM.7 | 강한 비밀번호 정책 | 개별 | ✅ 표현 가능 | `config:auth.password_policy` |  |
| aws:IAM.8 | 사용하지 않는 자격증명 제거 | 추가 | ✅ 표현 가능 | `config:account.dormant` |  |
| aws:IAM.21 | 서비스 단위 와일드카드 권한 금지 | 묶음 | ✅ 표현 가능 | `relation:has_permission` |  |
| aws:KMS.1 | 모든 키 복호화 허용 정책 금지 | 개별 | ✅ 표현 가능 | `relation:has_permission` | 키 credential 에 대한 read |
| aws:KMS.2 | 인라인 정책의 전체 복호화 금지 | 개별 | ✅ 표현 가능 | `relation:has_permission` |  |
| aws:KMS.3 | 키 의도치 않은 삭제 방지 | 개별 | ✅ 표현 가능 | `field:impact_goal.harm` | 키 파괴 = destroy 목표 |
| aws:KMS.5 | 키 공개 접근 금지 | 추가 | ✅ 표현 가능 | `config:access.anonymous` |  |
| aws:Lambda.1 | 함수 공개 접근 금지 | 개별 | ✅ 표현 가능 | `config:access.anonymous` |  |
| aws:Lambda.2 | 지원되는 실행 환경 | 개별 | ✅ 표현 가능 | `config:host.patch_currency` |  |
| aws:Lambda.5 | 다중 가용 영역 | 범위밖 | ➖ 범위 밖 | — | 사유: 가용성 |
| aws:S3.1 | 저장소 공개 차단 설정 | 개별 | ✅ 표현 가능 | `config:access.anonymous` |  |
| aws:S3.2 | 저장소 공개 읽기 차단 | 추가 | ✅ 표현 가능 | `relation:has_permission` | external → 저장소 read |
| aws:S3.3 | 저장소 공개 쓰기 차단 | 추가 | ✅ 표현 가능 | `relation:has_permission` | external → 저장소 write |
| aws:S3.5 | 저장소 요청 암호화 강제 | 개별 | ✅ 표현 가능 | `config:transport.encryption` |  |
| aws:S3.6 | 다른 계정 접근 제한 | 개별 | ✅ 표현 가능 | `relation:has_permission`, `relation:trusts` |  |
| aws:S3.8 | 저장소 공개 접근 차단 | 개별 | ✅ 표현 가능 | `config:access.anonymous` |  |
| aws:S3.9 | 저장소 접근 기록 | 개별 | ✅ 표현 가능 | `config:logging.audit` |  |
| aws:S3.12 | 접근 제어 목록 대신 정책 사용 | 묶음 | ✅ 표현 가능 | `relation:has_permission` |  |
| aws:S3.13 | 저장소 수명 주기 설정 | 묶음 | ⚠️ 일부 | `field:asset.data.volume` |  **한계:** 보존 기간은 데이터 양으로 근사 (CIS 3.4와 같음) |
| aws:S3.19 | 접근 지점 공개 차단 | 개별 | ✅ 표현 가능 | `config:access.anonymous` |  |
| aws:S3.24 | 다중 리전 접근 지점 공개 차단 | 개별 | ✅ 표현 가능 | `config:access.anonymous` |  |
| aws:S3.25 | 디렉터리 저장소 수명 주기 | 묶음 | ⚠️ 일부 | `field:asset.data.volume` |  **한계:** S3.13과 같음 |
| aws:SecretsManager.1 | 비밀 자동 교체 | 개별 | ✅ 표현 가능 | `config:auth.credential_rotation` |  |
| aws:SecretsManager.2 | 자동 교체 성공 | 개별 | ✅ 표현 가능 | `config:auth.credential_rotation` |  |
| aws:SecretsManager.3 | 사용하지 않는 비밀 제거 | 추가 | ✅ 표현 가능 | `config:account.dormant` |  |
| aws:SecretsManager.4 | 정해진 기간 내 교체 | 개별 | ✅ 표현 가능 | `config:auth.credential_rotation` |  |
