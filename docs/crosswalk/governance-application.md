# 관리·규제·애플리케이션 영역 대조표

> 생성된 문서다. 원본 `src/scengen/ir/crosswalk/governance-application.yaml`을 고친 뒤
> `.venv/bin/scengen crosswalk governance-application --markdown > docs/crosswalk/governance-application.md`로 다시 만든다.

질문: **범위 안/밖의 경계가 맞는가?**

- 기준: 관리·규제·애플리케이션 영역 2026-11-21 — 아래 출처 참고
- 항목 70개: ✅ 표현 가능 25 · ⚠️ 일부 24 · ❌ 불가 0 · ➖ 범위 밖 21
- 통과 조건 (표현 불가 0): **통과**

> NIST CSF 2.0: 22개 범주. NIST 공식 내려받기 파일(csrc.nist.gov)에 22개 코드가 모두 있음을 확인
> OWASP ASVS 5.0: 17개 장. 공식 저장소(github.com/OWASP/ASVS, 5.0/en)의 장 목록으로 확인
> OWASP Top 10 2025: 10개. 공식 저장소(github.com/OWASP/Top10, 2025/docs/en)로 확인
> ISMS-P 인증기준: 영역 21개 (관리체계 4, 보호대책 12, 개인정보 처리 단계 5). 공식 원문을 자동으로 받지 못해 영역 구성은 알려진 구조를 따랐다. **원문 대조 필요**

## 대조 중 발견해서 보강한 빈틈

| 빈틈 | 보강 | 관련 항목 |
|---|---|---|
| (반복된 한계) 시스템 간 데이터 흐름 엣지가 없음. CIS 3.8, D3FEND D3-DEM, ISMS-P 3.3 에서 반복 | 보류. 데이터 흐름(data_flow) 관계 추가를 P2 규칙 설계 때 결정 (유출 경로 판단에 필요한지 확인) | isms:3.3 |
| (반복된 한계) 애플리케이션 내부 검증(입력 검증, 객체 단위 권한, 예외 처리)은 app.secure_development 하나로 근사 | 의도된 한계 (L3). 애플리케이션 분석은 MVP 범위 밖 | asvs:V1, asvs:V2, top10:A01, top10:A05 |

## 범위 밖 사유 코드

| 코드 | 의미 |
|---|---|
| 절차 | 관리·거버넌스 절차. 그 결과는 다른 IR 값으로 나타난다 |
| 탐지 | 탐지·모니터링. 현재 모델 밖 |
| 사후 | 사고 대응·복구. 공격 성공 여부를 바꾸지 않는다 |
| 물리 | 물리 보안. 물리 접근은 공격자 시작점으로만 표현한다 |

## 항목

| 항목 | 요약 | 문서 | 상태 | IR 표현 | 설명 |
|---|---|---|---|---|---|
| csf:GV.OC | 조직 맥락 | NIST CSF 2.0 | ✅ 표현 가능 | `field:context.organization` |  |
| csf:GV.RM | 위험 관리 전략 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 절차 |
| csf:GV.RR | 역할·책임·권한 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 절차 |
| csf:GV.PO | 정책 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 절차 |
| csf:GV.OV | 감독 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 절차 |
| csf:GV.SC | 공급망 위험 관리 | NIST CSF 2.0 | ⚠️ 일부 | `relation:trusts`, `relation:manages`, `field:asset.external.trust_level` |  **한계:** 공급자 평가·계약은 절차. 공급 경로(신뢰·관리 관계)만 표현 |
| csf:ID.AM | 자산 관리 | NIST CSF 2.0 | ✅ 표현 가능 | `field:asset.role`, `field:asset.groups` | IR 자체 |
| csf:ID.RA | 위험 평가 | NIST CSF 2.0 | ✅ 표현 가능 | `field:impact_goal.impact`, `field:asset.criticality` | 이 도구의 출력이 곧 위험 평가 |
| csf:ID.IM | 개선 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 절차 |
| csf:PR.AA | 신원·인증·접근 통제 | NIST CSF 2.0 | ✅ 표현 가능 | `relation:authenticates_to`, `relation:has_permission`, `config:auth.mfa` |  |
| csf:PR.AT | 인식·교육 | NIST CSF 2.0 | ✅ 표현 가능 | `config:org.user_training` |  |
| csf:PR.DS | 데이터 보안 | NIST CSF 2.0 | ✅ 표현 가능 | `field:asset.data.categories`, `field:relation.contains.encrypted`, `config:transport.encryption` |  |
| csf:PR.PS | 플랫폼 보안 | NIST CSF 2.0 | ✅ 표현 가능 | `field:asset.config`, `config:host.patch_currency` |  |
| csf:PR.IR | 인프라 회복력 | NIST CSF 2.0 | ⚠️ 일부 | `config:storage.immutable`, `config:network.ddos_protection`, `relation:reaches` |  **한계:** 이중화·용량 같은 가용성 설계는 표현하지 않음 (공격 성공과 무관) |
| csf:DE.CM | 지속 모니터링 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 탐지 |
| csf:DE.AE | 이상 사건 분석 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 탐지 |
| csf:RS.MA | 사고 관리 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 사후 |
| csf:RS.AN | 사고 분석 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 사후 |
| csf:RS.CO | 사고 대응 보고·소통 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 사후 |
| csf:RS.MI | 사고 완화 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 사후 |
| csf:RC.RP | 복구 계획 실행 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 사후 |
| csf:RC.CO | 복구 소통 | NIST CSF 2.0 | ➖ 범위 밖 | — | 사유: 사후 |
| isms:1.1 | 관리체계 기반 마련 | ISMS-P | ➖ 범위 밖 | — | 사유: 절차 |
| isms:1.2 | 위험 관리 | ISMS-P | ✅ 표현 가능 | `field:impact_goal.impact` | 이 도구의 출력이 위험 평가 입력 |
| isms:1.3 | 관리체계 운영 | ISMS-P | ➖ 범위 밖 | — | 사유: 절차 |
| isms:1.4 | 관리체계 점검·개선 | ISMS-P | ➖ 범위 밖 | — | 사유: 절차 |
| isms:2.1 | 정책·조직·자산 관리 | ISMS-P | ⚠️ 일부 | `field:asset.role`, `field:asset.criticality` |  **한계:** 자산 관리 부분만 표현. 정책·조직은 절차 |
| isms:2.2 | 인적 보안 | ISMS-P | ⚠️ 일부 | `config:org.user_training`, `config:account.dormant` |  **한계:** 교육과 퇴직자 계정 정리만 표현. 서약·직무 분리 등은 절차 |
| isms:2.3 | 외부자 보안 | ISMS-P | ✅ 표현 가능 | `field:asset.external.trust_level`, `relation:trusts`, `relation:authenticates_to` |  |
| isms:2.4 | 물리 보안 | ISMS-P | ➖ 범위 밖 | — | 사유: 물리 |
| isms:2.5 | 인증·권한 관리 | ISMS-P | ✅ 표현 가능 | `relation:has_permission`, `relation:authenticates_to`, `config:auth.password_policy` |  |
| isms:2.6 | 접근 통제 | ISMS-P | ✅ 표현 가능 | `relation:reaches`, `relation:has_permission`, `config:access.anonymous` |  |
| isms:2.7 | 암호화 적용 | ISMS-P | ✅ 표현 가능 | `field:relation.contains.encrypted`, `config:transport.encryption` |  |
| isms:2.8 | 정보시스템 도입·개발 보안 | ISMS-P | ✅ 표현 가능 | `config:app.secure_development`, `field:asset.data.environment` |  |
| isms:2.9 | 시스템·서비스 운영 관리 | ISMS-P | ⚠️ 일부 | `config:host.patch_currency`, `config:logging.audit`, `config:storage.offsite` |  **한계:** 변경 관리·성능·장애 관리는 절차 |
| isms:2.10 | 시스템·서비스 보안 관리 | ISMS-P | ✅ 표현 가능 | `config:host.endpoint_protection`, `config:host.removable_media_restricted`, `config:host.patch_currency`, `relation:reaches` |  |
| isms:2.11 | 사고 예방·대응 | ISMS-P | ⚠️ 일부 | `config:org.vulnerability_scanning`, `config:org.threat_intel` |  **한계:** 예방(점검·인텔리전스)만 표현. 대응은 사후 |
| isms:2.12 | 재해 복구 | ISMS-P | ➖ 범위 밖 | — | 사유: 사후 |
| isms:3.1 | 개인정보 수집 시 보호조치 | ISMS-P | ➖ 범위 밖 | — | 사유: 절차 |
| isms:3.2 | 개인정보 보유·이용 시 보호조치 | ISMS-P | ⚠️ 일부 | `field:asset.data.categories`, `relation:has_permission` |  **한계:** 표시 제한·이용 목적 같은 처리 규칙은 절차. 분류·접근 권한만 표현 |
| isms:3.3 | 개인정보 제공 시 보호조치 | ISMS-P | ⚠️ 일부 | `field:asset.external.trust_level`, `relation:has_permission` |  **한계:** 제3자·국외로 데이터가 흐르는 경로는 데이터 흐름 엣지가 없어 근사 |
| isms:3.4 | 개인정보 파기 시 보호조치 | ISMS-P | ✅ 표현 가능 | `relation:contains` | 파기된 데이터는 IR에 없음 |
| isms:3.5 | 정보주체 권리 보호 | ISMS-P | ➖ 범위 밖 | — | 사유: 절차 |
| asvs:V1 | 인코딩·정제 | OWASP ASVS 5.0 | ⚠️ 일부 | `config:app.secure_development` |  **한계:** 앱 내부 (L3) |
| asvs:V2 | 입력 검증·업무 로직 | OWASP ASVS 5.0 | ⚠️ 일부 | `config:app.secure_development` |  **한계:** 앱 내부 (L3) |
| asvs:V3 | 웹 프런트엔드 보안 | OWASP ASVS 5.0 | ⚠️ 일부 | `config:app.secure_development` |  **한계:** 앱 내부 (L3) |
| asvs:V4 | API·웹 서비스 | OWASP ASVS 5.0 | ⚠️ 일부 | `config:app.secure_development`, `config:auth.methods`, `config:network.application_filtering` |  **한계:** API 단위 권한·검증은 L3 |
| asvs:V5 | 파일 처리 | OWASP ASVS 5.0 | ⚠️ 일부 | `config:app.secure_development` |  **한계:** 앱 내부 (L3) |
| asvs:V6 | 인증 | OWASP ASVS 5.0 | ✅ 표현 가능 | `config:auth.methods`, `config:auth.mfa`, `config:auth.password_policy`, `config:auth.lockout` |  |
| asvs:V7 | 세션 관리 | OWASP ASVS 5.0 | ⚠️ 일부 | `relation:session`, `config:auth.token_binding` |  **한계:** 세션 만료·재인증은 시간 모델이 없어 표현 못 함 |
| asvs:V8 | 인가 | OWASP ASVS 5.0 | ⚠️ 일부 | `relation:has_permission` |  **한계:** 앱 내부 객체 단위 권한은 L3 |
| asvs:V9 | 자체 포함 토큰 | OWASP ASVS 5.0 | ⚠️ 일부 | `relation:grants`, `field:asset.credential.kind`, `config:auth.token_binding` |  **한계:** 토큰 서명 검증 같은 구현 세부는 L3 |
| asvs:V10 | OAuth·OIDC | OWASP ASVS 5.0 | ✅ 표현 가능 | `relation:trusts`, `config:auth.methods` |  |
| asvs:V11 | 암호 | OWASP ASVS 5.0 | ✅ 표현 가능 | `config:transport.encryption`, `field:relation.contains.encrypted`, `field:relation.contains.key_ref` |  |
| asvs:V12 | 안전한 통신 | OWASP ASVS 5.0 | ✅ 표현 가능 | `config:transport.encryption`, `config:transport.certificate_pinning` |  |
| asvs:V13 | 설정 | OWASP ASVS 5.0 | ✅ 표현 가능 | `field:asset.config`, `relation:stores` |  |
| asvs:V14 | 데이터 보호 | OWASP ASVS 5.0 | ✅ 표현 가능 | `field:asset.data.categories`, `field:relation.contains.encrypted` |  |
| asvs:V15 | 안전한 코딩·구조 | OWASP ASVS 5.0 | ⚠️ 일부 | `config:app.secure_development`, `field:asset.software.version` |  **한계:** 앱 내부 (L3) |
| asvs:V16 | 보안 로그·오류 처리 | OWASP ASVS 5.0 | ⚠️ 일부 | `config:logging.audit` |  **한계:** 오류 처리는 앱 내부 (L3). 로그는 탐지 |
| asvs:V17 | WebRTC | OWASP ASVS 5.0 | ⚠️ 일부 | `config:transport.encryption`, `relation:reaches` |  **한계:** 실시간 통신 세부 설정은 L3 |
| top10:A01 | 접근 통제 실패 | OWASP Top 10 2025 | ⚠️ 일부 | `relation:has_permission`, `config:access.anonymous` |  **한계:** 앱 내부 객체 단위 권한은 L3 |
| top10:A02 | 보안 설정 오류 | OWASP Top 10 2025 | ✅ 표현 가능 | `field:asset.config`, `config:auth.default_credentials` |  |
| top10:A03 | 소프트웨어 공급망 실패 | OWASP Top 10 2025 | ⚠️ 일부 | `field:asset.software.version`, `relation:manages`, `relation:depends_on` |  **한계:** 공급자 내부 상태는 범위 밖 (ATT&CK T1195와 같음) |
| top10:A04 | 암호 실패 | OWASP Top 10 2025 | ✅ 표현 가능 | `config:transport.encryption`, `field:relation.contains.encrypted` |  |
| top10:A05 | 주입 | OWASP Top 10 2025 | ⚠️ 일부 | `config:app.secure_development`, `config:network.application_filtering` |  **한계:** 앱 내부 (L3) |
| top10:A06 | 안전하지 않은 설계 | OWASP Top 10 2025 | ⚠️ 일부 | `config:app.secure_development` |  **한계:** 앱 내부 (L3) |
| top10:A07 | 인증 실패 | OWASP Top 10 2025 | ✅ 표현 가능 | `config:auth.mfa`, `config:auth.password_policy`, `config:auth.lockout` |  |
| top10:A08 | 소프트웨어·데이터 무결성 실패 | OWASP Top 10 2025 | ✅ 표현 가능 | `config:host.code_signing_enforced`, `relation:manages` |  |
| top10:A09 | 로그·경보 실패 | OWASP Top 10 2025 | ➖ 범위 밖 | — | 사유: 탐지 |
| top10:A10 | 예외 상황 처리 실패 | OWASP Top 10 2025 | ⚠️ 일부 | `config:app.secure_development` |  **한계:** 앱 내부 (L3) |
