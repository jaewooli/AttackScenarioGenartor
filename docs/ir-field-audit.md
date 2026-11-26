# IR 필드 감사 (WBS 2.5 선행)

> 엔진을 만들기 전에 IR의 모든 필드를 두 질문으로 검증한다.
> 1. **엔진이 이 필드를 읽는가?** (최소 규칙 R1~R11, 도달성 계산, 목표 생성, 위험도)
> 2. **실제 입력에서 이 값을 얻을 수 있는가?**
>
> `tests/test_field_audit.py`가 스키마의 모든 필드가 이 표에 있는지 확인한다. 필드를 추가하면 이 표에 판정을 적어야 테스트가 통과한다.

최초 감사: 2026-11-21 (필드 74개)

## 기준

### 엔진 쪽: 읽는 곳
| 기호 | 엔진 부분 |
|---|---|
| R1 | 그룹 소속: `acts_as(사용자)` + `member_of` → `acts_as(그룹)` |
| R2 | 정상 로그인: `acts_as` + `authenticates_to` + 닿음 → `foothold` |
| R3 | 권한 사용: `acts_as` + `has_permission` → `foothold` / `controls` / `data_access` |
| R4 | 실행 계정: `foothold(admin)` + `runs.as` → `acts_as` |
| R5 | 로그인 세션: `foothold(admin)` + `session` → `acts_as` |
| R6 | 보관된 자격증명: `foothold(admin)` + `stores` → `has_credential` |
| R7 | 자격증명 사용: `has_credential` + `grants` → `acts_as` |
| R8 | 그룹 장악: 그룹을 관리하는 자산에 대한 `foothold(admin)` → `controls` |
| R9 | 데이터 접근: 저장소(또는 저장소를 올린 서버, `hosts`)에 대한 `foothold(admin)` + `contains` → `data_access` |
| R10 | 노출 서비스 침해: 외부·내부에서 닿는 서비스(`runs` 및 단독 `managed_service`) → `foothold(user)` (인증·설정별 사전확률) |
| R10b | 로컬 권한 상승: `foothold(host, user)` → `foothold(host, admin)` (패치·하드닝·EPP 반영) |
| R11 | 관리 주체: `foothold(admin)` on 관리자 + `manages` → 피관리 자산 `foothold(admin)` (**감사에서 새로 발견, 규칙 목록에 없었음**) |
| N | 네트워크 도달성 계산 (스펙 6.1) |
| G | 목표 자동 생성 (스펙 8.4) |
| S | 위험도·영향도 계산 (스펙 9장) |
| V | 분석 변형 (informed/uninformed, egress) |
| P | 사전분포 조회 (값이 비었을 때) |

### 입력 쪽: 얻을 수 있는 곳
| 기호 | 입력 |
|---|---|
| IaC | Terraform 등 클라우드/IaC 정의 |
| DIR | 디렉터리 서비스 덤프 (사용자, 그룹, 권한, 세션) |
| SCAN | 네트워크 스캔 결과 |
| 사람 | 담당자 입력, 자연어 설명 |

### 판정
| 판정 | 의미 | 조치 |
|---|---|---|
| **핵심** | 엔진이 읽고, 입력에서 대체로 얻을 수 있음 | 유지 |
| **핵심·사전분포 필수** | 엔진이 읽지만 실제 입력에서 자주 비어 있음 | 유지 + **좋은 사전분포가 반드시 필요** (대략 분석 품질이 여기서 결정됨) |
| **의미 미정** | 엔진이 써야 하는데 계산 방식이 정해지지 않음 | P2/P3에서 정의 |
| **메타** | 엔진은 안 읽음. 사람이 보거나 입력 병합(P5)에 씀 | 유지하되 엔진 설계에서 무시 |
| **보류** | 지금 단계(MVP)의 규칙이 안 씀 | 스키마에 두되 P3 이후 재검토 |

## 감사표

### group
| 필드 | 엔진이 읽는 곳 | 얻을 수 있는 곳 | 판정 |
|---|---|---|---|
| `group.kind` | N (네트워크 그룹), R8 (도메인·계정) | IaC, DIR | 핵심 |
| `group.parent` | N (규칙 상속), R8 (하위 그룹) | IaC, DIR | 핵심 |
| `group.config` | P (소속 자산의 기본값) | IaC 일부, 사람 | 핵심·사전분포 필수 |
| `group.cidr` | — (도달성은 `reaches`로 계산) | IaC, SCAN | 메타 (P5 개체 병합) |
| `group.fqdn` | — | DIR | 메타 (P5 개체 병합) |
| `group.netbios` | — | DIR | 메타 (P5 개체 병합) |
| `group.name` | — | 전부 | 메타 |
| `group.description` | — | 사람 | 메타 (P6 맥락 번역 재료) |
| `group.tags` | — | IaC | 메타 |

### asset (공통)
| 필드 | 엔진이 읽는 곳 | 얻을 수 있는 곳 | 판정 |
|---|---|---|---|
| `asset.role` | P (역할별 사전분포), G, R8 (도메인 컨트롤러), R10 | 사람, 추론(포트·이름) | 핵심·사전분포 필수 |
| `asset.groups` | N, R8, P (그룹 기본값 상속) | IaC, DIR, SCAN(서브넷) | 핵심 |
| `asset.criticality` | G (목표 가치), S | 사람 | 핵심·사전분포 필수 |
| `asset.config` | R2, R10, P | IaC 일부, SCAN 일부, 사람 | 핵심·사전분포 필수 |
| `asset.name` | — | 전부 | 메타 |
| `asset.description` | — | 사람 | 메타 (P5/P6 LLM 번역 재료) |
| `asset.tags` | — | IaC | 메타 |

### asset (타입별)
| 필드 | 엔진이 읽는 곳 | 얻을 수 있는 곳 | 판정 |
|---|---|---|---|
| `asset.host.os` | R10 (사전확률), P | SCAN, DIR, IaC 일부 | 핵심 |
| `asset.host.ip` | — | SCAN, IaC | 메타 (P5 개체 병합) |
| `asset.service+network_device.port` | N (`reaches.ports`와 맞춤), R10 | SCAN, IaC(보안 그룹) | 핵심 |
| `asset.service+network_device.protocol` | N | SCAN, IaC | 핵심 |
| `asset.service+network_device.product` | R10, P | SCAN | 핵심 |
| `asset.service+network_device.version` | R10 (L2: 공개 취약점 대조) | SCAN 일부 | 핵심·사전분포 필수 |
| `asset.service+network_device.kind` | — | 사람, DIR(예약 작업) | 메타 |
| `asset.software.version` | — (L3) | SBOM, 패키지 목록 | 보류 |
| `asset.software.ecosystem` | — (L3) | SBOM | 보류 |
| `asset.software.usage` | — (L3) | 코드 분석 | 보류 |
| `asset.identity.kind` | R1 (그룹인지), R5 (그룹은 세션 불가) | DIR, IaC(IAM) | 핵심 |
| `asset.identity.scope` | — | DIR | 메타 |
| `asset.credential.kind` | R7 (종류별 사용 확률) | 사람, 추론 | 의미 미정 (`rule-dsl.md` 5장에 정의안, P3에서 구현) |
| `asset.credential.scope` | — | 사람 | 메타 |
| `asset.data.categories` | G, S (영향도 기본값) | 사람, LLM 추론 | 핵심·사전분포 필수 |
| `asset.data.environment` | S (테스트 데이터는 영향 낮음) | 사람, 태그 추론 | 핵심·사전분포 필수 |
| `asset.data.identifiers` | G (결합 목표 후보) | 사람, DB 스키마 | 핵심·사전분포 필수 |
| `asset.data.volume` | S (영향도 크기) | 사람 | 의미 미정 (`rule-dsl.md` 5장에 정의안, P3에서 구현) |
| `asset.data.regulations` | S | 사람, `categories`에서 추론 | 의미 미정 (`rule-dsl.md` 5장에 정의안, P3에서 구현) |
| `asset.business_service.downtime_impact` | S (중단 목표 가치) | 사람 | 의미 미정 (`rule-dsl.md` 5장에 정의안, P3에서 구현) |
| `asset.policy.kind` | R11 (정책 → `manages` → 적용 대상) | DIR(그룹 정책), IaC(조직 정책) | 메타 (종류 구분용. 엔진은 `manages`와 권한만 읽음) |
| `asset.external.trust_level` | V (협력사 시작점) | 사람 | 메타 |

### relation
| 필드 | 엔진이 읽는 곳 | 얻을 수 있는 곳 | 판정 |
|---|---|---|---|
| `relation.reaches.ports` | N | IaC(보안 그룹), 방화벽 규칙 | 핵심 |
| `relation.reaches.protocol` | N | IaC | 핵심 |
| `relation.reaches.via` | N (경유 장비 방향성) | IaC(라우팅) | 핵심 |
| `relation.runs.as` | R4 | DIR(서비스 계정), 호스트 정보 | 핵심·사전분포 필수 |
| `relation.runs.privilege` | R4 (얻는 권한 수준) | 호스트 정보 | 핵심·사전분포 필수 |
| `relation.has_permission.action` | R3 | DIR, IaC(IAM) | 핵심 |
| `relation.has_permission.effect` | R3 (거부 우선) | DIR, IaC | 핵심 |
| `relation.has_permission.inherit` | R3 (하위 객체 전파) | DIR | 핵심 |
| `relation.has_permission.condition` | R3 (조건부 → 확률) | IaC(IAM 조건) | 핵심·사전분포 필수 |
| `relation.has_permission.native` | — | DIR, IaC | 메타 |
| `relation.authenticates_to.privilege` | R2 | DIR, 호스트 정보 | 핵심·사전분포 필수 |
| `relation.authenticates_to.method` | — | DIR | 메타 (인증 방식은 서비스 `config`의 `auth.methods`가 담당) |
| `relation.session.frequency` | R5 (세션이 있을 확률) | DIR(세션 수집), 사람 | 핵심·사전분포 필수 |
| `relation.session.logon` | R5 (로그인 방식별 자격증명 노출 확률) | DIR | 핵심·사전분포 필수 |
| `relation.stores.location` | — | 사람 | 메타 |
| `relation.contains.encrypted` | G (암호화 → AND 조건), R9 | 사람, IaC(저장소 암호화) | 핵심 |
| `relation.contains.key_ref` | G (키 획득 조건) | 사람, IaC(KMS 연결) | 핵심 |
| `relation.trusts.kind` | R1/R2 (신뢰 종류별 전파 범위) | DIR, IaC(역할 위임) | 핵심 |
| `relation.trusts.direction` | R1/R2 (방향) | DIR | 핵심 |
| `relation.hosts+grants+depends_on+manages.kind` | — | 사람 | 메타 |

### impact_goal, attacker_profile, context
| 필드 | 엔진이 읽는 곳 | 얻을 수 있는 곳 | 판정 |
|---|---|---|---|
| `impact_goal.harm` | G, S | 사람 / 자동 생성 | 핵심 |
| `impact_goal.condition` | G (DAG 뿌리) | 사람 / 자동 생성 | 핵심 |
| `impact_goal.impact` | S | 사람 / `criticality`·`categories`에서 | 핵심·사전분포 필수 |
| `impact_goal.cia` | S (조직 우선순위와 곱함) | `harm`에서 유도 가능 | 메타 (중복 가능성, P3에서 재검토) |
| `impact_goal.description` | — | 사람 | 메타 |
| `attacker_profile.start` | V (시작 상태) | 사람 / 자동 후보 | 핵심 |
| `attacker_profile.initial_privilege` | V | 사람 | 핵심 |
| `attacker_profile.knowledge` | V | 기본값(둘 다) | 핵심 |
| `attacker_profile.egress` | V | 기본값(둘 다) | 핵심 |
| `attacker_profile.capability` | S (단계 성공 확률: `low/medium/high/advanced` 계수) | 사람 | 핵심 |
| `attacker_profile.description` | — | 사람 | 메타 |
| `context.known_state` | V (시작 상태) | 사람 | 핵심 |
| `context.defaults` | P | 사람 | 핵심·사전분포 필수 |
| `context.scope` | N, G (제외 대상) | 사람 | 핵심 |
| `context.analysis` | G (목표 필터) | 사람 | 의미 미정 (`rule-dsl.md` 5장에 정의안, P3에서 구현) |
| `context.organization` | S (CIA 우선순위) | 사람 | 의미 미정 (`rule-dsl.md` 5장에 정의안, P3에서 구현) |
| `context.narrative` | — (P6 LLM 검토 층) | 사람 | 보류 |

## 감사 결과 (2026-11-21)

### 바로 고친 것 — 같은 사실을 두 군데에 적게 되어 있던 필드
| 제거한 필드 | 대신 쓰는 곳 | 이유 |
|---|---|---|
| `identity.mfa` | `config.auth.mfa` | 설정 키 사전과 중복 |
| `identity.privilege_level` | `has_permission`, `authenticates_to.privilege` | 권한은 관계에서 나옴. 주체에 붙은 "수준"은 의미가 모호 |
| `data_store.encryption` | `contains.encrypted` | 같은 저장소의 데이터마다 다를 수 있음 |
| `business_service.depends_on_assets` | `depends_on` 관계 | 관계와 중복 |
| `lod` (asset 공통) | 엔진이 계산 | 입력값이 아니라 결과값 |

### 판정 분포 (74개)
| 판정 | 개수 | 의미 |
|---|---|---|
| 핵심 | 26 | 엔진의 뼈대 |
| 핵심·사전분포 필수 | 16 | **대략 분석의 품질이 이 16개의 사전분포에 달려 있음** |
| 의미 미정 | 7 | 엔진이 써야 하는데 계산 방식이 없음 |
| 메타 | 21 | 엔진 설계에서 무시해도 됨 |
| 보류 | 4 | L3 소프트웨어 3개, 서술형 맥락 1개 |

### 새로 발견한 것
1. **규칙 R11(관리 주체)이 최소 규칙 목록에 빠져 있었다.** `manages` 관계는 IR에 있는데 읽는 규칙이 없었다. CI/CD, 백업, 구성관리 서버처럼 "다른 자산을 통제하는 자산"이 바로 여기에 해당하므로 중요하다.
2. **"의미 미정" 7개는 엔진이 쓸 값인데 계산식이 없다.** 특히 `attacker_profile.capability`(역량 → 단계 확률)와 영향도 관련 필드(`volume`, `regulations`, `downtime_impact`, `organization`)는 위험도 계산(P3 3.4~3.5) 전에 정해야 한다.
3. **"핵심·사전분포 필수" 16개 중 다수가 관계(`session`, `runs.as`, `has_permission.condition`, `authenticates_to.privilege`)다.** 이 관계들은 실제 입력에서 가장 자주 비어 있다. 그래서 IR 필드보다 **사전분포 표를 만드는 일이 더 중요할 수 있다.** WBS에 별도 작업으로 넣어야 한다.
4. **GOAD 인프라 샘플은 "핵심" 필드만 일부 채우고 있고, "핵심·사전분포 필수" 필드는 거의 비어 있다.** 지금 엔진을 돌리면 R10(노출 서비스)만 동작한다. 얇은 엔진 검증에는 정상 운영 설정(관리자 그룹, 원격 접속 그룹 등)과 가상 데이터 노드가 필요하다.

### 2회차: ATT&CK 완화책 대조 (2026-11-21, M0.5)
- 기준: ATT&CK v20.1 활성 완화책 44개. 결과는 `docs/mitigation-coverage.md`.
- 첫 대조: 표현 가능 11 · 일부 5 · **불가 26** · 범위 밖 2 → 보강 후: 표현 가능 40 · 일부 2 · **불가 0** · 범위 밖 2
- 설정 키 12개 → 44개 (`docs/config-keys.md`). 조직 단위 키(`org.*`)는 `context.defaults`에만 붙는다.
- 두 번째 샘플(`docs/samples/shop-hybrid.ir.yaml`)에 모든 키를 실제로 써서 검증 통과를 확인했다. 여기서 대조표로는 안 보이던 문제 2개가 나왔다.
  1. **저장소가 어느 서버 위에 있는지 표현할 수 없었다** → `hosts` 관계가 `data_store`도 가리킬 수 있게 확장
  2. **YAML이 따옴표 없는 `on`/`off`를 참/거짓으로 읽는다** → 허용값을 `enabled`/`disabled`로 바꾸고, 검증 오류에 원인 안내 추가
- 새 설정 키는 스키마 필드가 아니라 사전 항목이라 위 감사표의 개수(74)는 그대로다. 설정 키는 `asset.config`, `group.config`, `context.defaults` 행이 대표한다.

### 3회차: 참조 문서 5종 대조 (2026-11-21, WBS 1.6)
- ATT&CK 공격 기법, CIS Controls v8.1, D3FEND, 플랫폼 기준 표본, 관리·애플리케이션 영역. 모두 표현 불가 0. 요약은 `docs/crosswalk/README.md`
- 스키마 필드 74 → 75 (`asset.policy.kind`, 정책 객체 타입 추가). 설정 키 44 → 65
- 관계 허용 노드 확장: `session` → service, `has_permission` ← external
- 반복 한계(데이터 흐름 엣지, 애플리케이션 내부, 탐지·시간)는 `docs/crosswalk/README.md`에 정리

### 다음 감사 시점
- 규칙 형식(2.2)이 정해진 뒤: "엔진이 읽는 곳" 열을 규칙 파일에서 자동으로 뽑아 이 표와 대조
- 얇은 엔진을 돌린 뒤: 실제로 읽힌 필드 기록과 대조
