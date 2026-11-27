# Infra IR 스펙 v0.2

> 시나리오 생성기의 입력을 하나로 정규화하는 중간표현(IR)과, 그 IR 위에서 엔진이 위험도를 계산하는 규칙.
> 입력이 Terraform이든, 디렉터리 덤프든, 자산 엑셀이든, 자연어 설명이든 모두 이 IR로 변환한 뒤 엔진이 동작한다.

변경 이력
- v0.1: 초안 (자산/관계, Attr, LoD)
- v0.2: 그룹 계층, 데이터 노드, 권한 정규화, 맥락, 영향 목표, 분포 기반 위험도, 역방향 탐색

---

## 1. 설계 원칙

| 원칙 | 내용 | 이유 |
|---|---|---|
| 범용성 | 클라우드, 온프레미스, 디렉터리 서비스, OT, 하이브리드를 같은 모델로 표현 | 입력 인프라의 종류를 제한하지 않기 위해 |
| 그래프 | 자산은 노드, 관계는 엣지 | 시나리오 = 경로/DAG 탐색. 선행 연구(MulVAL, BloodHound, MAL)와 같은 방식 |
| 혼합 세부 수준(LoD) | 자산마다 아는 정보 수준이 달라도 됨. 모드 구분 없음 | 실제 인프라는 정보 수준이 섞여 있음 |
| 출처와 확신도 | 모든 값에 `source`, `confidence` | 가정 기반 결과와 확정 결과를 구분하기 위해 |
| 모름은 오류가 아님 | 빈 값은 사전분포로 대체하고 결과에 표시 | 정보가 적어도 분석이 돌아가야 함 |
| 펼치지 않음 | 그룹, 상속, 묶음 단위 규칙은 구조로 두고 엔진이 필요할 때 풂 | 엣지 폭발 방지, 규칙 변경 시 수정 범위 최소화 |

---

## 2. 최상위 구조

```yaml
ir_version: "0.2"
meta:
  name: "..."
  sources: [{ id, kind, path }]   # 이 IR을 만든 입력들
context: {}            # 7장. 인프라 전체에 적용되는 맥락
groups: []             # 3장. 네트워크/정책/디렉터리 묶음 (계층 가능)
assets: []             # 4장. 노드
relations: []          # 5장. 엣지
impact_goals: []       # 8장. 피해 목표 (생략 시 자동 생성)
attacker_profiles: []  # 10장. 공격자 시작점과 역량 (생략 시 기본값)
```

인프라 정의(`groups`, `assets`, `relations`)와 분석 조건(`context`, `impact_goals`, `attacker_profiles`)은 **별도 파일로 나눌 수 있다.** 같은 인프라에 다른 맥락을 붙여 "만약 ~라면" 비교를 하기 위해서다.

---

## 3. 속성 래퍼 `Attr`

```yaml
version:
  value: "1.18.0"
  source: declared        # declared | inferred | assumed | unknown
  confidence: 1.0         # 0.0 ~ 1.0
  evidence: src2          # 근거: 입력 소스 id, 추론 규칙 id, 또는 문장
```

| source | 의미 | 기본 confidence |
|---|---|---|
| `declared` | 입력에 명시됨 | 1.0 |
| `inferred` | 규칙이나 LLM으로 추론함 | 추론기가 지정 |
| `assumed` | 정보가 없어 사전값으로 채움 | 사전분포의 폭으로 표현 |
| `unknown` | 값도 가정도 없음 | 엔진이 사전분포 적용 |

단순 값만 쓰면 `declared`, `1.0`으로 간주한다. 관계(엣지)도 같은 필드를 가질 수 있다.

**객체 단위 출처**: 그룹, 자산, 관계, 그리고 `os` 같은 하위 객체에 `source`/`confidence`/`evidence`를 직접 붙이면, 하위 필드가 따로 지정하지 않는 한 그 값을 물려받는다.

```yaml
os: { family: windows, version: "Windows Server 2019", source: declared, evidence: doc }
```

### 3.1 확신도와 확률 분포의 연결

불확실성은 두 종류이고, **IR은 첫 번째만 담는다.**

| 불확실성 | 질문 | 담는 곳 |
|---|---|---|
| 인프라에 대한 불확실성 | "이 값이 실제로 맞나?" | IR의 `confidence`, `distribution` |
| 공격 단계의 불확실성 | "조건이 다 맞을 때 이 단계가 성공하나?" | 규칙(P2)의 성공 확률 분포 |

**`confidence`의 의미 = 이 값이 실제로 맞을 확률.** 관계에 붙으면 그 관계가 실제로 존재할 확률이다.

**`distribution` = 값을 모를 때 가능한 값들의 분포.**

```yaml
transport.signing:
  source: assumed
  distribution: { kind: categorical, p: { none: 0.3, optional: 0.5, required: 0.2 } }
```

지원 형태: `bernoulli`(참/거짓), `categorical`(선택지), `beta`(0~1 비율), `uniform`(수치 범위).

**엔진의 몬테카를로 표본 1회에서 속성 값을 정하는 방법:**

| source | 표본에서 쓰는 값 |
|---|---|
| `declared` | 항상 `value` |
| `inferred` | 확률 `confidence`로 `value`, 나머지 확률로 사전분포에서 뽑음 |
| `assumed` | `distribution`이 있으면 거기서 뽑음. 없으면 `value`를 `confidence` 확률로 쓰고, 나머지는 사전분포 |
| `unknown` | 사전분포(역할·타입별 기본값)에서 뽑음 |

- **같은 속성은 표본 1회 안에서 한 번만 뽑고, 그 값을 쓰는 모든 규칙이 공유한다.** 같은 미지 값에 의존하는 단계들이 함께 성공하거나 함께 실패해야 하기 때문이다.
- 이렇게 하면 단계 확률 분포(9.1)와 IR의 확신도가 하나의 표본 과정으로 연결되고, 정보 가치(9.4)는 "이 속성을 고정했을 때 결과 분산이 얼마나 줄어드나"로 계산된다.
- `confidence`를 Beta 분포의 폭으로 바꾸는 식의 임의 변환은 쓰지 않는다.

### 값의 우선순위
같은 속성에 값이 여러 곳에 있으면 아래 순서로 쓴다.

> 자산에 명시된 값 > 그룹 단위 값 > `context` 전체 기본값 > 일반 사전분포

---

## 4. 그룹 (`groups`)

여러 자산을 묶는 단위. 네트워크 위치, 정책 묶음, 디렉터리 구조를 모두 이것으로 표현한다.

```yaml
groups:
  - { id: vcn-prod,    kind: vcn }
  - { id: subnet-pub,  kind: subnet, parent: vcn-prod, cidr: "10.0.1.0/24" }
  - { id: nsg-web,     kind: security_group }       # 서브넷과 겹칠 수 있음
  - { id: dom-corp,    kind: directory_domain, fqdn: corp.local }
  - { id: ou-sales,    kind: directory_ou, parent: dom-corp }
```

| kind 계열 | 예 |
|---|---|
| 네트워크 위치 | `vpc`, `vcn`, `subnet`, `vlan`, `network_segment`, `dmz`, `wireless` |
| 정책 묶음 | `security_group`, `nsg`, `firewall_zone` |
| 디렉터리 | `directory_forest`, `directory_domain`, `directory_ou` |
| 플랫폼 | `cloud_account`, `k8s_cluster`, `k8s_namespace` |

- `parent`로 계층을 만든다. 하위 그룹은 상위 그룹의 규칙을 상속한다.
- 자산은 `groups: [...]`로 여러 그룹에 동시에 속할 수 있다 (예: 서브넷 + 보안 그룹 + 도메인).
- 관계, 목표, 공격자 프로필에서 그룹은 반드시 `group:<id>`로 참조한다. 접두어가 없으면 자산 id로 해석한다.
- 그룹 id와 자산 id는 겹칠 수 없다.
- **자산의 그룹 소속은 `groups` 필드로만 표현한다.** `member_of` 엣지는 주체(identity) 사이의 소속에만 쓴다.

---

## 5. 자산 (`assets`, 노드)

### 5.1 타입

| type | 설명 | 주요 필드 |
|---|---|---|
| `host` | 물리/가상 서버, VM, 컨테이너 노드, 워크스테이션 | `role`, `os`, `ip`, `groups` |
| `service` | 포트에서 동작하는 프로세스, 예약 작업, 관리형 서비스 | `kind`, `product`, `version`, `port`, `protocol`, `config` |
| `software` | 설치된 패키지, 라이브러리 | `name`, `version`, `ecosystem`, `usage` |
| `identity` | 사용자, 그룹, 서비스 계정, 클라우드 역할 | `kind`, `scope`, `config` (예: `auth.mfa`) |
| `credential` | 비밀번호, 키, 토큰, 인증서 | `kind`, `scope` |
| `data` | **데이터 자체** (무엇) | `description`, `categories`, `environment`, `volume`, `identifiers` |
| `data_store` | 데이터가 있는 곳 (어디) | `role` (암호화 여부는 `contains.encrypted`) |
| `business_service` | 업무 기능 | `description`, `downtime_impact` (의존 자산은 `depends_on` 관계) |
| `network_device` | 방화벽, 라우터, 게이트웨이, LB, VPN | `role`, `product`, `version` |
| `external` | 인터넷, 협력사, 외부 사용자. `has_permission`의 출발이 되면 "외부의 누구나" (공개 읽기·쓰기) | `trust_level` |
| `policy` | 여러 자산에 한꺼번에 적용되는 정책 객체 (디렉터리 그룹 정책, 클라우드 조직 정책, 구성 관리) | `kind`. 적용 대상은 `manages` |

### 5.2 공통 필드

```yaml
- id: web-01            # 필수, IR 안에서 유일
  type: host            # 필수
  name: "웹서버 1"
  description: "..."    # 자유 서술. LLM이 구조화 필드로 변환할 때 사용
  role: web_server      # L0에서 가장 중요한 필드
  groups: [subnet-pub, nsg-web]
  criticality: high     # low | medium | high | crown_jewel
  tags: [prod]
  # lod 는 입력하지 않는다. 엔진이 채워진 필드로 계산한다 (11장)
```

### 5.3 `role` 사전 (초안)
`web_server`, `app_server`, `db_server`, `file_server`, `directory_server`, `domain_controller`, `mail_server`, `jump_host`, `ci_cd`, `monitoring`, `backup`, `workstation`, `mobile_device`, `k8s_node`, `container`, `load_balancer`, `firewall`, `vpn_gateway`, `internet_gateway`, `nat_gateway`, `certificate_authority`, `identity_provider`, `key_management`, `plc`, `hmi`, `scada_server`, `other`

### 5.4 `identity.kind`
`user`, `group`, `service_account`, `managed_service_account`, `cloud_role`, `cloud_user`, `k8s_service_account`, `local_account`

### 5.5 데이터와 저장소의 분리
같은 데이터가 여러 저장소(운영 DB, 백업, 내보내기 파일)에 있을 수 있으므로, **가치는 `data` 노드에 한 번만 적고** 저장소는 `contains` 엣지로 연결한다.

```yaml
- id: data-customer
  type: data
  description: "온라인몰 회원 정보. 이름, 전화번호, 주소, 주문 내역"
  categories: { value: [personal, purchase_history], source: inferred, confidence: 0.8 }
  environment: prod                 # prod | staging | test
  volume: { records: 1200000 }
  regulations: [PIPA]
  identifiers: [customer_id, phone] # 다른 데이터와 결합 가능한 키
```

### 5.6 데이터 분류 (`categories`)

| 값 | 의미 |
|---|---|
| `personal` | 일반 개인정보 |
| `sensitive_personal` | 민감정보 (개인정보보호법 제23조: 건강, 사상·신념, 정치적 견해, 유전·생체인식 정보 등) |
| `unique_identifier` | 고유식별정보 (같은 법 제24조: 주민등록번호, 여권번호, 운전면허번호, 외국인등록번호) |
| `pseudonymized` | 가명정보 |
| `credit` | 개인신용정보 (신용정보법) |
| `payment` | 결제 정보 |
| `credential_material` | 인증 정보 (비밀번호 해시, 키, 토큰) |
| `source_code` | 소스코드 |
| `financial` | 재무, 회계 |
| `health` | 의료 |
| `trade_secret` | 영업비밀 |
| `operational` | 운영 설정, 로그 |
| `purchase_history` | 구매·주문 이력 |
| `public` | 공개 정보 |

### 5.7 보안 설정 (`config`)
서비스, 호스트, 그룹에 `config`로 보안 관련 설정을 담는다. 키는 아래 **설정 키 사전**에 있는 것만 규칙이 읽는다. 사전에 없는 키는 검증 경고가 난다.

```yaml
- id: svc-files
  type: service
  kind: network_service
  config:
    auth.methods: [password, kerberos]
    access.anonymous: false
    transport.signing: { source: assumed, distribution: { kind: categorical, p: { none: 0.3, optional: 0.5, required: 0.2 } } }
```

그룹에 붙이면 소속 자산의 기본값이 된다 (값의 우선순위: 자산 > 그룹 > `context.defaults` > 사전분포).

**키 목록은 [`docs/config-keys.md`](config-keys.md)** (설정 키 사전에서 자동 생성, 현재 65개). `context.defaults`(조직 전체 기본값)도 같은 사전으로 검증한다.

- 각 키에는 붙일 수 있는 곳(`applies_to`)이 정해져 있다. 맞지 않는 곳에 붙이면 검증 경고.
- YAML은 따옴표 없는 `on`/`off`/`yes`/`no`를 참/거짓으로 읽는다. 그래서 허용값에 이 단어를 쓰지 않는다 (예: 방화벽은 `enabled`/`partial`/`disabled`).
- 키는 공인 참조 문서(ATT&CK 완화책·공격 기법, CIS Controls, D3FEND, 플랫폼 기준)를 모두 표현할 수 있도록 정했다. 결과 요약은 [`docs/crosswalk/README.md`](crosswalk/README.md).
- 키를 추가하려면 `src/scengen/ir/vocab.py`를 고치고 문서를 다시 생성한다. 샘플(`docs/samples/shop-hybrid.ir.yaml`)에서 한 번 이상 써야 테스트가 통과한다.

---

## 6. 관계 (`relations`, 엣지)

| type | 방향 | 의미 | 주요 필드 |
|---|---|---|---|
| `reaches` | A → B | 네트워크 도달 가능 | `ports`, `protocol`, `via` |
| `routes_via` | group → network_device | 라우팅 경로 | |
| `runs` | host → service/software | 실행 | `as` (실행 계정), `privilege` |
| `hosts` | host → host, data_store | 하이퍼바이저·컨테이너, 저장소가 올라가 있는 서버 | `kind` |
| `member_of` | identity/host → identity/group | 소속 | |
| `has_permission` | identity → asset/group | 권한 (6.2) | `action`, `effect`, `inherit`, `condition` |
| `authenticates_to` | identity → service | 로그인할 수 있음 (권한) | `method`, `privilege` |
| `session` | identity → host, service | 실제로 로그인해 있거나 주기적으로 로그인함 (상태). service는 웹·SaaS 세션 | `logon`, `frequency` |
| `stores` | asset → credential | 자격증명 보관 | `location` |
| `grants` | credential → identity | 이 자격증명으로 해당 주체가 됨 | |
| `contains` | data_store → data | 데이터 보관 | `encrypted`, `key_ref` |
| `trusts` | A → B | 신뢰 관계 (도메인 신뢰, 역할 위임, 키 신뢰) | `kind`, `direction` |
| `depends_on` | A → B | 의존 | `kind` |
| `manages` | A → B | 관리 주체 (배포, 백업, 구성관리) | `kind` |

**관계 타입마다 허용 필드가 다르다.** 위 표의 "주요 필드"에 없는 필드는 검증 오류다 (예: `member_of`에 `ports`). 모든 관계는 공통으로 `source`, `confidence`, `evidence`, `note`를 가질 수 있다.

### 6.0 실행 상태: `runs.as`와 `session`
권한(할 수 있음)과 상태(실제로 그러고 있음)를 구분한다. 내부 이동 분석에는 상태가 필요하다.

```yaml
- { type: runs, from: srv02, to: svc-db, as: u-sqlsvc, privilege: user }   # 서비스가 어떤 계정으로 도는지
- { type: session, from: u-admin, to: ws-07, logon: remote_interactive, frequency: periodic }
```

| 필드 | 값 |
|---|---|
| `logon` | interactive, remote_interactive, network, service, batch, unknown |
| `frequency` | persistent (상시), periodic (주기적), occasional (가끔), unknown |
| `privilege` | system, admin, user, restricted |

`frequency`는 엔진이 "그 시점에 세션이 있을 확률"의 사전값으로 쓴다. 예약 작업은 `service`(`kind: scheduled_task`) + `runs.as`로 표현한다.

### 6.1 네트워크 도달 가능성
묶음 단위로 규칙을 적고, 실제 도달 여부는 엔진이 계산한다.

```yaml
- { type: reaches, from: external:internet, to: group:nsg-web, ports: [443], via: igw-01 }
- { type: reaches, from: group:subnet-pub,  to: group:subnet-priv, ports: [5432] }
```

> **A → B 도달 가능** = 라우팅 경로 존재 **AND** 네트워크 구간 규칙 허용 **AND** 자산 단위 규칙 허용

- 게이트웨이, LB 등은 경로상의 노드로 둔다 (방향성 표현).
- 특정 자산만 다른 경우, 그 자산을 직접 가리키는 엣지로 묶음 규칙을 덮어쓴다.
- 규칙 정보가 없으면 `assumed` 엣지로 둔다 (예: 같은 서브넷은 상호 도달 가능, confidence 0.9).

### 6.2 권한 정규화
모든 권한 체계(디렉터리 ACL, 클라우드 IAM, 파일 권한, DB GRANT, K8s RBAC)를 같은 형태로 줄인다.

```yaml
- type: has_permission
  from: g-helpdesk
  to: group:ou-employees
  action: reset_credential
  effect: allow           # allow | deny
  inherit: true           # 하위 객체로 상속
  condition: null         # 원문 보관. 평가 불가하면 Attr로 unknown 표시
  native: "..."           # 원래 시스템의 권한 이름 (참고용)
```

추상 행위 어휘:

| action | 의미 |
|---|---|
| `read` | 내용 읽기 |
| `write` | 내용/속성 수정 |
| `execute` | 실행, 로그인 |
| `reset_credential` | 다른 주체의 자격증명 변경 |
| `add_member` | 그룹 구성원 변경 |
| `modify_permissions` | 권한 자체 변경 |
| `take_ownership` | 소유자 변경 |
| `delegate` | 다른 주체로 위임/가장 |
| `admin` | 전체 권한 |

규칙:
- 시스템별 권한 이름 → 추상 어휘 변환은 **입력 어댑터**의 책임. 엔진은 추상 어휘만 안다.
- 그룹 중첩과 상속은 구조로 남기고 펼치지 않는다.
- 모든 주체에게 주어지는 기본 권한은 `context.defaults`에 한 번만 둔다.
- 추상 어휘에 대응하지 않는 권한은 원본만 보관하고 그래프에 넣지 않는다.
- 거부(`deny`) 우선 여부 등 시스템별 평가 규칙은 어댑터가 IR 메타데이터로 명시한다.
- 일시적 권한(JIT 등)은 v0.2 범위 밖.

---

## 7. 맥락 (`context`)

인프라 전체에 적용되는 정보. 자유 서술로 받고, 가능한 것은 아래 다섯 형태로 번역한다.

| 형태 | 예 | 엔진 반영 |
|---|---|---|
| 1. 사실 | "A 데이터는 이미 유출됨" | 공격자 초기 상태에 확률과 함께 넣음 |
| 2. 구조 | "외주 업체가 원격으로 유지보수함" | IR에 노드/엣지 추가 |
| 3. 파라미터 | "야간 모니터링 없음", "업종을 노리는 위협 그룹 존재" | 사전분포 조정 |
| 4. 분석 설정 | "규제 대상 데이터 위주로" | 목표 필터, 가중치 |
| 5. 치환 불가 | "곧 다른 회사 네트워크와 통합 예정" | 서술형으로 보관, LLM 검토 층에서만 사용 |

```yaml
context:
  organization:
    industry: ecommerce
    priorities: { C: high, I: medium, A: high }
    regulations: [PIPA, PCI-DSS]
  known_state:                       # 1. 사실
    - fact: { exfiltrated: data-customer-phone }
      probability: 1.0
      evidence: "과거 유출 사고"
  defaults:                          # 3. 파라미터 / 기본값
    mfa: { value: enforced, scope: [vpn, sso] }
    endpoint_protection: { coverage: 0.8 }
  analysis:                          # 4. 분석 설정
    focus_categories: [personal, unique_identifier]
  scope:
    exclude: [group:legacy-test]
  narrative:                         # 원문 (모든 맥락의 원본 + 5. 치환 불가)
    - text: "..."
      translated_to: [known_state[0]]   # 번역된 항목 추적. 비어 있으면 치환 불가
```

- 번역 결과는 `source: inferred`로 표시하고 사용자 확인을 거친다.
- **치환 불가 맥락의 LLM 조정은 엔진 결과와 분리한다.** 원래 순위와 조정 순위를 함께 보여주고, 조정마다 근거를 붙이고, 조정 폭에 상한을 둔다.
- 5번으로 자주 떨어지는 유형은 스키마에 빠진 것이 있다는 신호로 기록한다.

---

## 8. 영향 목표 (`impact_goals`)

### 8.1 정의
> **목표 = 그 상태에 도달한 것만으로 조직에 실제 피해가 발생하는 공격자 상태**

판별 질문: "공격자가 여기서 멈추면 피해가 생겼는가?" 아니면 중간 단계(수단)다. 관리자 권한, 자격증명 획득 등은 목표가 아니라 **중간 거점**이며, 그 가치는 이어지는 목표에서 나온다.

예외: **디렉터리 도메인 장악**(`controls: group:<directory_domain>`)은 목표로 본다. 개별 호스트의 관리자 권한과 달리, 조직의 공식 신원 체계를 공격자가 쥐는 것 자체가 피해다 (임의 신원 발급·위장, 모든 소속 자산의 신뢰 붕괴). 데이터나 업무 서비스가 IR에 없는 디렉터리 중심 인프라(GOAD 등)에서도 목표가 생긴다.

### 8.2 구조: 가치 있는 대상 × 피해 행위

| 피해 행위 | 축 | 대상 예 |
|---|---|---|
| `exfiltrate` | C | `data` |
| `tamper` | I | `data`, `business_service`, 배포 산출물 |
| `destroy` | A, I | `data`, 백업 |
| `disrupt` | A | `business_service`, 물리 공정 |
| `misuse` | 오용 | 컴퓨팅 자원, 금전 권한, 공식 신원/채널 |

### 8.3 조건과 결합 목표
조건은 AND/OR로 쓴다. 합쳐져야 커지는 영향은 결합 목표로 표현한다.

```yaml
impact_goals:
  - id: g-customer-combined
    harm: exfiltrate
    condition:
      all:
        - { exfiltrated: data-customer }
        - { exfiltrated: data-payment }
    impact: { level: critical, source: declared }
```

### 8.4 자동 생성
사용자가 정의하지 않으면 엔진이 만든다.
1. `data` 노드마다 `exfiltrate`, `tamper` 목표 생성 (저장소 중 하나만 장악하면 되는 OR 조건)
2. 암호화된 저장소는 "저장소 접근 AND 키 획득" AND 조건
3. `identifiers`가 겹치는 데이터 조합은 결합 목표 후보
4. `business_service`마다 `disrupt` 목표
5. 대상의 가치는 사용자 입력 > LLM 추론(`inferred`) > 유형별 기본값(`assumed`)
6. `directory_domain` 그룹마다 도메인 장악 목표 (`harm: misuse`, `condition: {controls: group:<id>}`, 기본 영향도 `critical`/`assumed`)

목표 탐지기의 성능은 정답이 있는 샘플 인프라에서 **재현율(recall)**로 평가한다.

---

## 9. 위험도 계산

### 9.1 단계 확률은 분포로
각 단계의 성공 확률을 숫자 하나가 아니라 분포(예: Beta)로 둔다. 이 분포는 **규칙**에 정의된다 (P2).
- 근거가 명시된 단계: 좁은 분포
- 모르는 단계: 넓은 사전분포
- 단계의 전제조건이 읽는 IR 속성 값은 3.1의 방식으로 표본마다 정해진다. 즉 표본 1회 = (속성 값 표본) → (전제조건 평가) → (단계 성공 표본).

### 9.2 DAG 위의 결합
- AND 노드: 하위 확률의 곱
- OR 노드: 1 − ∏(1 − p)
- 몬테카를로 표본으로 계산하므로 독립 가정을 나중에 완화할 수 있다 (예: 공격자 역량을 공통 변수로 표본화).

### 9.3 위험도
> **위험도 = P(목표 달성) × 영향도(목표)**

- 영향도는 **로그 스케일 등급**: `impact = b^level`. 밑 `b`는 보류 (데이터를 보고 결정).
- 금액 범위를 아는 경우 직접 입력 가능.
- 출력: 평균 + 구간 (예: 평균 0.42, 90% 구간 0.15~0.71). 구간 폭이 곧 확신도.
- 정렬 기준: 기본은 기대 위험도. 옵션으로 상위 백분위(최악 구간) 기준, 확률만 기준.
- 한 시나리오가 여러 목표를 달성할 때의 영향도 합산 규칙은 미정.

### 9.4 정보 가치
결과 분산에 가장 크게 기여하는 `unknown` 필드를 찾아 **"이 정보를 확인하면 순위가 바뀝니다"** 목록으로 출력한다.

---

## 10. 탐색 방식

1. **목표 선별**: 사용자 정의 + 자동 생성 (8.4)
2. **역방향 DAG 구성**: 목표에서 출발해 AND/OR 전제조건을 펼친다.
   - 이미 계산한 하위 목표는 재사용 (tabling)
   - 도달 불가능한 목표는 빈 DAG가 됨
3. **확률 계산과 top-k 추출**: 9장 방식. 모든 경우의 수는 DAG에 압축되어 있고, 개별 시나리오는 top-k만 펼친다.
4. **LLM 검토 층** (선택): 치환 불가 맥락으로 조정 제안. 엔진 결과와 분리 표시.

가정:
- **단조성**: 공격자는 얻은 상태를 잃지 않는다. 계산을 다항 시간으로 만드는 핵심 가정. 자격증명 폐기, 세션 만료 등은 표현하지 못한다.

공격 단계 규칙(전제조건 → 공격자 상태 변화)의 표현 형식은 별도 문서에서 정한다.

### 공격자 프로필

```yaml
attacker_profiles:
  - id: external
    start: [external:internet]
    capability: medium      # low | medium | high | advanced
  - id: insider
    start: [ws-01]
    initial_privilege: user
```
생략 시 `external:internet`에서 시작하는 medium 수준 공격자. 자동 후보(인터넷 노출 자산, 내부 사용자 단말, 외부 연결)도 제안한다.

**분석 변형**: `knowledge`(informed / uninformed)와 `egress`(assumed_open / from_ir)는 생략하면 두 값 모두 분석한다 (기본 4개 변형). 공격자 상태 모델과 변형의 의미는 `docs/attacker-state.md`.

---

## 11. 세부 수준 (LoD)

| 수준 | 아는 정보 | 엔진 판단 방식 |
|---|---|---|
| L0 토폴로지 | `id`, `type`, `role`, 그룹 소속 | role 사전과 사전분포 |
| L1 서비스 | OS 계열, 포트, 제품명 | 제품군 단위로 후보 축소 |
| L2 버전/설정 | 정확한 버전, 네트워크 규칙, 권한, 인증 설정 | 공개 취약점 DB와 악용 통계로 확률 산정, 실제 규칙으로 도달성 계산 |
| L3 코드/사용 방식 | 의존성 트리, 취약 코드 도달 여부, 설정 원문 | 실제 악용 가능성 판단 |

---

## 12. 스키마, 검증기, 샘플
- JSON Schema: `src/scengen/schema/ir.schema.json` (구조 검증)
- 검증기: `scengen validate <파일>` (구조 + 의미 검증)
  - 의미 검증: id 중복, 참조 무결성, `group:` 접두어, 그룹 계층 순환, 관계 타입별 허용 노드, Attr 일관성 (`unknown`인데 값 있음 등)
  - 종료 코드: 0 = 오류 없음, 1 = 오류 있음, 2 = 파일 없음
- 샘플:
  - `docs/samples/goad-infra.ir.yaml`: GOAD 실습 환경의 인프라 구성만 (L1, 권한 정보 없음)
  - `docs/samples/shop-hybrid.ir.yaml`: 가상 하이브리드 쇼핑몰. 데이터, 업무 서비스, 권한, 세션, 목표, 맥락, 출처 표시, 그리고 설정 키 사전의 모든 키를 실제로 사용
- 완화책 대조: `scengen mitigations` (검사), `docs/mitigation-coverage.md` (생성 문서)

### 관계 타입별 허용 노드 (검증기 기준)
| type | from | to |
|---|---|---|
| `runs` | host | service, software |
| `hosts` | host | host, data_store |
| `member_of` | identity, host | identity(kind: group), 그룹 |
| `has_permission` | identity, external | 모두 |
| `authenticates_to` | identity | service, host |
| `session` | identity (그룹 제외) | host, service |
| `stores` | 모두 | credential, data |
| `grants` | credential, host, service | identity |
| `contains` | data_store, host, service | data |
| `routes_via` | 그룹 | network_device |
| `reaches`, `trusts`, `depends_on`, `manages` | 모두 | 모두 |

---

## 13. 남은 결정 사항

- [ ] 로그 스케일 영향도의 밑 `b`
- [ ] 다중 목표 달성 시 영향도 합산 규칙
- [ ] 사전분포의 출처 (공개 통계 vs 전문가 설정)
- [ ] 공격 단계 규칙 DSL (전제조건 → 상태 변화)
- [x] ~~공격자 상태 모델~~ → `docs/attacker-state.md` (거점, 신원, 자격증명, 그룹 장악, 데이터 접근, 지식)
- [ ] 여러 입력의 개체 병합 (같은 서버가 Terraform, 스캔, 디렉터리에 다른 이름으로 나올 때) → P5
- [x] ~~확신도와 확률 분포의 연결~~ → 3.1
- [x] ~~실행 상태(세션, 실행 계정)~~ → 6.0
- [x] ~~서비스 보안 설정 구조~~ → 5.7
- [ ] 직렬화: YAML + JSON Schema 확정 여부
- [ ] MAL coreLang, BloodHound OpenGraph와의 변환 지원 여부
- [ ] 일시적 권한, 시간 축
