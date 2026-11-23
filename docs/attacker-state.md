# 공격자 상태 모델 (WBS 2.1) — 확정 2026-11-21

> 엔진이 "공격자가 지금 무엇을 가지고 있는가"를 표현하는 방식.
> 규칙(2.2)은 이 상태를 전제조건으로 읽고, 결과로 새 상태를 더한다.
> 이 문서는 **추상 수준**만 다룬다. 구체적인 공격 절차는 다루지 않는다 (CLAUDE.md 5장).

## 1. 결론 (제안)

**공격자 상태 = 사실(fact)들의 집합.** 자산×권한 쌍만으로는 부족하고, 신원과 자격증명을 별도 사실로 둔다.

| 사실 | 의미 | 예 |
|---|---|---|
| `foothold(asset, level)` | 해당 호스트/서비스에서 그 권한 수준으로 무언가를 실행할 수 있음 | `foothold(srv02, user)` |
| `acts_as(identity)` | 해당 주체로 행동할 수 있음 (인증된 상태로 쓸 수 있음) | `acts_as(u-jon)` |
| `has_credential(credential)` | 자격증명 자료를 보유함 (쓸 수 있는지는 별개) | `has_credential(cred-backup-key)` |
| `controls(group)` | 그룹(도메인, 클라우드 계정 등) 전체에 대한 관리 권한 | `controls(group:dom-north)` |
| `data_access(data, mode)` | 데이터를 읽거나(read) 쓸(write) 수 있음 | `data_access(data-customer, read)` |
| `knows(target)` | 공격자가 그 자산/주체/그룹의 존재를 앎. **구조를 모르는 공격자 변형에서만 쓴다** (6.1) | `knows(db-01)` |

**권한 수준**: `none < restricted < user < admin < system`. 높은 수준은 낮은 수준을 포함한다.

## 2. 왜 자산×권한만으로는 부족한가

| 상황 | 자산×권한만 쓰면 | 신원/자격증명을 따로 두면 |
|---|---|---|
| 디렉터리·클라우드 환경에서 한 계정으로 여러 서버에 접근 | 서버마다 따로 표현해야 하고, "같은 계정 덕분"이라는 공통 원인이 사라짐 | `acts_as(u)` 하나 + IR의 `authenticates_to` 엣지들로 표현 |
| 암호화된 백업 + 다른 곳의 키 (결합 목표) | 키를 얻은 상태를 표현할 곳이 없음 | `has_credential(key)` |
| 자격증명은 얻었지만 그게 통하는 곳에 아직 닿지 못함 | 구분 불가 | `has_credential` 있음, `acts_as` 없음 |
| 그룹 전체 장악 (도메인, 클라우드 계정) | 소속 자산 수만큼 사실이 폭발 | `controls(group)` 하나, 소속은 IR에서 풂 |

이 구분은 IR에 이미 있는 엣지(`grants`: 자격증명 → 주체, `authenticates_to`, `session`, `member_of`)와 그대로 맞물린다.

## 3. 계산하지만 저장하지 않는 것

- **네트워크 위치**: "어디에서 어디로 닿는가"는 `foothold`들과 IR의 도달성 규칙(스펙 6.1)으로 그때그때 계산한다. 사실로 저장하지 않는다.
- **그룹 소속에서 오는 권한**: `acts_as(u)`이고 u가 그룹 g의 구성원이면, g의 권한은 IR의 `member_of`를 따라 풀어서 쓴다.

## 4. 시작 상태

`attacker_profiles`에서 만든다.

| 프로필 | 시작 사실 |
|---|---|
| 외부 공격자 (`start: [external:internet]`) | `foothold(external:internet, none)` — 인터넷 쪽 네트워크 위치만 있음 |
| 내부자 (`start: [ws-01]`, `initial_privilege: user`) | `foothold(ws-01, user)` + 그 단말의 `session`에 연결된 주체가 있으면 `acts_as` |
| `context.known_state` | 적힌 사실을 그 확률로 추가 (예: 이미 유출된 데이터, 이미 탈취된 계정) |

## 5. 목표 조건과의 대응

목표 조건(스펙 8장)과 맥락의 사실은 **같은 어휘**를 쓴다.

| 조건 키 | 공격자 상태로 판정 |
|---|---|
| `privilege: {asset, level}` | `foothold(asset, ≥level)` |
| `acts_as` | `acts_as(identity)` |
| `has_credential` | `has_credential(credential)` |
| `controls` | `controls(group)` 또는 자산의 `foothold(asset, admin 이상)` |
| `read` | `data_access(data, read)` |
| `exfiltrated` | `data_access(data, read)` AND 외부로 나가는 경로 (판정 방식은 변형에 따라 다름, 6.2) |
| `tampered` / `destroyed` | `data_access(data, write)` |
| `disrupted` | 업무 서비스가 의존하는 자산 중 하나에 대한 `foothold(admin 이상)` 또는 `controls` |
| `misused` | 대상 자원에 대한 `foothold` 또는 해당 권한을 가진 `acts_as` |

## 6. 분석 변형과 가정

공격자에 대한 가정 두 가지는 하나로 고정하지 않고 **두 경우를 모두 분석한다.** 같은 인프라를 가정만 바꿔 돌리고, 결과를 나란히 비교한다.

### 6.1 인프라 구조 지식 (`knowledge`)

| 값 | 의미 | 엔진 동작 |
|---|---|---|
| `informed` | 공격자가 인프라 구조를 안다 (내부자, 유출된 설계 문서, 오래 잠복한 공격자) | 모든 `knows`가 처음부터 참. 정찰 단계 없음 |
| `uninformed` | 공격자는 처음에 시작점 주변만 안다 | 규칙이 대상을 노리려면 `knows(대상)`이 먼저 필요. `knows`는 "발견" 규칙으로 얻는다 (예: 거점에서 네트워크로 닿는 자산, 신원으로 조회할 수 있는 디렉터리 객체). 발견에도 확률이 붙는다 |

**두 결과의 차이가 곧 정보다.** `informed`에서만 상위에 오르는 시나리오는 "구조가 알려지지 않은 덕분에 지금은 덜 위험한 것"이다. 그래서 설계 문서 유출이나 내부자 위협에 민감한 지점을 보여준다.

### 6.2 외부로 나가는 경로 (`egress`)

| 값 | 의미 | 엔진 동작 |
|---|---|---|
| `assumed_open` | 데이터를 읽을 수 있으면 밖으로 가져갈 수도 있다고 가정 | `exfiltrated` = `data_access(read)` |
| `from_ir` | 외부로 나가는 경로를 IR로 확인해야 함 | `exfiltrated` = `data_access(read)` AND 공격자의 어떤 거점에서 `external`로 닿는 경로가 있음. 경로 정보가 IR에 없으면 사전분포(`assumed`)로 처리 |

두 결과의 차이는 **외부 통신 통제(egress 필터링)가 실제로 얼마나 효과가 있는지**를 보여준다. 방어 쪽(02_DEFENSE)에서도 쓸 수 있는 정보다.

### 6.3 변형 조합

`attacker_profiles`에 값을 하나만 쓰면 그 변형만, 목록으로 쓰면 조합마다 분석한다. **기본값은 둘 다 목록** (2 × 2 = 4개 변형).

```yaml
attacker_profiles:
  - id: external
    start: [external:internet]
    capability: medium
    knowledge: [informed, uninformed]     # 기본값
    egress: [assumed_open, from_ir]       # 기본값
```

결과는 변형별 top-k와 함께, **변형에 따라 순위가 크게 달라지는 시나리오**를 따로 보여준다.

| 변형 | 성격 |
|---|---|
| informed + assumed_open | 최악의 경우 (가장 보수적) |
| uninformed + from_ir | 현실에 가까운 경우 |
| 나머지 둘 | 각 가정의 영향을 분리해서 보기 위한 것 |

### 6.4 고정 가정과 한계

| 가정 | 의미 | 한계 |
|---|---|---|
| **단조성** | 얻은 사실은 잃지 않는다 | 자격증명 폐기, 세션 만료, 탐지 후 차단을 표현 못 함 |
| **시간 없음** | 단계 순서만 있고 소요 시간은 없음 | "얼마나 빨리"는 답하지 못함 |

## 7. 상태 공간 크기

사실의 개수 ≈ 자산 × 권한 수준(5) + 주체 수 + 자격증명 수 + 그룹 수 + 데이터 × 2 (+ `uninformed` 변형에서 `knows` 대상 수).
변형 4개를 돌리면 계산량도 최대 4배다.
GOAD 샘플(자산 64, 그룹 14) 기준 수백 개 수준이며, 자산 수에 비례해서 늘어난다(다항). 개별 경로가 아니라 사실 단위로 DAG를 만들기 때문에 경로 수 폭발을 피한다.

## 8. 결정 (2026-11-21 확정)

1. **자격증명과 신원 분리** (`has_credential` / `acts_as`) — 채택
2. **인프라 구조 지식**: 하나로 고정하지 않고 `informed` / `uninformed` 두 변형 모두 분석 (6.1)
3. **외부로 나가는 경로**: 하나로 고정하지 않고 `assumed_open` / `from_ir` 두 변형 모두 분석 (6.2)
