# 공격 단계 규칙 DSL 명세 (WBS 2.2)

> 얇은 엔진(`src/scengen/engine/thin.py`)에서 R1~R11(+ R10b, D2~D4)을 직접 구현·검증한 결과를 바탕으로 확정한 선언적 규칙 형식.
> 모든 규칙은 **추상 수준**(전제조건 → 공격자 상태 변화, ATT&CK 기법 ID 참조)으로만 기술하며, 실행 가능한 공격 절차나 익스플로잇 코드는 포함하지 않는다 (`CLAUDE.md` 5장).

---

## 1. 규칙 파일 구조

규칙은 `src/scengen/rules/*.yaml`에 목록(`rules: [...]`) 형태로 저장한다.

```yaml
rule_version: "0.1"
rules:
  - id: R10
    name: "노출 서비스 침해"
    category: transition            # transition | discovery | privilege_escalation
    attack_techniques: [T1190]
    vars:
      src: { type: asset }
      host: { type: asset, asset_type: host }
      svc: { type: asset, asset_type: service }
    when:
      - relation: { type: runs, from: $host, to: $svc }
      - neq: [$src, $host]
      - reaches: { from: $src, to: $host, port: $svc.port }
    requires:
      - foothold($src, none)
      - knows($host)                # knowledge=uninformed 일 때만 자동/명시 적용
    adds:
      - foothold($host, user)
    probability:
      base: { kind: beta, alpha: 3.5, beta: 6.5 }
      capability_scale: true
      modifiers:
        - when: { config: [$svc, app.secure_development, true] }
          factor: 0.55
        - when: { config: [$svc, network.application_filtering, true] }
          factor: 0.70
        - when: { config: [$host, host.patch_currency, lagging] }
          factor: 1.80
        - when: { config: [$host, host.patch_currency, current] }
          factor: 0.75
```

---

## 2. 핵심 절(Clause) 정의

| 필드 | 필수 | 설명 |
|---|---|---|
| `id` | 예 | 고유 규칙 ID (예: `R1`~`R11`, `R10b`, `D2`~`D4`) |
| `name` | 예 | 사람이 읽는 규칙 이름 |
| `category` | 예 | `transition`(상태 전이), `privilege_escalation`(권한 상승), `discovery`(정찰·발견) |
| `attack_techniques` | 아니오 | 관련 MITRE ATT&CK 기법 ID 목록 |
| `vars` | 예 | 바인딩 변수 선언. `type`: `asset`, `identity`, `group`(그룹 id), `level`(권한 수준), `value`(관계 속성 값). `asset_type`, `kind`로 범위 제한 |
| `when` | 예 | IR 그래프 조건. 사용할 수 있는 절은 6장 표 (로더가 그 밖의 절을 오류로 처리) |
| `requires` | 예 | 공격자 상태(`Fact`) 전제조건 목록 (`docs/attacker-state.md` 어휘 사용) |
| `adds` | 예 | 규칙 성공 시 추가되는 결론 `Fact` |
| `probability` | 예 | 성공 확률 분포(`base`), `capability_scale`, 조건별 승수(`modifiers`) |

---

## 3. 얇은 엔진 구현에서 도출된 설계 요구사항

`shop-hybrid.ir.yaml`과 단위 테스트(`tests/test_thin_engine.py`)를 통해 다음 요구사항을 확인했다.

1. **로컬 권한 상승(`R10b`) 필수**: `R10`(외부 노출 서비스 침해)은 `foothold(host, user)`를 부여하는 반면, `R4`·`R5`·`R6`·`R8`·`R9`·`R11`은 `foothold(host, admin)`을 요구한다. 따라서 `user → admin` 권한 상승 규칙을 별도 `privilege_escalation` 범주로 두어야 연쇄가 성립한다.
2. **자기 자신 재침해 방지(`neq: [$src, $host]`)**: `R10`처럼 네트워크 도달성을 전제로 하는 규칙은 출발 거점과 대상 호스트가 같을 때 발동하지 않아야 순환·과대 확률 계산을 막을 수 있다.
3. **`knows` 전제의 명시적 DAG 편입**: `uninformed` 변형에서는 `knows(target)`을 단순 필터가 아니라 `DerivationStep.premises`에 포함해야 정찰 확률이 경로 확률에 정상 반영된다.
4. **거부 우선(`not_denied`) 및 암호화 키(`encrypted` + `key_ref`)**: `has_permission`은 동일 행위 또는 `admin`의 `deny` 엣지를 우선 검사해야 하며, `contains.encrypted`가 참이면 `read`에 `has_credential($key_ref)`가 추가 전제로 붙는다.
5. **IR 확신도와의 결합**: 규칙 확률 = `(base 분포 표본 × modifiers × capability_factor) × Π(사용된 IR 관계/속성의 confidence)`.
   - 참고: `probability.base`의 `beta` 분포 표본화는 **P3 몬테카를로 엔진**에서 수행하며, 현재 얇은 엔진(`thin.py`)은 `base`의 기대값(고정 소수) × `modifiers` × `capability_factor`로 근사한다.

---

## 4. P2 보류 항목 결정

`STATUS.md` 및 `docs/crosswalk/README.md`의 보류 항목 3건을 아래처럼 확정한다.

| 항목 | 결정 | 이유 |
|---|---|---|
| 데이터 흐름(`data_flow`) 엣지 추가 여부 | **MVP 보류** | 현재 `contains` + `reaches` + `egress` 변형으로 유출 경로 판정이 가능함. ETL·복제 파이프라인 분석 시(P3 이후) 재검토 |
| 방어 무력화 상태를 공격자 상태에 넣을지 | **MVP 보류** | 단조성 가정(탐지·시간 모델 제외) 하에서는 `config` 값의 확신도·분포와 `foothold(admin)`으로 근사. 탐지 모델 도입 시("나중에") 추가 |
| 인증서 템플릿 노드 타입 추가 여부 | **MVP 보류** | `credential(kind: certificate)`와 `policy` 노드로 근사. AD CS 세부 규칙(ESC1~ESC8) 확장 시 별도 타입 추가 검토 |

---

## 5. 감사표 "의미 미정" 7개 필드 정의

| 필드 | 정의 (MVP 기준) |
|---|---|
| `attacker_profile.capability` | 확률적 침해·권한 상승 규칙(`capability_scale: true`)에 곱하는 역량 계수: `low=0.45`, `medium=0.70`, `high=0.88`, `advanced=0.96` |
| `asset.credential.kind` | R7(자격증명 사용) 성공 확률 사전값 (`password=0.90`, `token=0.95`, `key=0.95`, `certificate=0.85`, `hash=0.55`) |
| `asset.data.volume` | 영향도 산정 시 레코드 수 기반 자릿수 보정 가중치 (`records` 로그 스케일) |
| `asset.data.regulations` | 규제 대상 데이터(`PIPA`, `PCI-DSS` 등)일 때 목표 영향도 상향 보정 |
| `asset.business_service.downtime_impact` | `per_hour` 등급(`low/medium/high/critical`)을 자동 생성 `disrupt` 목표의 `impact.level` 기본값으로 매핑 |
| `context.analysis` | `focus_categories` 등 목표 생성기(G)의 필터 및 우선순위 가중치 |
| `context.organization` | `priorities` (`C/I/A: low|medium|high`)를 목표의 `harm` 축별 위험도 가중치로 반영 |

---

## 6. 규칙 평가기 실행 의미 (WBS 3.1, `src/scengen/engine/rule_eval.py`)

`scengen analyze`의 기본 엔진. 얇은 엔진(`--engine thin`)은 회귀 기준선으로 남긴다.
`core.yaml`만 쓰면 두 샘플의 모든 변형에서 사실 집합이 얇은 엔진과 **정확히 같다** (`tests/test_rule_eval.py`).

### 6.1 규칙 1건의 평가 순서
1. `requires`의 사실 패턴(`knows` 제외)을 현재 사실 집합과 맞춰 변수를 묶는다. `any`는 대안 중 하나.
2. `when` 절을 계획기가 고른 순서로 평가한다: 변수가 모두 묶인 절 → 생성 절(`relation`, `asset_type`, `asset_role`, `in_group`, `group_parent`) → 나머지(필요하면 변수 도메인을 열거).
3. `knows` 전제를 확인한다. `uninformed` 변형에서만 전제로 붙고, `informed`에서는 빠진다. `discovery` 규칙은 `uninformed`에서만 돈다.
4. `adds`의 사실을 만든다. 결론이 전제에 이미 있으면 만들지 않는다 (예: admin 거점에서 R10b).
5. 고정점까지 반복한다. 같은 (규칙, 결론, 전제)는 확률이 가장 높은 바인딩 하나만 남긴다.

### 6.2 사실 패턴
| 패턴 | 의미 |
|---|---|
| `foothold($x, L)` (requires) | 수준 L **이상**인 거점 중 자산별 최고 수준 사실 하나와 맞춘다 |
| `foothold($x, L)` (adds) | 정확히 수준 L. `L`은 `level` 변수일 수 있다 (예: R2의 `privilege: $lvl`) |
| 그 밖 | 인자가 모두 같은 사실과 맞춘다 |

### 6.3 when 절
| 절 | 형식 | 의미 |
|---|---|---|
| `relation` | `{type, from, to, <속성>: 값/$var, action_in, expand_groups}` | 관계 1건과 맞춘다. 속성 생략 시 기본값: `effect=allow`, `action=read`, `encrypted=false`, `privilege=user`, `frequency=unknown`. `$var` 값은 속성을 변수에 묶는다. 끝점이 `group:` 참조면 그룹 변수는 그룹 id, 자산 변수는 소속 자산으로 펼친다 (`inherit: false` 또는 `expand_groups: false`면 펼치지 않음). `from`/`to`를 생략하면 아무 값 |
| `reaches` | `{from, to, port, protocol}` | `InfraGraph.can_reach`. `$svc.port`처럼 자산 속성을 쓸 수 있다 |
| `config` | `[$x, key, value]` | 설정 값(자산 > 그룹 > `context.defaults`)이 value와 같음 |
| `config_set` | `[$x, key]` | 설정 값이 비어 있지 않음 |
| `not_denied` | `{from, to}` | 앞서 맞춘 허용 권한과 같은 행위(또는 `admin`)의 `deny` 엣지가 없음 |
| `neq` / `eq` | `[a, b]` | 값 비교 |
| `same_group` | `[$a, $b]` | 직접 소속 그룹이 하나 이상 겹침 |
| `asset_type` | `{asset, type}` | 자산 타입 |
| `asset_role` | `{asset, role, in_group, group_kind}` | 자산 역할. `in_group`은 직접 소속 그룹을 묶고 `group_kind`로 거른다 |
| `in_group` | `{asset, group}` | 조상 그룹 포함 소속 |
| `group_parent` | `{child, parent}` | 그룹 계층 |
| `any` / `all` / `not` | 절 목록 / 절 | 합집합 / 모두 / 존재하지 않음(안쪽 변수는 밖으로 묶이지 않음) |

### 6.4 확률 (WBS 3.4 전까지의 점 추정)
`p = min(0.99, mean(base) × Π(일치한 modifiers) × (capability_scale이면 역량 계수) × Π(사용한 관계·도달성·설정의 confidence))`
- 조건부 권한(`has_permission.condition`)은 조건 충족 여부를 모르므로 × 0.7.
- 유도 단계의 `source_relations`에 사용한 IR 근거(`관계타입:from->to`, `config:자산.키`)를 기록한다. 가정 표시·정보 가치(P7)의 입력.
- 얇은 엔진과 확률이 다른 곳: R10(인증 서비스 승수가 규칙 파일로 옮겨지며 근사가 바뀜), R5(빈도를 승수로 표현), R2/R8(base 기대값 사용). 사실 집합은 같다.

### 6.5 재현성
사실·자산·관계를 항상 정해진 순서로 순회한다. `PYTHONHASHSEED`가 달라도 유도 단계 목록이 같다 (테스트로 확인).

### 6.6 WBS 3.1에서 규칙 파일에 반영한 것
얇은 엔진에는 있었으나 규칙 파일에 없던 의미를 옮겼다: R2 권한 수준(`privilege`)·서비스 로그인(`R2-service`), R3 외부 주체·직접 데이터·execute/admin 분리·`add_member`는 그룹만, R5 세션 빈도, R8 하위 그룹·소속 호스트(`R8-subgroup`, `R8-members`)와 DC→도메인 한정, R9 쓰기·직접 암호화, R10 인증 승수, R10-managed는 실행 호스트 없는 서비스만, R11은 그룹 대상 제외.
확장 규칙 R15는 대상을 호스트로 제한했다 (도메인 간 `trusts`를 펼치면 신원에 거점이 생기던 오류).
