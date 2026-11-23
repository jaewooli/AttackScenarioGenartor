# WBS 2.2 규칙 DSL 초안 v0.1

규칙 하나는 검증된 IR에서 한 결론을 평가한다. 아래 YAML은 제안 문법이다. 현재 Python 프로토타입은 규칙을 코드로 평가한다.

```yaml
id: R10
version: 1
when:
  all:
    - relation: {type: reaches, from: "$external", to: "$group"}
    - relation: {type: runs, from: "$host", to: "$service"}
    - check: {name: group_membership, args: ["$host", "$group"]}
    - check: {name: service_endpoint_matches, args: ["$service", "$external", "$group"]}
then: {kind: candidate, subject: "$service", question: "경유 장비가 이 서비스로 전달하는가?"}
attack_ids: []
prior: null
```

## 규칙과 평가 기록

- id와 version이 규칙을 식별한다. 달러 기호로 시작하는 변수는 패턴에서 바인딩한다. 같은 변수는 같은 IR 객체를 가리킨다. 출력과 검사에서 참조하는 변수는 앞선 패턴에서 바인딩해야 한다.
- all은 같은 바인딩에서 모든 조건을 요구한다. relation은 관계 유형과 방향을 일치시키고, check는 이름이 등록된 판정만 호출한다. 전제가 명시적으로 거짓이면 해당 바인딩에서 결론을 생성하지 않는다.
- attack_ids는 검토된 ATT&CK 기법 참조 목록이다. prior는 단계 성공에 대한 사전분포 참조다. null이면 수치 평가를 보류한다. IR의 confidence는 입력 근거에 대한 확신도다.
- 각 결과에 규칙 ID와 버전, 입력 버전, 프로필, 바인딩, 전제 사실과 IR 근거를 기록한다. 같은 결론의 독립적인 도출 근거는 각각 보존한다. 출력은 결론과 근거 식별자 순으로 정렬한다.

| 결과 | 판정 기준 | 필수 기록 |
|---|---|---|
| 확정 사실 | 결론에 필요한 전제가 모두 확인되고 규칙의 효과가 결정적 | 결론과 전체 근거 |
| 평가 후보 | 관측된 조건이 있으며 규칙에 명시된 추가 확인으로 결론을 판정할 수 있음 | 관측 근거와 확인 질문 |
| 미평가 | 필요한 정책 의미나 검사 연산을 지원하지 않음 | 해당 필드와 보류 이유 |

후속 결정론적 규칙의 전제로는 확정 사실만 사용한다. 조건부 권한의 조건 해석이나 상속된 거부의 우선순위가 미정이면 권한 판정을 보류한다. 도달성 검사에서는 포트, 프로토콜, 경유 조건을 근거에 포함한다.

## shop-hybrid 판정 예시

| 샘플 근거 | 평가할 결론 | 기대 결과 |
|---|---|---|
| hosts(db-01, store-db) | 구성에 선언된 저장소 배치 | 확정 사실. 이 관계를 입력 근거로 보존 |
| ext-internet에서 group:nsg-web로 TCP 443 허용, via가 lb-01 | svc-web 외부 노출 | 평가 후보. 서비스 포트·그룹이 일치해도 lb-01의 전달 설정 확인 필요 |
| role-backup이 store-backup에 write 권한 보유 | 저장된 각 데이터의 수정 가능 여부 | 미평가. 저장소 쓰기 권한이 개별 데이터에 미치는 의미 미정 |

세 예시는 프로토타입의 `assessments` 출력과 통합 테스트에서 확인한다. 구성 관계와 저장소 권한의 해석 범위는 입력 전체에서 평가하고, 외부 노출 후보는 프로필별로 평가한다. 각 기록의 evidence는 입력 관계의 식별자다. 규칙 버전 및 입력 버전 연결은 후속 과제다.
