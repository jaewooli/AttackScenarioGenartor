# WBS 2.4 규칙별 IR 평가 가능성

판정 단위는 DSL v1 후보 한 건이다. 후보를 만들 근거와 후보가 제기하는 질문에 답할 근거를 구분했다.

| 규칙 | IR에서 사용하는 값 | 평가 범위와 보류 조건 |
|---|---|---|
| network-reach | reaches의 from, to. 시작 위치는 attacker_profiles.start | 동일 출발점의 선언된 연결을 찾을 수 있다. foothold는 실행 상태에서 공급한다. 그룹 소속, ports, protocol, via까지 검사해야 실제 도달성을 판정할 수 있다. |
| permission-scope | has_permission의 from, to, action, effect | 명시적 allow를 식별할 수 있다. 조건 적용과 상속된 deny의 우선순위는 별도 정책 의미론이 필요하다. |
| stored-data-read | has_permission의 action=read, effect=allow 및 contains의 from, to | 권한 대상과 데이터 보관 위치가 같은 경우만 후보로 삼는다. 개별 객체 권한과 암호화 조건은 추가 확인 대상이다. |
| discovery-uninformed | reaches의 from, to와 분석 시 선택한 지식 변형 | knows와 foothold가 같은 출발점을 가리켜야 한다. 둘 다 실행 상태다. uninformed 전용 선택은 규칙 파일 외부에 정의되어 있다. 연결 정보만으로 발견 성공을 확정할 수 없다. |

## 샘플 대조

shop-hybrid에서는 store-public에 대한 공개 읽기와 같은 저장소의 data-product-images 포함 관계가 결합된다. store-backup의 쓰기 권한은 이 읽기 후보에서 제외된다. 외부 시작점의 TCP 443 연결은 lb-01을 경유하므로 서비스까지의 전달 확인이 남는다. GOAD의 net-lab 그룹 간 연결에는 assumed 출처가 있으므로 출처와 확신도를 함께 보존해야 한다.

결론은 권한·보관 규칙 두 개가 IR 관계만으로 후보를 식별할 수 있고, 네트워크·발견 규칙 두 개는 IR에서 초기화하거나 앞 단계에서 도출한 프로필별 상태도 요구한다는 것이다. 네 규칙 모두 prior가 null이며 수치화는 보류한다. P3.1에서는 그룹 참조와 실행 상태를 제공하고, 선언되지 않은 입력 및 그룹 경계를 넘어선 조인을 검사한다.
