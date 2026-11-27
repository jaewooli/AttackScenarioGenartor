# CLAUDE.md — 공격 시나리오 생성기 (39_SCENARIO/01_ATTACK)

작업을 시작하기 전에 **이 파일 → STATUS.md → 해당 WBS 항목** 순서로 읽는다.

## 1. 프로젝트 목적 (북극성)

> **어떤 인프라든 입력받아, 그 인프라에서 가능한 공격 시나리오를 빠짐없이 생성하고,
> 위험도가 가장 높은 시나리오를 근거와 함께 top-k로 제시한다.**

세 가지 약속:
1. **어떤 인프라든**: 클라우드, 온프레미스, 디렉터리 서비스, OT, 하이브리드. 정보가 적어도 동작한다.
2. **빠짐없이**: 모든 경우의 수는 DAG에 압축해서 담는다. 개별 시나리오는 top-k만 펼친다.
3. **근거와 함께**: 순위마다 확률 분포, 가정 여부, 추가로 확인할 정보를 보여준다.

## 2. 차별점 (이걸 잃으면 이 프로젝트를 할 이유가 없다)
- 런타임 접근 없이 **설계/구성 정보만으로** 분석 (배포 전 분석 가능)
- 자산마다 **세부 수준이 섞여도** 동작 (대략 ↔ 세부가 연속적)
- **가정과 확정을 구분**하고, "이 정보를 주면 순위가 바뀐다"를 알려줌
- **결합 영향**(따로는 약하고 합치면 큰 피해)과 **인프라 전체 맥락**을 반영
- 순위는 **재현 가능한 엔진**이 정한다. LLM은 입력 번역과 분리된 검토 층에서만 쓴다.

## 3. 작업 시 점검 질문
새 기능이나 설계 변경 전에 확인한다. 하나라도 "아니오"면 멈추고 사용자와 상의한다.
1. 1장의 세 가지 약속 중 하나 이상에 기여하는가?
2. 2장의 차별점을 약화시키지 않는가? (특히 재현성, 가정 표시)
3. 지금 단계(STATUS.md의 현재 단계)의 범위 안인가?

## 4. 하지 않는 것 (Non-goals)
- 공격을 실제로 실행하는 도구가 아니다 (침투 자동화, 익스플로잇 코드 작성 안 함)
- 취약점 스캐너나 런타임 보안 점검(CSPM) 도구가 아니다
- LLM 단독으로 순위를 정하지 않는다
- 02_DEFENSE(방어 시나리오)는 별도 프로젝트. 이쪽은 연결 가능한 출력 형식만 신경 쓴다

## 5. 보안 및 데이터 원칙
- 이 프로젝트는 방어와 위험 평가 목적이다.
- 샘플 인프라(GOAD 등)는 **인프라 구성만** 가져온다. 비밀번호, 자격증명, 취약 설정 상세, 공격 절차는 저장소에 넣지 않는다.
- 공격 단계 규칙은 **추상 수준**(전제조건 → 공격자 상태 변화, ATT&CK 기법 ID 참조)으로 쓰고, 실행 가능한 절차나 명령은 쓰지 않는다.
- 외부에서 받은 파일은 스크래치 영역의 별도 디렉터리에 두고, 필요한 부분만 정리해서 옮긴다.

## 6. 핵심 설계 결정 (상세는 docs/ir-spec.md)
| 결정 | 요약 |
|---|---|
| 그래프 IR | 자산 = 노드, 관계 = 엣지. 그룹은 계층 가능, 규칙은 묶음 단위 |
| Attr | 모든 값에 `source`(declared/inferred/assumed/unknown) + `confidence` |
| LoD | L0 토폴로지 ~ L3 코드. 자산별로 혼합, 모드 구분 없음 |
| 권한 | (주체, 추상 행위, 대상, 조건, 허용/거부)로 정규화, 펼치지 않음 |
| 데이터 | `data`(무엇)와 `data_store`(어디) 분리 |
| 목표 | "여기서 멈춰도 피해가 생기는 상태". 대상 × 피해 행위, AND/OR 결합. 디렉터리 도메인 장악은 예외적으로 목표 |
| 위험도 | P(목표) × 영향도. 확률은 분포 + 몬테카를로, 영향도는 로그 스케일(밑 미정) |
| 탐색 | 목표에서 역방향 DAG, tabling, 단조성 가정 |
| 맥락 | 사실/구조/파라미터/분석 설정으로 번역, 치환 불가는 분리된 LLM 검토 층 |

설계 결정을 바꾸면 이 표, `docs/ir-spec.md`, STATUS.md의 결정 기록을 함께 갱신한다.

## 7. 문서와 디렉터리
| 경로 | 내용 |
|---|---|
| `CLAUDE.md` | 이 파일. 목적, 원칙, 작업 규칙 |
| `ROADMAP.md` | 단계와 마일스톤 |
| `WBS.md` | 작업 분해와 일정 |
| `STATUS.md` | 현재 단계, 진행 상황, 결정 기록, 막힌 것 |
| `docs/ir-spec.md` | IR 스펙 (현재 v0.2) |
| `docs/attacker-state.md` | 공격자 상태 모델 (WBS 2.1) |
| `docs/rule-dsl.md` | 규칙 DSL 형식과 평가기 실행 의미 (WBS 2.2, 3.1) |
| `docs/ir-field-audit.md` | IR 필드 감사 (엔진이 읽는가 × 입력에서 얻는가) |
| `docs/mitigation-coverage.md` | ATT&CK 완화책 대조표 (**생성 문서**, 원본: `src/scengen/ir/mitigation_map.yaml`) |
| `docs/config-keys.md` | 설정 키 사전 (**생성 문서**, 원본: `src/scengen/ir/vocab.py`) |
| `docs/crosswalk/` | 참조 문서 대조표 (**생성 문서**, `README.md`만 손으로 씀). 원본: `src/scengen/ir/technique_map.yaml`, `crosswalk_d3fend.yaml`, `crosswalk/*.yaml` |
| `docs/samples/` | 샘플 인프라 IR |
| `src/scengen/` | 패키지 (`ir/validate.py`: 검증기, `schema/`: JSON Schema, `cli.py`) |
| `src/scengen/rules/*.yaml` | 공격 단계 규칙 (`core.yaml`: 기준 규칙, `extended.yaml`: 확장). 패키지에 포함되어 설치된다 |
| `src/scengen/engine/` | `rule_eval.py`: 규칙 평가기(기본 엔진), `thin.py`: 얇은 엔진(회귀 기준선), `graph.py`, `goals.py`, `model.py` |
| `tests/` | pytest |

개발 명령: `.venv/bin/scengen validate <파일>`, `.venv/bin/scengen rules`, `.venv/bin/scengen analyze <파일> [--paths] [--engine thin]`, `.venv/bin/pytest`
- 규칙을 바꾸면 `scengen rules`와 `tests/test_rule_eval.py`(core 규칙 사실 집합 = 얇은 엔진)가 통과해야 한다.
스펙을 바꾸면 JSON Schema와 검증기, 샘플을 함께 맞추고 테스트를 돌린다.
- 스키마 필드를 추가·삭제하면 `docs/ir-field-audit.md` 표에 판정을 적어야 테스트가 통과한다.
- 설정 키를 추가하면 `docs/samples/shop-hybrid.ir.yaml`에서 한 번 이상 쓰고, 생성 문서를 다시 만든다.
- 생성 문서(`mitigation-coverage.md`, `config-keys.md`, `docs/crosswalk/*.md`)는 직접 고치지 않는다.
- 참조 문서 대조 검사: `scengen mitigations`, `scengen techniques`, `scengen crosswalk`. IR을 바꾸면 이 셋이 모두 통과해야 한다.
- 라이선스가 제한된 참조 문서(CIS 등)는 번호와 자체 요약만 저장한다. 원문 제목·본문을 저장소에 넣지 않는다.

## 8. 작업 규칙
- 작업 단위는 WBS 항목 ID로 부른다 (예: `WBS 2.1`).
- 작업을 끝내면 STATUS.md의 진행 상황과 WBS 상태를 갱신한다.
- 일정이 밀리면 WBS의 날짜를 조용히 바꾸지 말고 STATUS.md에 이유와 함께 기록한다.
- 범위 밖 아이디어는 바로 구현하지 않고 ROADMAP.md의 "나중에" 목록에 적는다.
- 응답과 문서는 한국어로 쓴다.
