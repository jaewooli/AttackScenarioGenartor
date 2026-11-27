"""scengen CLI.

사용:
    scengen validate <ir.yaml> [...]

종료 코드: 0 = 오류 없음 (경고는 허용), 1 = 오류 있음, 2 = 사용법 오류
"""

from __future__ import annotations

import argparse
import sys

from .ir import validate_file


def _cmd_validate(args: argparse.Namespace) -> int:
    worst = 0
    for path in args.files:
        try:
            result = validate_file(path)
        except OSError as e:
            print(f"{path}: 파일을 열 수 없음: {e}", file=sys.stderr)
            worst = max(worst, 2)
            continue
        for issue in result.issues:
            if issue.level == "warning" and args.quiet:
                continue
            print(f"{path}: {issue}")
        status = "OK" if result.ok else "FAIL"
        print(f"{path}: {status} (오류 {len(result.errors)}, 경고 {len(result.warnings)})")
        if not result.ok:
            worst = max(worst, 1)
    return worst


def _cmd_mitigations(args: argparse.Namespace) -> int:
    from .ir.mitigations import LABEL, STATUSES, check, render_markdown

    if args.markdown:
        print(render_markdown())
        return 0
    report = check()
    for p in report.problems:
        print(f"[problem] {p}")
    print("처음: " + ", ".join(f"{LABEL[s]} {report.initial.get(s, 0)}" for s in STATUSES))
    print("현재: " + ", ".join(f"{LABEL[s]} {report.current.get(s, 0)}" for s in STATUSES))
    print(f"M0.5 완화책 조건: {'통과' if report.passes_gate else '미통과'}")
    return 0 if report.passes_gate else 1


def _cmd_techniques(args: argparse.Namespace) -> int:
    from .ir.mitigations import LABEL, STATUSES
    from .ir.techniques import ROLE_LABEL, ROLES, check, render_markdown

    if args.markdown:
        print(render_markdown())
        return 0
    report = check()
    for p in report.problems:
        print(f"[problem] {p}")
    print("역할: " + ", ".join(f"{ROLE_LABEL[r]} {report.roles.get(r, 0)}" for r in ROLES))
    print("상태: " + ", ".join(f"{LABEL[s]} {report.status.get(s, 0)}" for s in STATUSES))
    print(f"공격 기법 대조: {'통과' if report.passes else '미통과'}")
    return 0 if report.passes else 1


def _cmd_crosswalk(args: argparse.Namespace) -> int:
    from .ir import crosswalks
    from .ir.mitigations import LABEL, STATUSES

    targets = [args.name] if args.name else crosswalks.names() + ["d3fend"]
    if args.markdown:
        if len(targets) != 1:
            print("--markdown 은 대조표 이름 하나와 함께 쓴다", file=sys.stderr)
            return 2
        md = crosswalks.d3fend_markdown() if targets[0] == "d3fend" else crosswalks.render_markdown(targets[0])
        print(md)
        return 0
    worst = 0
    for name in targets:
        r = crosswalks.d3fend_check() if name == "d3fend" else crosswalks.check(name)
        for p in r.problems:
            print(f"[problem] {p}")
        counts = ", ".join(f"{LABEL[s]} {r.status.get(s, 0)}" for s in STATUSES)
        print(f"{name}: {counts} → {'통과' if r.passes else '미통과'}")
        if not r.passes:
            worst = 1
    return worst


def _cmd_vocab(args: argparse.Namespace) -> int:
    from .ir.vocab import CONFIG_KEYS, render_markdown

    if args.markdown:
        print(render_markdown())
    else:
        for key, spec in CONFIG_KEYS.items():
            print(f"{key}\t{spec.kind}\t{','.join(spec.applies_to)}")
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    from .engine import analyze_doc, analyze_doc_rules
    from .ir import load_ir

    try:
        doc = load_ir(args.file)
    except OSError as e:
        print(f"{args.file}: 파일을 열 수 없음: {e}", file=sys.stderr)
        return 2
    res = validate_file(args.file)
    if not res.ok:
        for err in res.errors:
            print(f"{args.file}: {err}", file=sys.stderr)
        return 1

    if args.engine == "thin":
        variants = analyze_doc(doc)
    else:
        from .engine.rule_eval import RuleEvalError

        try:
            variants = analyze_doc_rules(doc)
        except RuleEvalError as e:
            print(f"rules/: {e}", file=sys.stderr)
            return 1
    for v in variants:
        print(f"=== [{v.profile_id}] knowledge={v.knowledge}, egress={v.egress} (사실 {len(v.facts)}개) ===")
        for g in v.goals:
            mark = "달성" if g.achieved else "미달성"
            print(f"  - {g.goal_id} ({g.harm}, impact={g.impact_level}): {mark} p={g.prob:.4f}")
            if g.achieved and args.paths:
                for idx, path in enumerate(g.paths, 1):
                    print(f"    [경로 {idx}]")
                    for step in path:
                        print(f"      {step.rule_id} -> {step.conclusion} (p={step.prob}) [{step.note}]")
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    from .rules import load_rules

    res = load_rules()
    for err in res.errors:
        print(f"[error] {err}", file=sys.stderr)
    print(
        f"규칙 {len(res.rules)}개 로드 "
        f"(참조 관계 {len(res.referenced_relations)}종, 설정 키 {len(res.referenced_configs)}종): "
        f"{'통과' if res.ok else '미통과'}"
    )
    return 0 if res.ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scengen")
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="IR 파일 검증")
    p_val.add_argument("files", nargs="+")
    p_val.add_argument("-q", "--quiet", action="store_true", help="경고 숨김")
    p_val.set_defaults(func=_cmd_validate)

    p_mit = sub.add_parser("mitigations", help="ATT&CK 완화책 대조표 검사")
    p_mit.add_argument("--markdown", action="store_true", help="대조표 문서를 출력")
    p_mit.set_defaults(func=_cmd_mitigations)

    p_tec = sub.add_parser("techniques", help="ATT&CK 공격 기법 대조표 검사")
    p_tec.add_argument("--markdown", action="store_true")
    p_tec.set_defaults(func=_cmd_techniques)

    p_cw = sub.add_parser("crosswalk", help="참조 문서 대조표 검사 (CIS Controls, D3FEND 등)")
    p_cw.add_argument("name", nargs="?", help="대조표 이름 (생략하면 전부)")
    p_cw.add_argument("--markdown", action="store_true")
    p_cw.set_defaults(func=_cmd_crosswalk)

    p_voc = sub.add_parser("vocab", help="설정 키 사전 출력")
    p_voc.add_argument("--markdown", action="store_true")
    p_voc.set_defaults(func=_cmd_vocab)

    p_ana = sub.add_parser("analyze", help="IR 분석 실행 (기본: src/scengen/rules/*.yaml DSL 규칙 평가기)")
    p_ana.add_argument("file")
    p_ana.add_argument(
        "--engine", choices=["rules", "thin"], default="rules",
        help="rules: DSL 규칙 평가기(기본), thin: 얇은 엔진(회귀 기준선)",
    )
    p_ana.add_argument("--paths", action="store_true", help="달성된 목표의 대표 경로 출력")
    p_ana.set_defaults(func=_cmd_analyze)

    p_rul = sub.add_parser("rules", help="규칙셋(src/scengen/rules/*.yaml) 로드 및 검증")
    p_rul.set_defaults(func=_cmd_rules)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
