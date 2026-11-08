"""Selected result pairs; Native owns eligibility and current evidence checks, Python owns presentation."""
from decimal import Decimal, InvalidOperation, localcontext

from . import BackendError
from .comparison import _selection

_REASON_LABELS = {
    "invalid_run": "Run 合同校验未通过", "invalid_result": "结果记录校验未通过",
    "attempt_unresolved": "Attempt 归属尚未确定", "attempt_mismatch": "Attempt 不同",
    "workstream_mismatch": "工作线不同", "strategy_mismatch": "策略合同不同",
    "observability_insufficient": "执行可观察性不足", "contract_not_valid": "未证明实验合同有效",
    "execution_scope_mismatch": "执行状态不支持该结果范围", "run_mismatch": "结果指向其他 Run",
    "run_revision_mismatch": "结果与 Run 修订不一致", "extractor_mismatch": "解析器与 Run 合同不一致",
    "comparison_contract_mismatch": "比较合同不同", "evidence_incomplete": "结果证据不完整",
    "verifier_not_passed": "缺少通过的重解析验证", "metric_missing": "未记录可解析指标",
    "unit_mismatch": "指标单位不同", "duplicate_result": "重复选择了同一结果",
    "raw_evidence_unavailable": "原始受保护输入不可读", "evidence_budget_exceeded": "原始证据核对超出读取预算",
    "reparse_mismatch": "原始输入重解析与保存的指标不一致",
}
_DIMENSION_LABELS = {
    "code_snapshot": "代码快照", "data": "数据指纹", "fixed_config": "固定配置", "variables": "变量声明",
    "seed_policy": "seed 策略", "metric": "指标定义", "extractor": "解析器版本",
    "multi_cas": "多输入策略", "environment": "环境指纹", "comparison_execution_binding": "受控执行绑定",
}


def _difference(left, right):
    try:
        a, b = Decimal(left), Decimal(right)
        if not a.is_finite() or not b.is_finite():
            return None
        precision = max(a.adjusted(), b.adjusted(), 0) - min(a.as_tuple().exponent, b.as_tuple().exponent) + 2
        if not 1 <= precision <= 4096:
            return None
        with localcontext() as context:
            context.prec = precision
            return str(b-a)
    except (InvalidOperation, ValueError, TypeError, OverflowError):
        return None


def _page(pair):
    assessment = pair.get("result_assessment")
    page = {"frontier": pair["left"]["state"]["frontier"], "query": pair["query"],
        "assessment": assessment, "issues": [], "difference": None, "difference_omitted": False}
    for name in ("left", "right"):
        side = pair[name]
        page[name] = {"state": side["content_state"], "selection": side["selection"],
            "result": side["fields"] if side["content_state"] == "ready" and side["fields_complete"] else None}
    if assessment:
        page["issues"] = [{"member": issue["member"], "label": _REASON_LABELS.get(issue["reason"], issue["reason"]),
            "dimensions": [_DIMENSION_LABELS.get(value, value) for value in issue["dimensions"]]} for issue in assessment["issues"]]
        left, right = page["left"]["result"], page["right"]["result"]
        if assessment["compatible"]:
            if left and right:
                page["difference"] = _difference(left["parsed_metric"]["decimal"], right["parsed_metric"]["decimal"])
            page["difference_omitted"] = page["difference"] is None
    return page


async def read_research_comparison(backend, query, frontier):
    query = backend._comparison_query(query)
    pair = await backend.read_pair(query)
    if pair["left"]["state"]["frontier"] < frontier:
        return {"kind": "conflict"}
    if pair["object_kind"] not in (None, "result"):
        raise BackendError("invalid_input")
    page = _page(pair)
    identity, selection = pair["left"]["state"]["data_identity"], _selection(pair)
    # No Native fence or cached result survives the Python decimal calculation.
    current = await backend.read_pair(query)
    if current["left"]["state"]["data_identity"] != identity:
        return {"kind": "conflict"}
    if any(current[name]["content_state"] != "ready" for name in ("left", "right")):
        page = _page(current)
    elif (_selection(current) != selection
        or any(current[name]["fields"] != pair[name]["fields"] for name in ("left", "right"))):
        return {"kind": "conflict"}
    elif current.get("result_assessment") != pair.get("result_assessment"):
        return {"kind": "conflict"}
    page["frontier"] = current["left"]["state"]["frontier"]
    return {"kind": "research_comparison", "comparison": page}
