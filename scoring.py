"""Rule-based scoring engine for the C-TRACE prototype."""

from dataclasses import dataclass
from typing import Mapping


DIMENSION_KEYS = ("identity", "synthetic", "urgency", "financial")


@dataclass(frozen=True)
class RiskResult:
    total: int
    level: str
    level_en: str
    color: str
    advice_zh: str
    advice_en: str


def calculate_risk(scores: Mapping[str, int]) -> RiskResult:
    """Validate four 0–2 dimension scores and return the risk classification."""
    missing = set(DIMENSION_KEYS) - set(scores)
    extra = set(scores) - set(DIMENSION_KEYS)
    if missing or extra:
        raise ValueError(f"评分维度不完整：missing={sorted(missing)}, extra={sorted(extra)}")

    values = [scores[key] for key in DIMENSION_KEYS]
    if any(type(value) is not int or value not in (0, 1, 2) for value in values):
        raise ValueError("每个维度必须是0、1或2分")

    total = sum(values)
    if total <= 2:
        return RiskResult(
            total, "低风险", "Low risk", "#159A64",
            "建议通过官方渠道进一步核实。在确认身份和请求真实性前，不要提供敏感信息。",
            "Verify through an official, independent channel before sharing sensitive information.",
        )
    if total <= 5:
        return RiskResult(
            total, "中风险", "Medium risk", "#D88A00",
            "停止当前操作，通过独立渠道核验身份。不要使用对方提供的号码、链接或联系方式进行核验。",
            "Pause the interaction and verify the identity through an independent channel. Do not use contact details supplied by the requester.",
        )
    return RiskResult(
        total, "高风险", "High risk", "#C9362B",
        "立即停止操作：不转账、不点击、不下载。保存聊天、账号、链接和转账信息，并联系银行、平台或警方等官方机构求助。",
        "Stop immediately: do not transfer money, click links, or download files. Preserve evidence and contact your bank, platform, police, or another official authority.",
    )


def progress_percent(total: int) -> int:
    if not 0 <= total <= 8:
        raise ValueError("总分必须在0至8之间")
    return round(total / 8 * 100)

