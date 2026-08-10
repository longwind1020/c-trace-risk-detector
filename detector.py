"""Transparent Chinese/English rule detector for C-TRACE.

The engine does not make a factual determination. It finds textual risk clues,
assigns a suggested 0–2 score to each project dimension, and returns the exact
evidence that caused every match.
"""

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Tuple


DIMENSION_NAMES = {
    "identity": "身份核验 / Identity",
    "synthetic": "生成内容线索 / Synthetic clues",
    "urgency": "紧急操控 / Urgency",
    "financial": "财务请求 / Financial request",
}

SAMPLE_ZH = "我是公司董事长，现在人在国外。这个号码是临时的，不要告诉其他同事，也不要给我回拨。项目保证金必须今天立即支付，请把50万元转到新的境外账户，之后删除聊天记录。视频有点卡顿，口型可能对不上。"
SAMPLE_EN = "This is your CEO. I am overseas and using a new number. Keep this confidential and do not call me back. Wire the deposit to this new offshore account immediately. The video may freeze and the lip movement may look unusual."


@dataclass(frozen=True)
class Rule:
    dimension: str
    score: int
    label_zh: str
    label_en: str
    patterns: Tuple[str, ...]
    flag: str


@dataclass(frozen=True)
class Match:
    score: int
    label_zh: str
    label_en: str
    evidence: str
    flag: str


@dataclass(frozen=True)
class Analysis:
    scores: Dict[str, int]
    matches: Dict[str, List[Match]]
    language: str
    language_label: str
    scam_types: List[str]
    cross_border_hits: List[str]

    @property
    def signal_count(self) -> int:
        return sum(len(items) for items in self.matches.values())

    @property
    def all_flags(self) -> List[str]:
        result = []
        for items in self.matches.values():
            for item in items:
                if item.flag not in result:
                    result.append(item.flag)
        return result


RULES = (
    Rule("identity", 2, "明确阻止独立核验", "Independent verification is blocked",
         (r"不要.{0,6}(回拨|联系|核实|告诉)", r"不得.{0,6}(核验|联系)", r"do not (call|contact|verify)", r"don['’]?t (call|contact|verify)"),
         "对方阻止通过独立渠道核验身份"),
    Rule("identity", 2, "身份或发送渠道无法核实", "Identity or sender cannot be verified",
         (r"无法核实", r"身份不明", r"陌生号码", r"新号码", r"临时.{0,3}(号码|账户)", r"unknown sender", r"new number", r"temporary number", r"cannot verify"),
         "身份或发送渠道缺乏可独立验证的信息"),
    Rule("identity", 1, "自称权威或熟人身份", "Claims a trusted or authoritative identity",
         (r"我是.{0,8}(董事长|老板|领导|警察|公安|检察官|客服|家人|儿子|孙子)", r"冒充", r"this is your (ceo|boss|manager|bank|son|daughter)", r"i am (a police|from the police|your ceo)"),
         "文本中出现需要独立验证的身份声称"),

    Rule("synthetic", 2, "明确提及深度伪造或克隆", "Explicit deepfake or cloning clue",
         (r"AI.{0,4}(换脸|拟声|克隆|生成)", r"深度伪造", r"deepfake", r"voice clon", r"face[- ]?swap", r"synthetic voice"),
         "内容明确涉及AI换脸、语音克隆或深度伪造"),
    Rule("synthetic", 1, "音视频出现可疑痕迹", "Suspicious audio or video artifacts",
         (r"口型.{0,5}(对不上|不同步|异常)", r"画面.{0,5}(卡顿|僵硬|异常)", r"声音.{0,5}(机械|异常|失真)", r"眨眼.{0,4}异常", r"lip.{0,8}(sync|movement|unusual)", r"video.{0,8}(freeze|artifact)", r"robotic voice", r"audio.{0,8}distort"),
         "音视频存在口型、画面或声音异常"),
    Rule("synthetic", 2, "来源不明或无标识", "Unknown source or missing provenance",
         (r"来源不明", r"无任何标识", r"无法确认来源", r"unknown source", r"no provenance", r"unverified media"),
         "生成内容来源无法查询或缺少标识"),

    Rule("urgency", 2, "紧急要求与保密同时出现", "Urgency combined with secrecy",
         (r"(立即|马上|今天|限时).{0,18}(保密|不要告诉|不得核验|删除记录)", r"(保密|不要告诉).{0,18}(立即|马上|今天)", r"(immediately|today|urgent).{0,25}(confidential|secret|do not tell|delete)", r"(confidential|secret).{0,25}(immediately|today|urgent)"),
         "紧迫时间压力与保密要求组合出现"),
    Rule("urgency", 2, "要求保密、删除或隔离", "Secrecy, deletion, or isolation request",
         (r"保密", r"不要告诉", r"删除.{0,6}(聊天|记录|邮件)", r"不能联系", r"keep (this )?confidential", r"do not tell", r"delete (the )?(chat|message|email)", r"keep (it )?secret"),
         "要求保密、删除记录或阻断与他人联系"),
    Rule("urgency", 1, "制造时间压力或威胁", "Time pressure or threat",
         (r"立即", r"马上", r"今天必须", r"最后期限", r"账户.{0,3}冻结", r"家人.{0,4}出事", r"immediately", r"right now", r"urgent", r"today only", r"account.{0,5}(frozen|suspended)", r"final deadline"),
         "文本使用紧急期限、威胁或恐慌推动行动"),

    Rule("financial", 2, "加密货币、境外或异常账户", "Crypto, overseas, or abnormal account",
         (r"(境外|海外|离岸).{0,5}(账户|收款)", r"虚拟货币", r"加密货币", r"USDT", r"比特币", r"账户.{0,6}(变更|更换)", r"offshore account", r"overseas account", r"crypto", r"bitcoin", r"USDT", r"account.{0,8}(changed|new)"),
         "收款方式涉及加密货币、境外账户或频繁变更"),
    Rule("financial", 1, "陌生个人或新收款账户", "Unfamiliar personal or new payment account",
         (r"个人账户", r"私人账户", r"新的?账户", r"陌生收款", r"personal account", r"private account", r"new account"),
         "要求向陌生个人账户或新账户付款"),
    Rule("financial", 1, "明确索取资金或金融信息", "Requests money or financial credentials",
         (r"转账", r"汇款", r"保证金", r"验证码", r"银行卡", r"付款", r"wire (the )?(money|funds|deposit)", r"transfer", r"payment", r"verification code", r"bank details"),
         "文本包含转账、付款、验证码或银行信息请求"),
)


SCAM_TYPE_RULES = (
    ("冒充企业高管 / Business email compromise", (r"董事长|老板|领导|CEO", r"\bceo\b|\bboss\b|\bmanager\b")),
    ("冒充亲友 / Family impersonation", (r"家人|儿子|女儿|孙子|亲友", r"son|daughter|grandson|family member")),
    ("冒充公检法 / Law-enforcement impersonation", (r"警察|公安|检察官|法院", r"police|prosecutor|court officer")),
    ("投资理财诈骗 / Investment fraud", (r"投资|理财|稳赚|高回报", r"investment|guaranteed return|high return")),
    ("虚拟绑架 / Virtual kidnapping", (r"绑架|赎金|家人出事", r"kidnap|ransom|family.*danger")),
    ("虚假客服 / Fake customer service", (r"客服|退款|账户异常", r"customer service|refund|account problem")),
)

CROSS_BORDER_RULES = (
    ("境外/海外账户", (r"境外账户|海外账户|离岸账户", r"offshore account|overseas account")),
    ("人在国外或跨国场景", (r"人在国外|在海外|跨国|国外出差", r"overseas|abroad|cross-border")),
    ("国际平台或通信渠道", (r"WhatsApp|Telegram|Zoom|Instagram",)),
    ("加密货币跨境支付线索", (r"USDT|比特币|虚拟货币|加密货币", r"crypto|bitcoin")),
)


def _first_evidence(text: str, patterns: Iterable[str]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            start = max(0, match.start() - 18)
            end = min(len(text), match.end() + 24)
            excerpt = text[start:end].strip().replace("\n", " ")
            if start > 0:
                excerpt = "…" + excerpt
            if end < len(text):
                excerpt += "…"
            return excerpt
    return None


def detect_language(text: str) -> Tuple[str, str]:
    zh_count = len(re.findall(r"[\u4e00-\u9fff]", text))
    en_count = len(re.findall(r"[A-Za-z]", text))
    if zh_count and en_count and min(zh_count, en_count) >= 6:
        return "mixed", "中英混合 / Mixed"
    if zh_count >= en_count / 3:
        return "zh", "中文 / Chinese"
    return "en", "英文 / English"


def _classify(text: str, definitions) -> List[str]:
    result = []
    for label, pattern_groups in definitions:
        if any(re.search(pattern, text, flags=re.IGNORECASE) for group in pattern_groups for pattern in (group if isinstance(group, tuple) else (group,))):
            result.append(label)
    return result


def analyze_text(text: str) -> Analysis:
    text = text.strip()
    matches: Dict[str, List[Match]] = {key: [] for key in DIMENSION_NAMES}
    for rule in RULES:
        evidence = _first_evidence(text, rule.patterns)
        if evidence:
            matches[rule.dimension].append(Match(rule.score, rule.label_zh, rule.label_en, evidence, rule.flag))

    scores = {key: max((item.score for item in items), default=0) for key, items in matches.items()}
    language, language_label = detect_language(text)

    scam_types = []
    for label, patterns in SCAM_TYPE_RULES:
        if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns):
            scam_types.append(label)

    cross_border_hits = []
    for label, patterns in CROSS_BORDER_RULES:
        evidence = _first_evidence(text, patterns)
        if evidence:
            cross_border_hits.append(f"{label}：{evidence}")

    return Analysis(scores, matches, language, language_label, scam_types, cross_border_hits)

