"""Transparent Chinese/English rule detector for C-TRACE.

The detector identifies reviewable textual clues. It does not determine that a
message is fraudulent and it does not authenticate audio, video, or identities.
"""

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Tuple


DIMENSION_NAMES = {
    "identity": ("身份核验", "Identity verification"),
    "synthetic": ("生成内容线索", "Synthetic-content clues"),
    "urgency": ("紧急操控", "Urgency and manipulation"),
    "financial": ("财务请求", "Financial or data request"),
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
    flag_zh: str
    flag_en: str


@dataclass(frozen=True)
class Match:
    score: int
    label_zh: str
    label_en: str
    evidence: str
    flag_zh: str
    flag_en: str


@dataclass(frozen=True)
class CrossBorderHit:
    label_zh: str
    label_en: str
    evidence: str


@dataclass(frozen=True)
class Analysis:
    scores: Dict[str, int]
    matches: Dict[str, List[Match]]
    language: str
    language_label: str
    scam_types: List[Tuple[str, str]]
    cross_border_hits: List[CrossBorderHit]

    @property
    def signal_count(self) -> int:
        return sum(len(items) for items in self.matches.values())

    def flags(self, language: str) -> List[str]:
        attr = "flag_en" if language == "en" else "flag_zh"
        result: List[str] = []
        for items in self.matches.values():
            for item in items:
                flag = getattr(item, attr)
                if flag not in result:
                    result.append(flag)
        return result


RULES = (
    # Identity verification
    Rule("identity", 2, "明确阻止独立核验", "Independent verification is blocked",
         (r"(?:不要|别|无需|不必).{0,10}(?:回拨|打电话|联系|核实|确认|询问)", r"(?:不得|不能|不可以).{0,8}(?:核验|联系|回拨)", r"(?:do not|don't|cannot|can't|must not).{0,12}(?:call|contact|verify|check)", r"no need to.{0,8}(?:call|verify)"),
         "对方阻止或回避通过独立渠道核验身份", "The sender blocks or avoids independent identity verification"),
    Rule("identity", 2, "身份或发送渠道明确无法核实", "Identity or sender is explicitly unverifiable",
         (r"无法核实", r"身份不明", r"来历不明", r"陌生号码", r"(?:新|临时|备用).{0,3}(?:号码|账号)", r"unknown sender", r"unverified identity", r"new (?:phone )?number", r"temporary (?:phone )?number", r"cannot (?:be )?verified"),
         "身份或发送渠道缺乏可独立验证的信息", "The identity or channel lacks independently verifiable information"),
    Rule("identity", 1, "自称权威、机构或熟人身份", "Claims a trusted person or authority",
         (r"(?:我是|这里是|我们是|我系).{0,12}(?:董事长|老板|领导|经理|警察|公安|检察院|法院|领事馆|大使馆|银行|客服|家人|儿子|女儿|朋友)", r"(?:冒充|代替).{0,8}(?:领导|亲友|客服|警方)", r"(?:this is|i am|we are|calling from).{0,16}(?:ceo|boss|manager|police|prosecutor|court|consulate|embassy|bank|customer service|your son|your daughter|your friend)"),
         "文本中出现需要通过官方或既有联系方式核验的身份声称", "A claimed identity should be checked through an official or existing contact channel"),
    Rule("identity", 1, "暂时不便直接通话，需间接核实", "Direct contact is unavailable; indirect verification is needed",
         (r"(?:现在|暂时|这里|目前)?不方便.{0,6}(?:接|打|视频)?电话", r"(?:现在|暂时|目前).{0,5}(?:不能|无法).{0,5}(?:接听|通话|视频)", r"(?:unable|not able|not convenient) to (?:take|answer|join) (?:a )?(?:call|video call)", r"can't talk (?:right now|at the moment)"),
         "暂时不能直接通话不等于身份无法核实，但应通过原号码或可信联系人间接确认", "Temporary unavailability does not prove the identity is unverifiable; confirm through an existing number or trusted contact"),

    # Synthetic-content clues
    Rule("synthetic", 2, "明确提及深度伪造或克隆", "Explicit deepfake or cloning clue",
         (r"(?:AI|人工智能).{0,6}(?:换脸|拟声|克隆|合成|生成)", r"深度伪造", r"deepfake", r"voice clon", r"face[- ]?swap", r"synthetic (?:voice|video|image)"),
         "内容明确涉及AI换脸、语音克隆或深度伪造", "The content explicitly mentions face swaps, voice cloning, or deepfakes"),
    Rule("synthetic", 1, "音视频出现可疑痕迹", "Suspicious audio or video artifacts",
         (r"口型.{0,8}(?:对不上|不同步|异常|不自然)", r"画面.{0,8}(?:卡顿|僵硬|异常|闪烁)", r"声音.{0,8}(?:机械|异常|失真|断续|不自然)", r"(?:眨眼|表情).{0,6}(?:异常|僵硬|不自然)", r"lip.{0,10}(?:sync|movement|unusual|unnatural)", r"video.{0,10}(?:freeze|artifact|glitch|unnatural)", r"robotic voice", r"audio.{0,10}(?:distort|glitch|unnatural)"),
         "音视频存在口型、画面、表情或声音异常", "The media shows unusual lip, image, expression, or voice artifacts"),
    Rule("synthetic", 2, "媒体来源不明或无法查证", "Media source or provenance is unavailable",
         (r"(?:视频|音频|图片|文件).{0,8}(?:来源不明|无法确认来源|无标识)", r"unknown (?:media )?source", r"no provenance", r"unverified (?:media|video|audio|image)"),
         "音视频或图像来源无法查询或缺少标识", "The media source cannot be checked or lacks provenance"),

    # Urgency and manipulation
    Rule("urgency", 2, "紧急要求与保密或隔离同时出现", "Urgency combined with secrecy or isolation",
         (r"(?:立即|马上|立刻|尽快|今天|限时|务必).{0,35}(?:保密|不要告诉|别告诉|不得核验|删除|不要声张)", r"(?:保密|不要告诉|别告诉|不要声张).{0,35}(?:立即|马上|立刻|尽快|今天|限时|务必)", r"(?:immediately|right now|today|urgent|promptly|within \d+ hours?).{0,45}(?:confidential|secret|do not tell|don't tell|delete|do not discuss)", r"(?:confidential|secret|do not tell|don't tell|do not discuss).{0,45}(?:immediately|today|urgent|promptly|within \d+ hours?)"),
         "紧迫时间压力与保密或隔离要求组合出现", "Time pressure appears together with secrecy or isolation"),
    Rule("urgency", 2, "要求保密、删除记录或隔离求证", "Secrecy, deletion, or isolation request",
         (r"(?:请|务必|一定要|必须|先)?保密", r"(?:不要|别).{0,8}(?:告诉|声张|外传|讨论|联系其他人)", r"删除.{0,10}(?:聊天|记录|邮件|信息)", r"(?:不得|不许).{0,8}(?:告诉|联系|讨论)", r"keep (?:this|it)? ?confidential", r"(?:do not|don't).{0,8}(?:tell|discuss|contact anyone)", r"delete (?:the )?(?:chat|message|email|record)", r"keep (?:it )?secret"),
         "对方要求保密、删除证据或避免向他人求证", "The sender requests secrecy, deletion, or isolation from other people"),
    Rule("urgency", 1, "制造时间压力、损失或法律后果", "Time pressure, threatened loss, or legal consequence",
         (r"立即", r"马上", r"立刻", r"尽快", r"今天.{0,5}(?:必须|完成|处理)", r"(?:最后|截止).{0,5}(?:期限|时间)", r"(?:账户|银行卡).{0,8}(?:冻结|停用|注销)", r"(?:否则|不然).{0,15}(?:损失|负责|处罚|逮捕|起诉|遣返|冻结)", r"避免.{0,8}(?:处罚|法律后果|账户冻结)", r"immediately", r"right now", r"urgent", r"act promptly", r"as soon as possible", r"within \d+ hours?", r"(?:account|card).{0,8}(?:frozen|suspended|closed)", r"(?:otherwise|or else).{0,20}(?:arrest|prosecution|penalty|loss|deportation|frozen)", r"avoid.{0,12}(?:legal consequences|penalty|arrest)"),
         "文本使用期限、损失或法律后果推动立即行动", "The message uses deadlines, loss, or legal consequences to push action"),

    # Financial/data requests
    Rule("financial", 2, "加密货币、境外或异常账户", "Crypto, overseas, or abnormal payment destination",
         (r"(?:境外|海外|离岸|国外).{0,8}(?:账户|收款|钱包)", r"(?:虚拟|加密)货币", r"USDT", r"比特币", r"账户.{0,8}(?:变更|更换|改了)", r"(?:offshore|overseas|foreign).{0,5}(?:account|wallet)", r"crypto", r"bitcoin", r"USDT", r"account.{0,10}(?:changed|new|updated)"),
         "收款方式涉及加密货币、境外账户或临时变更", "The payment uses crypto, an overseas account, or a changed destination"),
    Rule("financial", 1, "请求资金周转、付款或敏感数据", "Requests funds, payment, or sensitive data",
         (r"资金周转", r"周转(?:一下|几天)?", r"借(?:我)?(?:点|一笔|一些)?钱", r"垫付", r"转账", r"汇款", r"打款", r"保证金", r"押金", r"医疗费", r"手续费", r"税费", r"罚款", r"验证码", r"银行卡", r"账户信息", r"付款", r"帮我.{0,8}(?:付|转|汇)", r"(?:wire|transfer|send|lend).{0,12}(?:money|funds|payment|deposit|fee)", r"financial help", r"cash flow", r"working capital", r"make (?:a )?payment", r"pay (?:the )?(?:fee|deposit|tax|fine|bill)", r"verification code", r"bank (?:details|information)"),
         "文本包含资金、付款、验证码或银行信息请求", "The message requests money, payment, a verification code, or bank information"),
    Rule("financial", 1, "陌生个人或新收款账户", "Unfamiliar personal or new payment account",
         (r"(?:个人|私人|陌生|新的?|临时).{0,4}(?:账户|收款码|钱包)", r"(?:personal|private|unfamiliar|new|temporary).{0,5}(?:account|wallet)"),
         "要求向陌生个人账户或新账户付款", "Payment is requested to an unfamiliar, personal, or new account"),
)


SCAM_TYPE_RULES = (
    (("冒充企业高管", "Business executive impersonation"), (r"董事长|老板|领导|经理|CEO", r"\bceo\b|\bboss\b|\bmanager\b")),
    (("冒充亲友", "Family or friend impersonation"), (r"家人|儿子|女儿|孙子|亲友|朋友", r"son|daughter|grandson|family member|your friend")),
    (("冒充公检法或使领馆", "Law-enforcement or consulate impersonation"), (r"警察|公安|检察院|法院|领事馆|大使馆", r"police|prosecutor|court|consulate|embassy")),
    (("投资理财诈骗", "Investment fraud"), (r"投资|理财|稳赚|高回报", r"investment|guaranteed return|high return")),
    (("虚拟绑架", "Virtual kidnapping"), (r"绑架|赎金|家人出事", r"kidnap|ransom|family.*danger")),
    (("虚假客服", "Fake customer service"), (r"客服|退款|账户异常", r"customer service|refund|account problem")),
)

CROSS_BORDER_RULES = (
    (("境外或海外账户", "Overseas or offshore account"), (r"境外账户|海外账户|离岸账户|国外账户", r"offshore account|overseas account|foreign account")),
    (("人在国外或跨国场景", "Overseas or cross-border context"), (r"人在国外|身在国外|在海外|跨国|跨境|国外出差|境外出差", r"overseas|abroad|cross-border|outside the country")),
    (("国际平台或通信渠道", "International communication platform"), (r"WhatsApp|Telegram|Zoom|Instagram",)),
    (("加密货币跨境支付线索", "Crypto payment clue"), (r"USDT|比特币|虚拟货币|加密货币", r"crypto|bitcoin")),
    (("使领馆或外国执法场景", "Consular or foreign-authority context"), (r"领事馆|大使馆|境外警方", r"consulate|embassy|foreign police")),
)

MONEY_REQUEST = tuple(pattern for rule in RULES if rule.dimension == "financial" for pattern in rule.patterns)
IDENTITY_CLAIM = RULES[2].patterns
VERIFIABLE_CUE = (r"官方(?:网站|电话|柜台|App|APP|应用)", r"原号码", r"当面核实", r"official (?:website|number|app|channel)", r"verified (?:business|company) account")
CROSS_BORDER_CONTEXT = tuple(pattern for _, patterns in CROSS_BORDER_RULES for pattern in patterns)


def _first_evidence(text: str, patterns: Iterable[str]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            start = max(0, match.start() - 22)
            end = min(len(text), match.end() + 30)
            excerpt = text[start:end].strip().replace("\n", " ")
            return ("…" if start else "") + excerpt + ("…" if end < len(text) else "")
    return None


def detect_language(text: str) -> Tuple[str, str]:
    zh_count = len(re.findall(r"[\u4e00-\u9fff]", text))
    en_words = len(re.findall(r"\b[A-Za-z]+\b", text))
    if zh_count >= 4 and en_words >= 4:
        return "mixed", "中英混合 / Mixed"
    if zh_count:
        return "zh", "中文"
    return "en", "English"


def _has(text: str, patterns: Iterable[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _append_derived(matches: Dict[str, List[Match]], dimension: str, score: int,
                    label_zh: str, label_en: str, evidence: str,
                    flag_zh: str, flag_en: str) -> None:
    matches[dimension].append(Match(score, label_zh, label_en, evidence, flag_zh, flag_en))


def analyze_text(text: str) -> Analysis:
    text = text.strip()
    matches: Dict[str, List[Match]] = {key: [] for key in DIMENSION_NAMES}
    for rule in RULES:
        evidence = _first_evidence(text, rule.patterns)
        if evidence:
            matches[rule.dimension].append(Match(
                rule.score, rule.label_zh, rule.label_en, evidence,
                rule.flag_zh, rule.flag_en,
            ))

    # Context rule: a direct money/data request from a text that supplies no
    # independently verifiable identity still needs verification. It receives
    # 1 point because the text alone cannot prove that verification is impossible.
    money_evidence = _first_evidence(text, MONEY_REQUEST)
    if money_evidence and not _has(text, IDENTITY_CLAIM) and not _has(text, VERIFIABLE_CUE):
        _append_derived(
            matches, "identity", 1,
            "提出资金或数据要求，但身份未说明或不可由文本确认",
            "Money or data is requested without a verifiable identity",
            money_evidence,
            "不要仅凭当前消息确认对方身份，应使用已有联系方式独立核验",
            "Do not rely on this message alone; verify through an existing independent channel",
        )

    # Context rule: an overseas story plus a money request raises identity risk,
    # while the payment destination itself is scored only in the financial dimension.
    cross_evidence = _first_evidence(text, CROSS_BORDER_CONTEXT)
    if cross_evidence and money_evidence and not matches["identity"]:
        _append_derived(
            matches, "identity", 1,
            "跨境情境下提出资金请求，身份需间接核实",
            "Cross-border money request requires indirect identity verification",
            cross_evidence,
            "跨境情境增加核验难度，应通过原号码或官方渠道确认",
            "The cross-border context makes verification harder; use an original or official channel",
        )

    scores = {key: max((item.score for item in items), default=0) for key, items in matches.items()}
    language, language_label = detect_language(text)

    scam_types: List[Tuple[str, str]] = []
    for labels, patterns in SCAM_TYPE_RULES:
        if _has(text, patterns):
            scam_types.append(labels)

    cross_border_hits: List[CrossBorderHit] = []
    for labels, patterns in CROSS_BORDER_RULES:
        evidence = _first_evidence(text, patterns)
        if evidence:
            cross_border_hits.append(CrossBorderHit(labels[0], labels[1], evidence))

    return Analysis(scores, matches, language, language_label, scam_types, cross_border_hits)
