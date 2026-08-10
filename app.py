from datetime import datetime

import streamlit as st

from detector import DIMENSION_NAMES, SAMPLE_EN, SAMPLE_ZH, analyze_text
from scoring import calculate_risk, progress_percent


st.set_page_config(
    page_title="C-TRACE 跨境诈骗风险检测",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp { background:#f3f6f9; }
      .block-container { max-width:1220px; padding-top:1.4rem; padding-bottom:3rem; }
      .hero { background:linear-gradient(135deg,#102f50 0%,#08747c 100%); color:#fff;
              padding:1.6rem 1.8rem; border-radius:20px; margin-bottom:1rem;
              box-shadow:0 12px 30px rgba(17,54,88,.16); overflow:hidden; }
      .hero h1 { margin:0; font-size:clamp(1.55rem,4vw,2.15rem); line-height:1.25; }
      .hero p { margin:.55rem 0 0; opacity:.92; }
      .eyebrow { letter-spacing:.12em; font-size:.76rem; opacity:.78; font-weight:700; }
      .risk-card { background:#fff; border-radius:16px; padding:1.2rem 1.35rem;
                   box-shadow:0 5px 18px rgba(24,52,84,.08); border-top:5px solid var(--risk); }
      .score { font-size:2.35rem; line-height:1; font-weight:850; color:var(--risk); }
      .muted { color:#607086; font-size:.86rem; }
      .empty { background:#fff; border:1px dashed #9fb2c5; border-radius:16px;
               padding:2rem; text-align:center; color:#53677c; }
      .notice { background:#e8f3f5; border-radius:10px; padding:.7rem .9rem; color:#184c54; }
      div[data-testid="stMetric"] { background:#fff; padding:.75rem 1rem; border-radius:13px;
                                    box-shadow:0 3px 12px rgba(24,52,84,.06); }
      div[data-testid="stTextArea"] textarea { font-family:"Microsoft YaHei","Segoe UI",sans-serif; font-size:1rem; }
      img { max-width:100%; height:auto; object-fit:contain; }
      @media (max-width:640px) { .hero { padding:1.2rem; border-radius:14px; } .block-container { padding-top:.7rem; } }
    </style>
    <div class="hero">
      <div class="eyebrow">C-TRACE · EXPLAINABLE RULE ENGINE</div>
      <h1>🛡️ 跨境诈骗风险实时检测</h1>
      <p>输入中文、英文或混合文本，查看四维评分、命中证据和可执行建议</p>
    </div>
    """,
    unsafe_allow_html=True,
)


def pick(zh: str, en: str, language: str) -> str:
    return en if language == "en" else zh


def secondary_language(language: str) -> str:
    return "zh" if language == "en" else "en"


def risk_level(result, language: str) -> str:
    return result.level_en if language == "en" else result.level


def advice(result, language: str) -> str:
    return result.advice_en if language == "en" else result.advice_zh


with st.sidebar:
    st.header("显示语言 / Display language")
    display_choice = st.selectbox(
        "结果显示方式",
        ["自动识别", "中文", "English"],
        help="自动识别会优先显示输入文本的主要语言，另一种语言收进折叠区。",
    )
    st.caption("Auto mode prioritizes the input language. The translation remains available in a collapsed section.")
    st.divider()
    st.markdown("**四维评分 / Four dimensions**")
    st.write("① 身份核验　② 生成内容线索\n\n③ 紧急操控　④ 财务或数据请求")
    st.markdown("**风险阈值 / Thresholds**")
    st.success("0–2　低风险 / Low")
    st.warning("3–5　中风险 / Medium")
    st.error("6–8　高风险 / High")
    st.divider()
    st.caption("这是透明规则驱动的初筛工具，可能漏报或误报，不鉴定音视频真伪，也不代替警方、银行或法律意见。")

if "message_text" not in st.session_state:
    st.session_state.message_text = ""

st.subheader("1. 输入待检测内容")
sample_a, sample_b, clear_col, privacy_col = st.columns([1.15, 1.15, .8, 3])
with sample_a:
    if st.button("载入中文示例", use_container_width=True):
        st.session_state.message_text = SAMPLE_ZH
with sample_b:
    if st.button("Load English sample", use_container_width=True):
        st.session_state.message_text = SAMPLE_EN
with clear_col:
    if st.button("清空", use_container_width=True):
        st.session_state.message_text = ""
with privacy_col:
    st.markdown('<div class="notice">请删除姓名、证件号、银行卡号等个人信息；输入内容不会写入数据库。</div>', unsafe_allow_html=True)

text = st.text_area(
    "聊天、邮件或电话转写",
    key="message_text",
    height=210,
    placeholder="粘贴中文、英文或中英混合的聊天、邮件、短信或电话转写内容……",
    label_visibility="collapsed",
)

if not text.strip():
    st.markdown(
        '<div class="empty"><h3>等待输入</h3><p>输入内容后，系统会实时显示风险等级、命中规则和原文证据。</p></div>',
        unsafe_allow_html=True,
    )
    st.stop()

analysis = analyze_text(text)
if display_choice == "中文":
    ui_language = "zh"
elif display_choice == "English":
    ui_language = "en"
elif analysis.language == "en":
    ui_language = "en"
else:
    ui_language = "zh"
other_language = secondary_language(ui_language)

auto_scores = analysis.scores
st.subheader(pick("2. 自动检测结果", "2. Live detection result", ui_language))
k1, k2, k3, k4 = st.columns(4)
k1.metric(pick("检测语言", "Detected language", ui_language), analysis.language_label)
k2.metric(pick("文本长度", "Characters", ui_language), len(text))
k3.metric(pick("风险线索", "Risk signals", ui_language), analysis.signal_count)
k4.metric(pick("跨境线索", "Cross-border clues", ui_language), len(analysis.cross_border_hits))

with st.expander(pick("人工复核自动评分", "Review or override the automatic scores", ui_language), expanded=False):
    st.caption(pick(
        "如果文本外信息表明自动判断不准确，可人工修改。跨境线索不是第五维；它只在与身份核验或异常付款组合时进入对应维度。",
        "Scores may be adjusted using information outside the text. Cross-border context is not a fifth dimension; it affects a relevant dimension only when combined with verification or payment risk.",
        ui_language,
    ))
    override_enabled = st.toggle(pick("启用人工调整", "Enable manual override", ui_language), value=False)
    if override_enabled:
        review_cols = st.columns(4)
        scores = {}
        for index, key in enumerate(DIMENSION_NAMES):
            with review_cols[index]:
                scores[key] = st.select_slider(
                    DIMENSION_NAMES[key][0 if ui_language == "zh" else 1],
                    options=[0, 1, 2],
                    value=auto_scores[key],
                    key=f"review_{key}",
                    help=pick("0=未见风险线索，1=需间接核实，2=明显高风险线索", "0=no clue, 1=indirect verification needed, 2=strong risk clue", ui_language),
                )
    else:
        scores = dict(auto_scores)
        st.info(pick("当前采用自动检测分。低分不等于绝对安全。", "Automatic scores are currently used. A low score does not guarantee safety.", ui_language))

result = calculate_risk(scores)
left, right = st.columns([1, 2], gap="large")
with left:
    st.markdown(
        f"""
        <div class="risk-card" style="--risk:{result.color}">
          <div class="muted">{pick('综合评分', 'Overall score', ui_language)}</div>
          <div class="score">{result.total} / 8</div>
          <h3 style="color:{result.color};margin:.45rem 0 .1rem">{risk_level(result, ui_language)}</h3>
          <div class="muted">{pick('自动分', 'Automatic', ui_language)}：{sum(auto_scores.values())}/8 · {pick('当前复核分', 'Reviewed', ui_language)}：{result.total}/8</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.progress(progress_percent(result.total), text=f"{pick('风险强度', 'Risk intensity', ui_language)} {progress_percent(result.total)}%")
with right:
    if result.total >= 6:
        st.error(pick("立即停止：不转账、不点击、不下载、不共享屏幕；保存证据并联系官方。", "Stop immediately: do not transfer, click, download, or share your screen. Preserve evidence and contact an authority.", ui_language))
    elif result.total >= 3:
        st.warning(pick("暂停当前操作，通过对方未提供的独立渠道核验身份和请求。", "Pause and verify the identity and request through an independent channel not supplied by the sender.", ui_language))
    else:
        st.success(pick("暂未发现足够的高风险组合，但仍应独立核验；低分不等于安全。", "No strong risk combination was found, but independent verification is still recommended. A low score is not a guarantee.", ui_language))
    st.markdown(f"**{pick('行动建议', 'Recommended action', ui_language)}：** {advice(result, ui_language)}")
    with st.expander(pick("查看英文建议", "查看中文建议", ui_language), expanded=False):
        st.write(advice(result, other_language))

st.markdown(f"#### {pick('四维解释与原文证据', 'Four-dimension explanation and evidence', ui_language)}")
dimension_cols = st.columns(4)
for index, key in enumerate(DIMENSION_NAMES):
    matches = analysis.matches[key]
    with dimension_cols[index]:
        st.markdown(f"**{DIMENSION_NAMES[key][0 if ui_language == 'zh' else 1]}**")
        st.metric(pick("自动评分", "Automatic score", ui_language), f"{auto_scores[key]} / 2")
        if matches:
            for match in matches:
                with st.container(border=True):
                    st.markdown(f"**{match.label_en if ui_language == 'en' else match.label_zh}**")
                    st.caption(f"{pick('规则分值', 'Rule score', ui_language)}：{match.score}/2")
                    st.markdown(f"{pick('证据', 'Evidence', ui_language)}：`{match.evidence}`")
        else:
            st.caption(pick("未命中该维度规则", "No rule matched this dimension", ui_language))

tab_flags, tab_types, tab_rules = st.tabs([
    pick("综合风险信号", "Risk signals", ui_language),
    pick("疑似诈骗类型", "Possible scam type", ui_language),
    pick("规则与局限", "Rules and limitations", ui_language),
])
with tab_flags:
    current_flags = analysis.flags(ui_language)
    if current_flags:
        for flag in current_flags:
            st.write(f"- {flag}")
    else:
        st.write(pick("未检出明确风险信号。", "No explicit risk signal was detected.", ui_language))
    if analysis.cross_border_hits:
        st.markdown(f"**{pick('跨境线索', 'Cross-border clues', ui_language)}**")
        for hit in analysis.cross_border_hits:
            st.write(f"- {hit.label_en if ui_language == 'en' else hit.label_zh}：{hit.evidence}")
        st.caption(pick("跨境本身不等于诈骗，也不会单独加分；与核验困难或异常付款组合时才影响相应维度。", "Cross-border context alone is not fraud and adds no score by itself; it affects a dimension only when combined with verification or payment risk.", ui_language))
with tab_types:
    if analysis.scam_types:
        for item_zh, item_en in analysis.scam_types:
            st.write(f"- {item_en if ui_language == 'en' else item_zh}")
    else:
        st.write(pick("没有足够线索判断具体类型。", "There are not enough clues to classify a scam type.", ui_language))
with tab_rules:
    st.write(pick("本原型使用可查看的中英文关键词、同义表达和组合规则，不调用大模型，也不上传内容。", "This prototype uses reviewable Chinese and English phrases, synonyms, and context combinations. It does not call a language model or upload the text.", ui_language))
    st.write(pick("自动结果只表示文本中存在风险线索，不能证明发送者实施诈骗，也不能鉴定音视频真假。", "The result only indicates textual risk clues. It neither proves fraud nor authenticates audio or video.", ui_language))

with st.expander(pick("证据保全与处置清单", "Evidence and response checklist", ui_language)):
    c1, c2 = st.columns(2)
    with c1:
        st.checkbox(pick("保存完整聊天或邮件", "Preserve the full chat or email", ui_language))
        st.checkbox(pick("保存账号、号码、链接和二维码", "Preserve accounts, numbers, links, and QR codes", ui_language))
        st.checkbox(pick("保存原始音视频和文件", "Preserve original media and files", ui_language))
    with c2:
        st.checkbox(pick("停止转账、点击和下载", "Stop transfers, clicks, and downloads", ui_language))
        st.checkbox(pick("通过独立渠道核验", "Verify through an independent channel", ui_language))
        st.checkbox(pick("联系银行、平台或警方", "Contact the bank, platform, or police", ui_language))

evidence_zh = []
evidence_en = []
for key in DIMENSION_NAMES:
    for match in analysis.matches[key]:
        evidence_zh.append(f"- {DIMENSION_NAMES[key][0]}：{match.label_zh}｜{match.evidence}")
        evidence_en.append(f"- {DIMENSION_NAMES[key][1]}: {match.label_en} | {match.evidence}")

types_zh = "、".join(item[0] for item in analysis.scam_types) if analysis.scam_types else "未识别"
types_en = ", ".join(item[1] for item in analysis.scam_types) if analysis.scam_types else "Not identified"
report = (
    f"C-TRACE 风险检测摘要｜{datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
    f"检测语言：{analysis.language_label}\n自动评分：{sum(auto_scores.values())}/8；复核评分：{result.total}/8；风险：{result.level}\n"
    f"身份核验 {scores['identity']}；生成内容线索 {scores['synthetic']}；紧急操控 {scores['urgency']}；财务请求 {scores['financial']}。\n"
    f"疑似类型：{types_zh}\n命中证据：\n{chr(10).join(evidence_zh) if evidence_zh else '- 无'}\n建议：{result.advice_zh}\n\n"
    f"C-TRACE Risk Summary\nAutomatic: {sum(auto_scores.values())}/8; Reviewed: {result.total}/8; Risk: {result.level_en}\n"
    f"Identity {scores['identity']}; Synthetic clues {scores['synthetic']}; Urgency {scores['urgency']}; Financial/data request {scores['financial']}.\n"
    f"Possible type: {types_en}\nEvidence:\n{chr(10).join(evidence_en) if evidence_en else '- None'}\nAdvice: {result.advice_en}\n\n"
    "说明 / Note：本结果由透明规则生成，不构成事实认定或专业意见。"
)
st.download_button(
    pick("下载检测摘要（含中英文）", "Download report (Chinese and English)", ui_language),
    data=report.encode("utf-8-sig"),
    file_name="C-TRACE_风险检测摘要.txt",
    mime="text/plain",
    use_container_width=True,
)

st.caption("C-TRACE Prototype V3 · Language-aware display · Explainable rule detection · No AI API · No database storage")
