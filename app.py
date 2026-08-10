from datetime import datetime

import streamlit as st

from detector import DIMENSION_NAMES, SAMPLE_EN, SAMPLE_ZH, analyze_text
from scoring import calculate_risk, progress_percent


st.set_page_config(
    page_title="C-TRACE 中英文诈骗实时检测",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp { background:#f3f6f9; }
      .block-container { max-width:1220px; padding-top:1.5rem; padding-bottom:3rem; }
      .hero { background:linear-gradient(135deg,#102f50 0%,#08747c 100%); color:#fff;
              padding:1.8rem 2rem; border-radius:20px; margin-bottom:1rem;
              box-shadow:0 12px 30px rgba(17,54,88,.16); }
      .hero h1 { margin:0; font-size:2.15rem; }
      .hero p { margin:.55rem 0 0; opacity:.92; }
      .eyebrow { letter-spacing:.12em; font-size:.76rem; opacity:.75; font-weight:700; }
      .risk-card { background:#fff; border-radius:16px; padding:1.2rem 1.35rem;
                   box-shadow:0 5px 18px rgba(24,52,84,.08); border-top:5px solid var(--risk); }
      .score { font-size:2.35rem; line-height:1; font-weight:850; color:var(--risk); }
      .muted { color:#607086; font-size:.86rem; }
      .signal { background:#edf4f7; border-left:4px solid #0f6b78; border-radius:8px;
                padding:.65rem .8rem; margin:.35rem 0; }
      .empty { background:#fff; border:1px dashed #9fb2c5; border-radius:16px;
               padding:2.2rem; text-align:center; color:#53677c; }
      .notice { background:#e8f3f5; border-radius:10px; padding:.7rem .9rem; color:#184c54; }
      div[data-testid="stMetric"] { background:#fff; padding:.75rem 1rem; border-radius:13px;
                                    box-shadow:0 3px 12px rgba(24,52,84,.06); }
      div[data-testid="stTextArea"] textarea { font-family:"Microsoft YaHei",sans-serif; font-size:1rem; }
    </style>
    <div class="hero">
      <div class="eyebrow">C-TRACE · EXPLAINABLE RULE ENGINE</div>
      <h1>🛡️ 中英文诈骗内容实时检测</h1>
      <p>粘贴聊天、邮件或电话转写 → 自动识别中英文风险线索 → 四维评分 → 双语行动建议</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("检测说明 / Guide")
    st.write("本工具直接分析中文、英文或中英混合文本。所有命中规则和证据片段都会展示，可人工复核。")
    st.caption("Chinese, English, and mixed-language text are supported. Every matched rule is visible and reviewable.")
    st.divider()
    st.markdown("**评分维度 / Dimensions**")
    st.write("① 身份核验　② 生成内容线索\n\n③ 紧急操控　④ 财务请求")
    st.markdown("**风险阈值 / Thresholds**")
    st.success("0–2　低风险 / Low")
    st.warning("3–5　中风险 / Medium")
    st.error("6–8　高风险 / High")
    st.divider()
    st.caption("规则检测可能漏报或误报；结果用于教学和初步风险提示，不代替警方、银行或法律专业意见。")

if "message_text" not in st.session_state:
    st.session_state.message_text = ""

st.subheader("1. 输入待检测内容 / Paste content")
sample_a, sample_b, clear_col, privacy_col = st.columns([1, 1, 1, 3])
with sample_a:
    if st.button("载入中文高风险示例", use_container_width=True):
        st.session_state.message_text = SAMPLE_ZH
with sample_b:
    if st.button("Load English sample", use_container_width=True):
        st.session_state.message_text = SAMPLE_EN
with clear_col:
    if st.button("清空 / Clear", use_container_width=True):
        st.session_state.message_text = ""
with privacy_col:
    st.markdown('<div class="notice">请先删除姓名、证件号、银行卡号等个人信息。输入不会写入数据库。</div>', unsafe_allow_html=True)

text = st.text_area(
    "聊天、邮件或电话转写 / Chat, email, or call transcript",
    key="message_text",
    height=210,
    placeholder="例如：我是你们公司CEO，现在在国外。不要联系其他人，立即把保证金转到这个境外账户……\n\nExample: This is your CEO. I am overseas. Keep this confidential and wire the money to this new account immediately...",
    label_visibility="collapsed",
)

if not text.strip():
    st.markdown(
        '<div class="empty"><h3>等待输入 / Waiting for content</h3><p>输入中文、英文或中英混合内容后，系统会自动显示风险等级、命中规则和证据片段。</p></div>',
        unsafe_allow_html=True,
    )
    st.stop()

analysis = analyze_text(text)
auto_scores = analysis.scores

st.subheader("2. 自动检测结果 / Live detection")
k1, k2, k3, k4 = st.columns(4)
k1.metric("检测语言 / Language", analysis.language_label)
k2.metric("文本长度 / Characters", len(text))
k3.metric("风险线索 / Signals", analysis.signal_count)
k4.metric("跨境线索 / Cross-border", len(analysis.cross_border_hits))

with st.expander("人工复核自动评分 / Review and override", expanded=False):
    st.caption("自动评分来自公开规则。若上下文信息表明自动判断不准确，可人工修改；修改后总分和建议会立即更新。")
    override_enabled = st.toggle("启用人工调整 / Enable manual override", value=False)
    if override_enabled:
        review_cols = st.columns(4)
        scores = {}
        for index, key in enumerate(DIMENSION_NAMES):
            with review_cols[index]:
                scores[key] = st.select_slider(
                    DIMENSION_NAMES[key],
                    options=[0, 1, 2],
                    value=auto_scores[key],
                    key=f"review_{key}",
                    help="0=低线索，1=可疑，2=高风险线索",
                )
    else:
        scores = dict(auto_scores)
        st.info("当前采用自动检测分。开启人工调整后，可结合回拨核验、账户性质和音视频原件等文本外信息修正。")

result = calculate_risk(scores)
left, right = st.columns([1, 2], gap="large")
with left:
    st.markdown(
        f"""
        <div class="risk-card" style="--risk:{result.color}">
          <div class="muted">综合评分 / Overall score</div>
          <div class="score">{result.total} / 8</div>
          <h3 style="color:{result.color};margin:.45rem 0 .1rem">{result.level} · {result.level_en}</h3>
          <div class="muted">自动建议分：{sum(auto_scores.values())}/8 · 当前复核分：{result.total}/8</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.progress(progress_percent(result.total), text=f"风险强度 / Intensity {progress_percent(result.total)}%")
with right:
    if result.total >= 6:
        st.error("立即停止：不转账 · 不点击 · 不下载 · 不共享屏幕 · 保存证据 · 联系官方")
    elif result.total >= 3:
        st.warning("暂停当前操作，通过对方未提供的独立官方渠道核验身份和请求。")
    else:
        st.success("暂未发现足够的高风险组合，但仍应独立核验；低分不等于绝对安全。")
    st.markdown(f"**中文建议：** {result.advice_zh}")
    st.markdown(f"**English advice:** {result.advice_en}")

st.markdown("#### 四维解释 / Explainable four-dimension analysis")
dimension_cols = st.columns(4)
for index, key in enumerate(DIMENSION_NAMES):
    matches = analysis.matches[key]
    with dimension_cols[index]:
        st.markdown(f"**{DIMENSION_NAMES[key]}**")
        st.metric("自动评分", f"{auto_scores[key]} / 2")
        if matches:
            for match in matches:
                st.markdown(
                    f'<div class="signal"><b>{match.label_zh}</b><br><span class="muted">{match.label_en}</span><br>证据：{match.evidence}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("未命中该维度的规则 / No rule matched")

tab_flags, tab_types, tab_rules = st.tabs(["🚩 综合风险信号", "🧭 疑似诈骗类型", "🔎 规则与局限"])
with tab_flags:
    if analysis.all_flags:
        for flag in analysis.all_flags:
            st.write(f"- {flag}")
    else:
        st.write("未检出明确风险信号。")
    if analysis.cross_border_hits:
        st.info("跨境线索：" + "；".join(analysis.cross_border_hits))
with tab_types:
    if analysis.scam_types:
        st.write("系统识别到的可能类型（可多选）：")
        for item in analysis.scam_types:
            st.write(f"- {item}")
    else:
        st.write("没有足够关键词判断诈骗类型。")
with tab_rules:
    st.write("本原型使用中英文关键词、短语组合和上下文规则，不调用大模型，不上传内容。")
    st.write("自动结果仅表示文本中出现了风险线索；它不能鉴定音视频真假，也不能证明发送者一定实施诈骗。")
    st.write("人工复核分用于补充文本之外的信息，例如是否能独立回拨、账户是否为真实对公账户、音视频是否有异常痕迹。")

with st.expander("证据保全与处置清单 / Evidence and response checklist"):
    c1, c2 = st.columns(2)
    with c1:
        st.checkbox("保存完整聊天或邮件 / Preserve full chat or email")
        st.checkbox("保存账号、号码、链接和二维码 / Preserve accounts, numbers, links, QR codes")
        st.checkbox("保存原始音视频和文件 / Preserve original media and files")
    with c2:
        st.checkbox("停止转账、点击和下载 / Stop transfers, clicks, and downloads")
        st.checkbox("通过独立渠道核验 / Verify independently")
        st.checkbox("联系银行、平台或警方 / Contact bank, platform, or police")

evidence_lines = []
for key in DIMENSION_NAMES:
    for match in analysis.matches[key]:
        evidence_lines.append(f"- {DIMENSION_NAMES[key]}：{match.label_zh}｜{match.evidence}")

report = (
    f"C-TRACE 中英文风险检测摘要｜{datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
    f"语言：{analysis.language_label}\n"
    f"自动评分：{sum(auto_scores.values())}/8；复核评分：{result.total}/8；风险：{result.level} / {result.level_en}\n"
    f"身份核验 {scores['identity']}；生成内容线索 {scores['synthetic']}；紧急操控 {scores['urgency']}；财务请求 {scores['financial']}。\n"
    f"疑似类型：{'、'.join(analysis.scam_types) if analysis.scam_types else '未识别'}\n"
    f"命中证据：\n{chr(10).join(evidence_lines) if evidence_lines else '- 无'}\n"
    f"建议：{result.advice_zh}\nEnglish advice: {result.advice_en}\n"
    "说明：本结果由透明规则生成，不构成事实认定或专业意见。"
)
st.download_button(
    "下载双语检测摘要 / Download report",
    data=report.encode("utf-8-sig"),
    file_name="C-TRACE_双语风险检测摘要.txt",
    mime="text/plain",
    use_container_width=True,
)

st.caption("C-TRACE Prototype V2 · Chinese/English real-time rule detection · Explainable · No AI API · No database storage")
