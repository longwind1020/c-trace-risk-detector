# C-TRACE 原型 V2

一个透明、规则驱动的中英文跨境 AI 诈骗内容检测工具。用户可粘贴中文、英文或中英混合的聊天、邮件和电话转写文本，系统实时显示命中的规则、证据片段、四维评分、疑似诈骗类型、跨境线索和双语行动建议。

核心功能：

- 中英文及混合文本检测；
- 身份核验、生成内容线索、紧急操控、财务请求四维自动评分；
- 每项结果展示命中规则和原文证据；
- 自动评分可以人工复核和覆盖；
- 识别疑似冒充高管、冒充亲友、公检法、投资、虚拟绑架和虚假客服；
- 检测境外账户、海外场景、国际平台和加密货币线索；
- 下载双语检测摘要和使用证据保全清单；
- 不调用大模型或OpenAI API，不使用数据库保存输入。

## 本地运行

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

## 评分规则

| 维度 | 0分 | 1分 | 2分 |
|---|---|---|---|
| 身份核验 | 可通过独立官方渠道核实 | 需间接核实 | 无法核实任何身份信息 |
| 生成内容线索 | 有明显AI标识/来源可查 | 有可疑痕迹 | 完全无标识/来源不明 |
| 紧急操控 | 无紧急要求 | 有紧急但可核实 | 紧急且要求保密/不得核验 |
| 财务请求 | 正常对公账户 | 陌生个人账户 | 加密货币/境外账户/频繁变更 |

- 0–2分：低风险——建议通过官方渠道进一步核实。
- 3–5分：中风险——停止当前操作，通过独立渠道核验身份。
- 6–8分：高风险——立即停止；不转账、不点击、不下载；保存证据并联系官方。

## 部署到互联网（非 OpenAI 平台）

推荐使用 [Streamlit Community Cloud](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app)：

1. 将 `ctrace_streamlit` 文件夹内容上传到 GitHub 仓库。
2. 登录 Streamlit Community Cloud，选择 **Create app**。
3. 选择仓库、分支，并把入口文件设为 `app.py`。
4. 点击部署。平台会根据 `requirements.txt` 安装依赖。

也可以部署到 Render、Railway 或自有服务器，启动命令为：

```text
streamlit run app.py --server.address 0.0.0.0 --server.port $PORT
```

## 验证

```powershell
python -m unittest discover -s tests -v
```

本应用不需要数据库，也不会主动存储用户输入。它是风险提示工具，不能替代警方、银行、平台或法律专业意见。
