# 游戏协议逆向分析框架（通用版）

> 一套用于**分析闭源手游网络协议**的工程化框架。
> 本文档 + 代码是「方法论 + 骨架」，**不含任何具体游戏的协议常量、密钥、风控绕过或可直接获利的操作**。
> 游戏相关参数由使用者填入自己的 `private.json`（不随本项目分发）。

---

## 1 这个框架解决什么问题

闭源手游的协议分析通常是这样的痛点：

| 痛点 | 本框架的应对 |
|---|---|
| 抓到的 pcap 混杂广告/心跳/CDN，找不到有效连接 | 端口白名单 + 流重组 + 帧合法性打分 |
| 协议是**变长帧 + 自定义头 + 混合编码**（明文/压缩/异或/二进制） | 可插拔 Codec 链，逐帧自动试探 |
| 数据是**带 schema 的表快照**，字段全无名字 | schema-aware 表存储（列名来自登录响应） |
| 增量更新（DELTA_UPDATE）和全量快照混在一起 | 快照 + 叠加层（overlay）双层模型 |
| 反复重启客户端才能看到状态变化 | 常驻进程 + 本地控制口（JSON-lines） |
| 分析结论散落在各种临时脚本里 | 统一 CLI + 插件化 op 注册 |

---

## 2 架构总览

```
                 ┌──────────────────────────────────────┐
   抓包产物 ────▶ │  stream.py   TCP 流重组（去重/补洞）   │
   (.pcap)        └──────────────┬───────────────────────┘
                                 ▼
                 ┌──────────────────────────────────────┐
                 │  frame.py    变长帧切分 + 合法性打分   │
                 └──────────────┬───────────────────────┘
                                 ▼
                 ┌──────────────────────────────────────┐
                 │  codec.py    编码探测链（可插拔）      │
                 │  ├ PlainCodec   明文                  │
                 │  ├ DeflateCodec 压缩                  │
                 │  ├ XorCodec     单字节异或             │
                 │  └ YourCodec    ← 你私有的实现         │
                 └──────────────┬───────────────────────┘
                                 ▼
                 ┌──────────────────────────────────────┐
                 │  tables.py   schema 感知的表存储       │
                 │  快照层 + 增量叠加层                   │
                 └──────────────┬───────────────────────┘
                                 ▼
                 ┌──────────────────────────────────────┐
                 │  cli.py      子命令 / 插件 op 注册      │
                 └──────────────────────────────────────┘
```

### 两条独立的分析路径

**路径 A：离线 pcap 分析**（只读，零风险）

```
pcap ─▶ streams ─▶ frames ─▶ codec ─▶ 统计/检索
```

适合：摸清协议结构、找命令号、验证字段语义。

**路径 B：在线客户端**（需要登录凭据，风险自担）

```
登录链 ─▶ 会话 ─▶ 本地控制口(127.0.0.1) ─▶ 脚本调用
```

适合：读取实时状态、验证字段含义、复现操作。

> 本发布包只提供**路径 A 的完整实现**；路径 B 只给架构与接口定义。

---

## 3 目录结构

```
publish/
├─ README.md                 ← 本文件
├─ ARCHITECTURE.md           ← 分层与数据模型细节
├─ METHODOLOGY.md            ← 逆向方法论（六步法）
├─ SANITIZE.md               ← ★ 剔除清单：哪些被隐藏、为什么
├─ requirements.txt
├─ config.example.json       ← 参数模板（需自行填写私有的 private.json）
├─ src/
│  ├─ __init__.py
│  ├─ config.py              配置加载
│  ├─ stream.py              TCP 流重组
│  ├─ frame.py               变长帧切分
│  ├─ codec.py               编码探测链
│  ├─ tables.py              schema 感知表存储
│  └─ cli.py                 命令行入口
├─ examples/
│  ├─ analyze_pcap.py        示例：统计 pcap 里的连接与帧
│  └─ dump_tables.py         示例：把表导成 CSV
└─ docs/
   └─ FRAME_SCORING.md       帧合法性打分算法说明
```

---

## 4 快速开始

```bash
# 0 只依赖标准库（Python >= 3.8），无需 pip install

# 1 生成 demo 数据（纯造数据，不含任何真实游戏内容）
python examples/make_demo_pcap.py

# 2 看 pcap 概要
python -m src.cli stats demo/demo_plain.pcap

# 3 列 TCP 流
python -m src.cli pcap-streams demo/demo_plain.pcap --port 12345

# 4 自动探测帧布局
python -m src.cli probe demo/demo_plain.pcap --port 12345

# 5 切帧统计
python -m src.cli pcap-frames demo/demo_plain.pcap -c demo/demo.json

# 6 跑编码探测链（zlib / raw-deflate / 异或 混合流）
python -m src.cli codecs demo/demo_codec.pcap -c demo/demo.json

# 7 表存储与导出
python examples/dump_tables.py --out ./out --json
```

### 实测输出（可直接对照）

**`stats`**
```
文件      : demo/demo_plain.pcap (1.7KB)
包总数    : 9
TCP 包    : 9
载荷字节  : 1.6KB
目的端口分布 (top 15):
  12345        9
```

**`probe`**（自动探测布局 + 判定 header_len）
```
TOP 5 候选布局:
  score=0.900  header_len=4   endian=big    incl_self=True  frames=40
  score=0.900  header_len=8   endian=big    incl_self=True  frames=40
  ...

header_len 判定（看 body 是否像结构化数据）：
  header_len=0   结构化占比 0%   (0/40)
  header_len=4   结构化占比 0%   (0/40)
  header_len=8   结构化占比 100% (40/40)
  header_len=12  结构化占比 0%   (0/40)
  → 建议 header_len = 8（结构化占比 100%）
```

**`pcap-frames`**
```
10.0.0.2:51234 -> 1.2.3.4:12345  UP frames=40  bad=0  avg=41B  OK
合计 frames=40 bad_bytes=0 (0.00%)
```

**`codecs`**（混合编码流）
```
解码成功 12 / 失败 0  (100.0%)
各 codec 命中:
  zlib     4
  deflate  4
  xor      4
样例:
  [zlib]    19B  b'{"i": 0, "kind": 0}'
  [deflate] 19B  b'{"i": 1, "kind": 1}'
  [xor]     19B  b'{"i": 2, "kind": 2}'
```

**`dump_tables.py`**（快照 + 增量 + 导出）
```
[1] 从响应载荷识别表   识别到 1 个表 {'demo_users': 0}
[2] 应用增量          insert / update / delete
[3] 当前视图          3 行（含 update 后的 7777、insert 的 1004）
[4] 导出              demo_users.csv  3 行
```

### 换成你自己的数据

```bash
cp config.example.json private.json
# 填入你自己的端口 / 帧布局 / codec 参数
python -m src.cli pcap-frames your.pcap -c private.json
```

---

## 5 设计原则

1. **凡是可以从数据里推出来的，都不要写死**
   端口、magic、编码方式全部走配置或自动探测。

2. **编码用策略链，不做 if-else 森林**
   每帧依次尝试 codec，用「解出来的东西像不像结构化数据」打分。

3. **表存储必须 schema-aware**
   协议里表是「列名数组 + 行数组」，把列名和行绑在一起，否则后面全是下标魔法。

4. **快照与增量分开**
   全量快照是基线，增量是 patch。混在一起永远对不上账。

5. **一切结论可复现**
   每个分析结论都要能指回「哪条 pcap / 哪一帧 / 哪个字段」。

---

## 6 免责声明

本项目是**协议分析工程实践**的教学材料。

- 不含任何游戏的密钥、协议常量、反作弊绕过代码；
- 不含账号凭据、自动化刷取、获利操作；
- 使用者应自行确认对目标服务的行为符合其服务条款与当地法律。

作者不对任何滥用后果负责。
