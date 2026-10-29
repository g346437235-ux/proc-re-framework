# 逆向方法论：六步法

> 这套流程适用于绝大多数「客户端 ↔ 服务端」长连接游戏。
> 核心思想：**先用统计找到结构，再用结构推导语义**，不要一上来猜字段含义。

---

## 第 0 步：确定分析面

先决定用哪条路径，这决定了风险和成本：

| 路径 | 能拿到什么 | 成本 | 风险 |
|---|---|---|---|
| **A. 离线 pcap** | 协议结构、命令号、字段布局 | 低，纯只读 | 无（不接触服务端） |
| **B. 客户端代码** | 命令名、字段名、业务逻辑 | 中，需反编译 | 低（静态分析） |
| **C. 在线客户端** | 实时状态、字段语义验证 | 高，需登录 | 取决于行为 |

**推荐顺序：A → B → C**。
先用 pcap 找到「有一个 cmd=X 的消息」，再用客户端代码查到「cmd=X 叫 GET_XXX」，最后才考虑在线验证。

---

## 第 1 步：流分离

### 目标
从成百上千条 TCP 连接里，找出「真正承载游戏协议」的那几条。

### 做法

1. **端口白名单**：先按端口聚类，统计每个端口的流量与包数
2. **流重组**：按 `(src, sport, dst, dport)` 归组，按 `seq` 排序，处理重传与空洞
3. **特征打分**，给每条流算分：

```
score = w1 * 首字节熵稳定度
      + w2 * 帧切分成功率
      + w3 * 双向对称性
      + w4 * (1 - 重传率)
```

4. **取 top-N** 进入下一步

### 常见陷阱

| 现象 | 原因 |
|---|---|
| 切帧大量失败 | 抓包从流中间开始（缺前导） |
| `gaps > 0` | 抓到的是采样/丢包，重组会错位 |
| 帧长看起来合理但内容乱码 | 还有一层编码未解 |

**经验值**：一条正常游戏流，`bad_frames / total_frames` 应 < 5%。超过就说明切错了。

---

## 第 2 步：切帧

### 目标
把字节流切成「一条一条消息」。

### 三种常见布局

**A. 长度前缀（最常见）**

```
[len:4][header][body]
```

注意 length 的语义有两种，必须试：
- `len` = 整帧长度（含自身 4 字节）
- `len` = 整帧长度 − 4（即 body 长度）

**B. 固定头 + 变长体**

```
[magic:2][ver:1][type:1][len:2][body]
```

**C. 分隔符**（罕见，游戏协议基本不用）

```
{json}\n{json}\n
```

### 打分验证

对每种假设都跑一遍切分，用三个指标选：

```
1. 切出的帧数是否合理（10 ~ 数千）
2. 帧长分布是否集中在有限几个值（有峰值 = 对）
3. 从切出的帧里解析出的字段，是否符合「单调/有界/枚举少」的特征
```

详见 `docs/FRAME_SCORING.md`。

---

## 第 3 步：编码识别

### 目标
搞清楚 body 到底怎么编码的。

### 常见编码与识别特征

| 编码 | 识别特征 |
|---|---|
| **明文 JSON** | 首字节 `[` `{`，UTF-8 合法 |
| **zlib** | 首两字节 `78 9C` / `78 01` / `78 DA`；`inflate` 成功 |
| **raw deflate** | 无 magic，需在偏移 0~16 逐个试 `wbits=-15` |
| **gzip** | `1F 8B` |
| **单字节异或** | 熵高但 `key` 固定时，对同一 key 异或后 JSON 合法 |
| **二进制 protobuf** | 首字节是 tag，`(tag & 7)` 是 wire type ∈ {0,1,2,5} |

### 关键技巧：已知明文攻击

异或编码最容易被破。如果明文一定以某前缀开头（如 `[` 或 `{"`），那么：

```
key = cipher[0] ^ 0x5B     # 假设明文以 '[' 开头
```

然后**用整段必须是合法 JSON** 来校验这个 key 对不对。这是自校验的，不需要试 256 次。

```python
def guess_xor_key(cipher, prefixes=(b'[', b'{')):
    for p in prefixes:
        k = cipher[0] ^ p[0]
        plain = bytes(b ^ k for b in cipher)
        if looks_like_structured(plain):
            return k
    return None
```

### 混合编码

真实协议常常是「头 + 编码后的 body」，且**不同类型的消息用不同编码**。所以：

```
body 前若有几个字节的头，这些字节常常是：
  - 未压缩长度（4 字节大端）
  - 偏移量 / 标志位
  - 编码类型枚举
```

**必须把「偏移」也当成变量去扫**，不要假设编码从 body 第 0 字节开始。

---

## 第 4 步：表结构还原

### 目标
很多游戏协议会一次性下发「数据库表快照」。这些表通常长这样：

```
["demo_table,col_a,col_b,col_c", [row1...], [row2...], ...]
```

或者

```
[["demo_table", [cols...], [rows...]], ...]
```

### 做法

1. 找到「列名字符串数组」，这是**免费的 schema**
2. 把后续的行数组按列序 zip 成 dict
3. 记录每张表的**主键列**（通常第一列）

### 数据模型

```python
{
  "demo_table": {
    "columns": ["col_a", "col_b", "col_c"],
    "key": "col_a",              # 主键
    "rows": {                    # 按主键索引
       "k1": {"col_a": "k1", "col_b": 1},
    }
  }
}
```

### 增量更新

服务器后续只发 patch：

```
[op, table, payload]
  op=1 insert  → payload = 整行
  op=2 update  → payload = [ignore, key, field_idx, value, field_idx, value, ...]
  op=3 delete  → payload = [key]
```

**关键**：`field_idx` 是**列下标**，要用 schema 映射回列名。

```python
def apply_update(store, table, payload):
    cols = store[table]["columns"]
    key  = payload[1]
    row  = store[table]["rows"].setdefault(key, {cols[0]: key})
    for i in range(2, len(payload), 2):
        idx, val = payload[i], payload[i+1]
        row[cols[idx]] = val
```

这就是「快照 + 叠加层」模型，能让你**不重启客户端**就看到最新值。

---

## 第 5 步：语义推断

到了这一步，你有：命令号、编解码、表结构、字段名。
还缺：**字段到底什么含义、命令之间什么因果关系**。

### 方法：单变量实验

每次只改一个东西，观察响应差异。

```
对照组：cmd=A, payload=[0]
实验组：cmd=A, payload=[1]
比较两份响应 → 差异字段就是 payload 控制的那个东西
```

### 方法：异常信息反推

很多服务端在参数不对时会抛异常，**异常信息本身就是免费的规格说明**：

```
Index 1 out of bounds for length 1   → 这个命令要 ≥2 个参数
非法参数                              → 参数数量对，但取值不合法
未定义指令                            → 这个命令号服务端根本没有
该功能暂未开放                        → 命令存在，但功能被开关关闭
```

**这一条极其高效**：先用空数组、单元素数组去撞，从异常信息里读出参数个数。

```python
for n in range(0, 5):
    r = send(cmd, [0] * n)
    print(n, r.error)     # IndexOutOfBounds(n) 说明还需要更多参数
```

### 方法：状态对比

改动前后各抓一次全量快照，做 diff。

```python
before = snapshot()
do_something()
after = snapshot()
print(diff_tables(before, after))
```

---

## 第 6 步：固化与回归

分析出来的东西**必须立刻变成可重复执行的代码**，否则下次全丢。

### 三层固化

| 层 | 形式 | 作用 |
|---|---|---|
| **常量层** | `private.json` | 端口、magic、密钥、命令号 |
| **逻辑层** | `src/*.py` | 通用算法（可发布） |
| **业务层** | `plugins/*.py` | 具体游戏的 op |

### 回归测试

每加一个新结论，就加一条断言：

```python
def test_frame_layout():
    frames, bad = split(buf, uplink=False)
    assert bad / len(buf) < 0.05
    assert all(len(f) >= 12 for f in frames)

def test_codec_roundtrip():
    for f in frames:
        plain = decode(f)
        assert is_structured(plain)
```

---

## 附：常见卡点与突破思路

| 卡点 | 突破思路 |
|---|---|
| 帧切不干净 | 换 length 语义（含/不含自身）；试大端/小端；考虑流中间开始 |
| 编码解不开 | 扫偏移（0~32）+ 扫 wbits（-15/15/47）；考虑「头 + 编码体」 |
| 字段名全无 | 找列名数组；找客户端代码里的常量表 |
| 命令号对不上 | 客户端版本 ≠ 服务端版本；异常信息会告诉你「未定义」 |
| 状态对不上 | 你没应用增量；或者读的是登录快照的旧值 |
| 服务端无响应 | 前置状态不对（未登录/未选角/活动未开）；不是协议问题 |

---

## 一句话总结

> **结构靠统计，语义靠差分，规格靠异常。**
