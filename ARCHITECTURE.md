# 分层架构与数据模型

---

## 1 分层职责

```
┌─────────────────────────────────────────────────────────┐
│ 业务层 plugins/                                          │
│   具体游戏的 op：查询状态、业务动作                        │
│   ⚠ 不在本发布包内                                       │
├─────────────────────────────────────────────────────────┤
│ 会话层 session                                          │
│   长连接、重连、请求/响应配对、超时                       │
│   ⚠ 不在本发布包内（只给接口）                            │
├─────────────────────────────────────────────────────────┤
│ 协议层 codec + frame + stream                            │
│   切帧、编解码、流重组                                    │
│   ✅ 本包提供通用实现                                     │
├─────────────────────────────────────────────────────────┤
│ 存储层 tables                                            │
│   schema 感知的表快照 + 增量叠加                          │
│   ✅ 本包提供                                            │
├─────────────────────────────────────────────────────────┤
│ 配置层 config                                            │
│   端口、magic、密钥、命令号（外部 json）                   │
│   ✅ 本包提供加载器，值由使用者填                          │
└─────────────────────────────────────────────────────────┘
```

---

## 2 数据模型

### 2.1 Frame（帧）

```python
@dataclass
class Frame:
    raw: bytes            # 原始字节
    length: int           # 头部声明的长度
    cmd: int | None       # 命令号（若可解析）
    seq: int | None       # 序号（若可解析）
    body: bytes           # 载荷
    direction: str        # 'up' | 'down'
    ok: bool              # 切分是否可信
```

### 2.2 Stream（流）

```python
@dataclass
class Stream:
    key: tuple            # (src, sport, dst, dport)
    data: bytes           # 重组后的连续字节
    nseg: int             # 段数
    gaps: int             # 空洞数（>0 表示重组不可信）
    first_ts: float
    last_ts: float
```

**`gaps` 是最重要的质量指标**。`gaps > 0` 时后续切帧结果一律不可信。

### 2.3 TableStore（表存储）

```python
class TableStore:
    def __init__(self):
        self.schema = {}      # table -> [(col, type)]
        self.snapshot = {}    # table -> [row, ...]
        self.overlay = {}     # table -> {key: {col: val}}

    def get(self, table) -> list[dict]:
        """快照 + 增量合并后的视图"""
```

合并规则：

```
merged = {key(row): row for row in snapshot}
for key, patch in overlay.items():
    merged.setdefault(key, {}).update(patch)
```

**为什么必须分两层**：
- `snapshot` 是登录那一刻的基线，永远不变
- `overlay` 是之后的每次增量
- 只看 snapshot → 数据永远是旧的
- 只看 overlay → 看不到没变过的行
- 两者合并 → 得到当前真实状态

### 2.4 Codec（编解码器）

策略模式，每个 codec 负责：
1. `probe(frame) -> bool`：判断「我这帧归我管」
2. `decode(frame) -> bytes | None`：解码，失败返回 None
3. `encode(obj) -> bytes`：编码（可选，只读分析不需要）

```python
class Codec(ABC):
    name: str = 'base'
    def probe(self, frame: Frame) -> bool: ...
    def decode(self, frame: Frame) -> bytes | None: ...
```

**探测链原则**：从「最确定」到「最试探」排序，第一个成功的胜出。

```
PlainCodec    → 首字节是 [ { 就直接返回
GzipCodec     → 1F 8B
ZlibCodec     → 78 9C/01/DA
DeflateCodec  → 扫偏移 + wbits=-15
XorCodec      → 已知明文攻击
BinaryCodec   → protobuf 启发式
```

---

## 3 配置分层

```json
{
  "ports": [12345],
  "frame": {
    "header_len": 12,
    "length_offset": 0,
    "length_size": 4,
    "endian": "big",
    "length_includes_self": true
  },
  "codecs": [
    {"type": "plain"},
    {"type": "zlib", "offset_scan": [0, 4, 6]},
    {"type": "xor", "key": null, "guess_from_prefix": "[{"}
  ],
  "tables": {
    "snapshot_cmd": 0,
    "update_cmd": 0
  }
}
```

**敏感值全部留空**，使用者自己填。

---

## 4 错误处理原则

| 层 | 失败时的行为 |
|---|---|
| config | 立即抛错，不要用默认值猜 |
| stream | 记录 `gaps`，不抛错 |
| frame | 记录 `bad`，继续切 |
| codec | 返回 None，交给下一个 codec |
| tables | 缺 schema 就跳过该表，不崩溃 |

**核心**：分析工具要「尽量多产出信息」，不要一遇错就停。

---

## 5 性能考虑

- pcap 读取：流式，不要一次读进内存
- 流重组：用 `dict[seq] = payload`，最后按 seq 排序拼接，比逐段插入快
- 切帧：一次遍历，不要反复切片
- codec 探测：先做 O(1) 的首字节判断，再做 O(n) 的解压

对于 100 MB 级别的 pcap，纯 Python 标准库实现可以在 30 秒内完成重组 + 切帧。
