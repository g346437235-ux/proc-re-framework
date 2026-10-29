# 帧合法性打分算法

> 切帧是协议分析里最容易出错的一步。本文说明 `src/frame.py`
> 里 `score_layout()` 的打分依据，以及怎么调。

---

## 1 为什么需要打分

同一段字节流，用不同的 layout 假设去切，可能都能切出「看起来合理」的帧：

```
假设 A（length 含自身）：
  切出 38 帧，平均 120 字节，帧长集中在 40/120/240

假设 B（length 不含自身）：
  切出 41 帧，平均 110 字节，帧长分布很散

假设 C（小端）：
  切出 2 帧，一帧 2000 字节
```

肉眼很难判断，但**打分可以**。核心直觉：

- 真实协议的帧长**有峰值**（命令种类有限，每种长度固定）
- 切错时，帧数会异常（太少=把多帧并成一条，太多=碎切）
- 切错时，坏字节比例会高

---

## 2 四个维度

### 维度 1：切分成功率（权重 0.5）

```
success = 1 - bad_bytes / total_bytes
```

`bad_bytes` 是「长度字段指向非法值」而被跳过的字节数。

**阈值参考**：
- `success > 0.98` → 基本正确
- `0.90 ~ 0.98` → 可能是流中间开始，前几帧残缺
- `< 0.90` → layout 错了

### 维度 2：帧数合理性（权重 0.2）

```
min_reasonable = header_len + 4
avg_len = mean(frame_len)
count_score = 1.0  if avg_len >= min_reasonable
            = avg_len / min_reasonable  otherwise
```

另外如果 `n_frames > total_bytes / 4`，说明平均每帧不到 4 字节——碎切，扣分。

### 维度 3：帧长集中度（权重 0.3）

```
unique_lens = len(set(frame_lens))
conc = 1 / (1 + unique_lens / n_frames)
```

- 完全分散（每帧长度都不同）→ `conc ≈ 0`
- 只有 3 种长度 → `conc ≈ 0.75`

真实协议 `conc` 通常 > 0.3。

### 维度 4（外部）：双向一致性

单个 buffer 算不出来，需要在 `summary` 层做：

```
如果 uplink 和 downlink 用同一 layout 都能切干净 → 大幅加分
```

---

## 3 总分

```python
score = 0.5 * success + 0.2 * count_score + 0.3 * conc
```

范围 `[0, 1]`。经验阈值：

| score | 含义 |
|---|---|
| **> 0.85** | 高度可信，可以直接用 |
| 0.70 ~ 0.85 | 大概率对，需人工看几个帧头确认 |
| 0.50 ~ 0.70 | 可疑，换 layout 试试 |
| **< 0.50** | 基本可以放弃这个假设 |

---

## 4 常见失败模式与对策

### 模式 A：流从帧中间开始

**现象**：`success` 只有 0.9 左右，前几十字节被跳过。

**对策**：跳过前 N 字节再切，或者接受 `resync` 的逐字节前移。

```python
# 找到第一个能连续切干净的位置
for skip in range(64):
    frames, bad = split(buf[skip:], cfg)
    if bad < len(buf) * 0.01:
        print("skip =", skip)
        break
```

### 模式 B：length 语义相反

**现象**：两个假设的 `success` 都还行，但帧长分布不同。

**对策**：看哪个的平均帧长更接近「你从别的渠道知道的典型值」，或者看 `header_len` 是否与帧长匹配。

### 模式 C：有「心跳/填充」帧

**现象**：大部分帧切得很好，但每隔几十帧出现一次 `bad`。

**对策**：把这类帧识别出来单独处理，不要因此否定整个 layout。

```python
# 统计坏字节的位置分布，如果周期性出现，说明是特定帧类型
```

### 模式 D：两层长度

**现象**：外层 length 正确，但 body 内部还有一层「长度 + 数据」。

**对策**：切完外层后，对 body 再做一次切分。这是「帧套帧」，很常见。

```python
outer, _ = split(buf, outer_cfg)
for f in outer:
    inner, _ = split(f.body, inner_cfg)
```

---

## 5 自动化建议

写个脚本，把所有假设一次性跑完并输出表格：

```python
from src.frame import candidate_layouts, score_layout

results = []
for c in candidate_layouts():
    r = score_layout(buf, c)
    results.append((r["score"], c, r))

results.sort(key=lambda x: -x[0])
for score, cfg, r in results[:5]:
    print(score, cfg)
```

然后**人工确认 top1**：打印前 5 个帧的头部 hex，看是否符合你从客户端代码里读到的结构。

**打分只用来缩小范围，最终判定一定要靠人**。
