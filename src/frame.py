# -*- coding: utf-8 -*-
"""变长帧切分 + 合法性打分

协议里的帧通常是「长度前缀 + 头 + 体」。难点在于 length 的语义有歧义：

    A) len  = 整帧长度（含 length 自身 4 字节）
    B) len  = 整帧长度 − 4（即 body 长度）

还有一种更坑的：帧从流中间开始（抓包早于握手），第一帧是残的。

本模块不猜，而是**把所有假设都跑一遍，用打分选最优**。

用法：
    from src.frame import split, score_layout
    frames, bad = split(buf, cfg.frame, uplink=True)
    best = score_layout(buf, cfg.frame)     # {'score':..,'layout':..}
"""

import struct
from dataclasses import dataclass

from .config import Config


@dataclass
class Frame:
    raw: bytes
    length: int           # 头部声明值
    total_len: int        # 实际字节数
    cmd: int = None
    seq: int = None
    body: bytes = b""
    direction: str = "?"
    ok: bool = True

    def __len__(self):
        return len(self.raw)

    def __repr__(self):
        return "<Frame cmd=%s len=%d>" % (self.cmd, self.total_len)


# ================================================================== 切分
def split(buf, frame_cfg, uplink=True, resync=True):
    """按长度前缀切帧

    frame_cfg : dict（见 config.py 的 DEFAULTS['frame']）
    uplink    : True 时 length 语义按「不含自身」，False 按「含自身」
                实际以配置的 length_includes_self 为准
    resync    : 切失败时是否逐字节前移重新对齐（慢但鲁棒）

    返回 (frames, bad_bytes)
    """
    off_len = int(frame_cfg.get("length_offset", 0))
    sz = int(frame_cfg.get("length_size", 4))
    endian = frame_cfg.get("endian", "big")
    incl_self = bool(frame_cfg.get("length_includes_self", True))
    min_len = int(frame_cfg.get("min_frame_len", 5))
    max_len = int(frame_cfg.get("max_frame_len", 1 << 22))
    fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}.get(sz)
    if fmt is None:
        raise ValueError("length_size 只能是 1/2/4/8")
    endian_ch = ">" if endian == "big" else "<"

    frames = []
    bad = 0
    o = 0
    n = len(buf)
    while o + max(off_len + sz, 1) <= n:
        try:
            ln = struct.unpack_from(endian_ch + fmt, buf, o + off_len)[0]
        except struct.error:
            break
        total = ln if incl_self else ln + off_len + sz
        if total < min_len or total > max_len or o + total > n:
            bad += 1
            o += 1 if resync else total if total > 0 else 1
            continue
        raw = buf[o:o + total]
        hl = int(frame_cfg.get("header_len", 0))
        body_start = min(off_len + sz + hl, total)
        fr = Frame(raw=raw, length=ln, total_len=total,
                    body=raw[body_start:], direction="up" if uplink else "down")
        frames.append(fr)
        o += total
    if o < n:
        bad += n - o
    return frames, bad


# ================================================================== 打分
def score_layout(buf, frame_cfg, sample=400):
    """给当前 layout 打分（0~1，越高越可信）

    打分维度：
      1. 切分成功率        bad / len 越小越好
      2. 帧数合理性        太少说明切错，太多说明碎切
      3. 帧长集中度        真实协议帧长有峰值
      4. 双向一致性        （单个 buf 无法算，留作外部合并）
    """
    frames, bad = split(buf, frame_cfg, resync=True)
    n = max(len(buf), 1)
    if not frames:
        return {"score": 0.0, "n_frames": 0, "bad": bad, "reasons": ["no frames"]}

    # ---- 1 成功率 ----
    success = max(0.0, 1.0 - bad / n)

    # ---- 2 帧数合理性 ----
    # 期望：平均每帧 >= header+4 字节，且帧数不至于离谱
    hl = int(frame_cfg.get("header_len", 0))
    min_reasonable = max(hl + 4, 8)
    avg_len = sum(len(f) for f in frames) / len(frames)
    count_score = 1.0
    if avg_len < min_reasonable:
        count_score = avg_len / min_reasonable
    if len(frames) > n / 4:
        count_score *= 0.5

    # ---- 3 帧长集中度（熵） ----
    lens = [len(f) for f in frames[:sample]]
    uniq = len(set(lens))
    conc = 1.0 / (1.0 + uniq / max(len(lens), 1))   # 越集中越高

    # ---- 4 头部可读性提示 ----
    head_ok = 0
    for f in frames[:sample]:
        if len(f.raw) >= 4:
            head_ok += 1

    score = 0.5 * success + 0.2 * count_score + 0.3 * conc
    reasons = []
    if success < 0.95:
        reasons.append("success=%.2f" % success)
    if count_score < 0.8:
        reasons.append("count=%.2f" % count_score)
    if conc < 0.1:
        reasons.append("no peak in frame sizes")
    return {"score": round(score, 4), "n_frames": len(frames),
            "bad": bad, "avg_len": round(avg_len, 1),
            "unique_lens": uniq, "reasons": reasons}


def best_layout(buf, candidates):
    """在多个 frame 配置里选最优

    candidates : [frame_cfg, ...]
    返回 (best_cfg, best_result)
    """
    best, best_r = None, None
    for cfg in candidates:
        r = score_layout(buf, cfg)
        if best_r is None or r["score"] > best_r["score"]:
            best, best_r = cfg, r
    return best, best_r


def candidate_layouts(header_len=0, length_size=4):
    """生成常见 layout 组合，供 best_layout 使用"""
    out = []
    for endian in ("big", "little"):
        for incl in (True, False):
            for off in (0,):
                out.append({
                    "header_len": header_len,
                    "length_offset": off,
                    "length_size": length_size,
                    "endian": endian,
                    "length_includes_self": incl,
                    "min_frame_len": 5,
                    "max_frame_len": 1 << 22,
                })
    return out


# ================================================================== 便捷
def split_stream(stream, cfg, uplink=None):
    """对 Stream 自动判断方向并切帧"""
    ports = set(cfg.ports)
    if uplink is None:
        uplink = (stream.dport in ports)
    return split(stream.data, cfg.frame, uplink=uplink)


if __name__ == "__main__":
    import sys
    from .stream import collect_streams, summary
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    cfg = Config.load(sys.argv[2] if len(sys.argv) > 2 else None)
    streams = collect_streams(sys.argv[1], ports=cfg.ports)
    for key, s in streams.items():
        if not s.data:
            continue
        best, r = best_layout(s.data, candidate_layouts(
            cfg.frame.get("header_len", 0)))
        print("%s -> %s  best=%s" % (key, r, best))
