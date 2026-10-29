# -*- coding: utf-8 -*-
"""示例 1：分析一个 pcap 的协议结构

演示完整流程：
    pcap → 流重组 → 布局探测 → 切帧 → 编码探测 → 命令号统计

运行：
    python examples/analyze_pcap.py capture.pcap
    python examples/analyze_pcap.py capture.pcap --port 12345 --config private.json
"""

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import stream as st          # noqa: E402
from src import frame as fr           # noqa: E402
from src import codec as cd           # noqa: E402
from src.config import Config         # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", "-p", type=int, action="append")
    ap.add_argument("--config", "-c")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    ports = args.port or cfg.ports

    # ---------- 1 流重组 ----------
    print("=" * 60)
    print("[1] 流重组")
    streams = st.collect_streams(args.pcap, ports=ports)
    rows = st.summary(streams, ports=ports)
    if not rows:
        print("  没有匹配的流。试试 --port，或者不加 --port 看全部：")
        streams = st.collect_streams(args.pcap)
        rows = st.summary(streams)
    for r in rows[:5]:
        print("  %-20s -> %-20s %8dB segs=%-4d gaps=%d %s"
              % (r["src"], r["dst"], r["bytes"], r["segs"], r["gaps"],
                 "OK" if r["reliable"] else "HOLE"))
    if not rows:
        print("  完全没有 TCP 流量")
        return 1

    # ---------- 2 布局探测 ----------
    print("\n[2] 帧布局探测")
    top = streams[rows[0]["key"]]
    cands = []
    for hl in (4, 8, 12, 16):
        for endian in ("big", "little"):
            for incl in (True, False):
                cands.append({
                    "header_len": hl, "length_offset": 0, "length_size": 4,
                    "endian": endian, "length_includes_self": incl,
                    "min_frame_len": 5, "max_frame_len": 1 << 22,
                })
    scored = sorted((fr.score_layout(top.data, c) | {"cfg": c}
                     for c in cands), key=lambda x: -x["score"])
    for r in scored[:3]:
        c = r["cfg"]
        print("  score=%.3f header_len=%-2d endian=%-6s incl_self=%-5s frames=%d"
              % (r["score"], c["header_len"], c["endian"],
                 c["length_includes_self"], r["n_frames"]))
    best = scored[0]["cfg"] if scored else cfg.frame
    if args.config:
        best = cfg.frame

    # ---------- 3 切帧 + 编码 ----------
    print("\n[3] 切帧 + 编码探测")
    chain = cd.build_chain(cfg.codecs)
    ports_set = set(ports or [])
    cmd_counter = Counter()
    codec_counter = Counter()
    samples = []
    for r in rows[:5]:
        s = streams[r["key"]]
        if not s.data:
            continue
        up = (s.dport in ports_set) if ports_set else True
        frames, bad = fr.split(s.data, best, uplink=up)
        for f in frames:
            plain, name = chain.decode(f)
            if plain is None:
                continue
            codec_counter[name] += 1
            # 命令号：取 header 里第一个长度字段之后的 4 字节（仅作演示）
            off = best["length_offset"] + best["length_size"]
            if len(f.raw) >= off + 4:
                import struct
                import sys as _s
                cmd = struct.unpack_from(
                    (">" if best["endian"] == "big" else "<") + "i",
                    f.raw, off)[0]
                cmd_counter[cmd] += 1
            if len(samples) < 3:
                samples.append((name, plain[:120]))
        print("  %-20s -> %-20s frames=%-4d bad=%-4d"
              % (r["src"], r["dst"], len(frames), bad))

    print("\n  codec 命中: %s" % dict(codec_counter))
    print("  命令号 top10: %s" % cmd_counter.most_common(10))

    print("\n[4] 解码样例")
    for name, head in samples:
        print("  [%s] %r" % (name, head[:100]))

    print("\n完成。把探测到的 best cfg 写进 private.json 的 frame 段即可复用。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
