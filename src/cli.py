# -*- coding: utf-8 -*-
"""命令行入口

子命令：
    stats         pcap 概要（连接数、包数、端口分布）
    pcap-streams  TCP 流清单（按流量降序）
    pcap-frames   切帧统计（需要 --config 或自动探测）
    probe         自动探测帧布局（在多个候选里选最优）
    codecs        对某条流的帧跑编码探测链
    export        把表导出成 CSV/JSON

用法：
    python -m src.cli stats          capture.pcap
    python -m src.cli pcap-streams   capture.pcap --port 12345
    python -m src.cli probe          capture.pcap --config private.json
    python -m src.cli codecs         capture.pcap --config private.json
"""

import argparse
import json
import os
import sys
from collections import Counter

from . import stream as st
from . import frame as fr
from . import codec as cd
from .config import Config, ConfigError


def _fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%.1fTB" % n


# ================================================================== 子命令
def cmd_stats(args):
    cfg = Config.load(args.config)
    ports_c = Counter()
    n_pkt = 0
    n_tcp = 0
    total = 0
    for ts, linktype, raw in st.read_pcap(args.pcap):
        n_pkt += 1
        p = st.parse_packet(linktype, raw)
        if not p:
            continue
        n_tcp += 1
        src, sport, dst, dport, seq, flags, data = p
        total += len(data)
        ports_c[dport] += 1

    print("文件      : %s (%s)" % (args.pcap, _fmt_bytes(os.path.getsize(args.pcap))))
    print("包总数    : %d" % n_pkt)
    print("TCP 包    : %d" % n_tcp)
    print("载荷字节  : %s" % _fmt_bytes(total))
    print("目的端口分布 (top 15):")
    for port, c in ports_c.most_common(15):
        print("  %-6s %7d" % (port, c))
    return 0


def cmd_pcap_streams(args):
    cfg = Config.load(args.config)
    ports = args.port or cfg.ports
    streams = st.collect_streams(args.pcap, ports=ports)
    rows = st.summary(streams, ports=ports)
    if not rows:
        print("没有匹配的流（试试 --port 或不加过滤）")
        return 1

    print("%-24s %-24s %6s %10s %6s %5s %4s %s"
          % ("源", "目的", "方向", "字节", "段数", "空洞", "重复", "可信"))
    for r in rows[:args.top]:
        print("%-24s %-24s %6s %10s %6d %5d %4d %s"
              % (r["src"], r["dst"], r["direction"], _fmt_bytes(r["bytes"]),
                 r["segs"], r["gaps"], r["dup"],
                 "OK" if r["reliable"] else "HOLE"))

    # 汇总
    ok = sum(1 for r in rows if r["reliable"])
    print("\n共 %d 条流，可信 %d 条" % (len(rows), ok))
    if args.dump:
        with open(args.dump, "wb") as f:
            for r in rows[:1]:
                f.write(streams[r["key"]].data)
        print("已导出最大流到 %s" % args.dump)
    return 0


def _pick_streams(args, cfg):
    ports = args.port or cfg.ports
    streams = st.collect_streams(args.pcap, ports=ports)
    rows = st.summary(streams, ports=ports)
    if args.stream:
        want = args.stream
        rows = [r for r in rows if "%s-%s" % (r["src"], r["dst"]) == want]
    return streams, rows


def cmd_pcap_frames(args):
    cfg = Config.load(args.config)
    if cfg.validate() and not args.config:
        print("提示：未提供 --config，将自动探测布局\n", file=sys.stderr)
    streams, rows = _pick_streams(args, cfg)

    total_f, total_bad = 0, 0
    cmds = Counter()
    for r in rows[:args.top]:
        s = streams[r["key"]]
        if not s.data:
            continue
        up = (s.dport in set(cfg.ports)) if cfg.ports else (args.direction == "up")
        fcfg = cfg.frame
        if args.auto or not fcfg.get("header_len"):
            best, res = fr.best_layout(s.data, fr.candidate_layouts(
                fcfg.get("header_len", 0)))
            fcfg = best
        frames, bad = fr.split(s.data, fcfg, uplink=up)
        total_f += len(frames)
        total_bad += bad
        print("%-22s -> %-22s %6s frames=%-5d bad=%-5d avg=%.0fB  %s"
              % (r["src"], r["dst"], "UP" if up else "DN",
                 len(frames), bad,
                 (sum(len(f) for f in frames) / len(frames)) if frames else 0,
                 "OK" if bad < len(s.data) * 0.05 else "SUSPECT"))
        for f in frames[:args.sample]:
            print("    len=%-6d total=%-6d head=%s"
                  % (f.length, f.total_len, f.raw[:12].hex()))

    print("\n合计 frames=%d bad_bytes=%d (%.2f%%)"
          % (total_f, total_bad,
             100.0 * total_bad / max(sum(len(streams[r['key']].data) for r in rows), 1)))
    return 0


def cmd_probe(args):
    cfg = Config.load(args.config)
    streams, rows = _pick_streams(args, cfg)
    if not rows:
        print("没有流")
        return 1
    s = streams[rows[0]["key"]]
    print("分析流 %s:%s -> %s:%s  %s"
          % (s.src, s.sport, s.dst, s.dport, _fmt_bytes(len(s.data))))

    cands = []
    for hl in (args.header_len or [4, 8, 12, 16]):
        for endian in ("big", "little"):
            for incl in (True, False):
                cands.append({
                    "header_len": hl, "length_offset": 0,
                    "length_size": 4, "endian": endian,
                    "length_includes_self": incl,
                    "min_frame_len": 5, "max_frame_len": 1 << 22,
                })
    results = []
    for c in cands:
        r = fr.score_layout(s.data, c)
        results.append((r["score"], c, r))
    results.sort(key=lambda x: -x[0])

    print("\nTOP 5 候选布局:")
    for score, c, r in results[:5]:
        print("  score=%.3f  header_len=%-3d endian=%-6s incl_self=%-5s "
              "frames=%-5d avg=%.0fB"
              % (score, c["header_len"], c["endian"],
                 c["length_includes_self"], r["n_frames"],
                 r.get("avg_len", 0)))
    best = results[0][1]

    # ★ 切帧打分只能定 length 语义，定不了 header_len。
    #   用「按该 header_len 切出的 body 有多少像结构化数据」来定。
    print("\nheader_len 判定（看 body 是否像结构化数据）：")
    best_hl, best_hit = None, -1
    for hl in (args.header_len or [0, 4, 6, 8, 12, 16]):
        cfg2 = dict(best)
        cfg2["header_len"] = hl
        frames, _ = fr.split(s.data, cfg2,
                             uplink=(s.dport in set(cfg.ports)) if cfg.ports else True)
        if not frames:
            continue
        hit = 0
        for f in frames[:200]:
            body = f.raw[hl + cfg2["length_size"]:]
            if cd.looks_structured(body):
                hit += 1
        ratio = hit / float(len(frames[:200]))
        print("  header_len=%-3d 结构化占比 %.0f%% (%d/%d)"
              % (hl, 100 * ratio, hit, len(frames[:200])))
        if ratio > best_hit:
            best_hl, best_hit = hl, ratio
    if best_hl is not None:
        best["header_len"] = best_hl
        print("  → 建议 header_len = %d（结构化占比 %.0f%%）"
              % (best_hl, 100 * max(best_hit, 0)))

    print("\n建议写入配置:")
    print(json.dumps({"frame": best}, ensure_ascii=False, indent=2))
    return 0


def cmd_codecs(args):
    cfg = Config.load(args.config)
    chain = cd.build_chain(cfg.codecs)
    streams, rows = _pick_streams(args, cfg)
    if not rows:
        print("没有流")
        return 1
    ports = set(cfg.ports)
    ok, fail = 0, 0
    examples = []
    for r in rows[:args.top]:
        s = streams[r["key"]]
        if not s.data:
            continue
        up = (s.dport in ports) if ports else True
        frames, _ = fr.split(s.data, cfg.frame, uplink=up)
        for f in frames:
            plain, name = chain.decode(f)
            if plain is None:
                fail += 1
                continue
            ok += 1
            if len(examples) < args.sample:
                examples.append((name, len(plain), plain[:100]))

    print("解码成功 %d / 失败 %d  (%.1f%%)"
          % (ok, fail, 100.0 * ok / max(ok + fail, 1)))
    print("各 codec 命中:")
    for n, c in chain.stats.items():
        if c:
            print("  %-8s %d" % (n, c))
    if examples:
        print("\n样例:")
        for name, ln, head in examples:
            print("  [%s] %dB  %r" % (name, ln, head[:80]))
    return 0


def cmd_export(args):
    print("export 需要先把响应载荷解析成表（见 examples/dump_tables.py）")
    return 0


# ================================================================== 入口
def build_parser():
    p = argparse.ArgumentParser(
        prog="src.cli", description="游戏协议逆向分析框架（通用版）")
    p.add_argument("--version", action="version", version="1.0.0")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("pcap", help="pcap / pcapng 文件")
        sp.add_argument("--config", "-c", help="配置文件（private.json）")
        sp.add_argument("--port", "-p", type=int, action="append",
                        help="端口白名单，可多次指定")
        sp.add_argument("--top", type=int, default=10, help="只看前 N 条流")
        sp.add_argument("--stream", help="指定流 src:sport-dst:dport")

    s = sub.add_parser("stats", help="pcap 概要")
    s.add_argument("pcap")
    s.add_argument("--config", "-c")
    s.set_defaults(func=cmd_stats)

    s = sub.add_parser("pcap-streams", help="TCP 流清单")
    add_common(s)
    s.add_argument("--dump", help="把最大流导出到文件")
    s.set_defaults(func=cmd_pcap_streams)

    s = sub.add_parser("pcap-frames", help="切帧统计")
    add_common(s)
    s.add_argument("--sample", type=int, default=3, help="每流打印几个帧头")
    s.add_argument("--auto", action="store_true", help="自动探测布局")
    s.add_argument("--direction", choices=("up", "down"), default="up")
    s.set_defaults(func=cmd_pcap_frames)

    s = sub.add_parser("probe", help="自动探测帧布局")
    add_common(s)
    s.add_argument("--header-len", type=int, action="append",
                   help="候选 header_len，可多次指定")
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("codecs", help="运行编码探测链")
    add_common(s)
    s.add_argument("--sample", type=int, default=5)
    s.set_defaults(func=cmd_codecs)

    s = sub.add_parser("export", help="导出表")
    s.add_argument("pcap")
    s.add_argument("--config", "-c")
    s.set_defaults(func=cmd_export)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except ConfigError as e:
        print("配置错误: %s" % e, file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print("文件不存在: %s" % e, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
