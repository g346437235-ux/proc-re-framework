# -*- coding: utf-8 -*-
"""生成 demo pcap（用于验证框架自身）

不依赖任何真实游戏，纯造数据：
    demo_plain.pcap  明文 JSON 帧
    demo_codec.pcap  zlib / raw-deflate@6 / 单字节异或 三类混合

用法：
    python examples/make_demo_pcap.py
    python examples/make_demo_pcap.py --out ./demo

生成后可直接验证：
    python -m src.cli stats        demo/demo_plain.pcap
    python -m src.cli probe        demo/demo_plain.pcap --port 12345
    python -m src.cli pcap-frames  demo/demo_plain.pcap --config demo/demo.json
    python -m src.cli codecs       demo/demo_codec.pcap --config demo/demo.json
"""

import argparse
import json
import os
import socket
import struct
import sys
import zlib

SRC, DST = "10.0.0.2", "1.2.3.4"
SPORT, DPORT = 51234, 12345
HDR_LEN = 8          # 长度字段之外的头字节数（见 demo.json）


def _ip4(s):
    return socket.inet_aton(s)


def _tcp_pkt(seq, data):
    tcp = struct.pack(">HHIIBBHHH", SPORT, DPORT, seq, 0,
                      (5 << 4), 0x18, 65535, 0, 0) + data
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     _ip4(SRC), _ip4(DST))
    return ip + tcp


def _eth(payload):
    return (b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" +
            b"\x08\x00" + payload)


def _write_pcap(path, stream, seq0=1000, chunk=200):
    pkts = [_tcp_pkt(seq0 + o, stream[o:o + chunk])
            for o in range(0, len(stream), chunk)]
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        t = 1700000000
        for i, p in enumerate(pkts):
            raw = _eth(p)
            f.write(struct.pack("<IIII", t, i, len(raw), len(raw)))
            f.write(raw)
    return len(pkts), len(stream)


def build_plain():
    """明文 JSON 帧：[len:4][cmd:4][idx:4][json]"""
    stream = b""
    for i in range(40):
        body = json.dumps({"i": i, "v": "x" * (2 + i % 19)}).encode()
        total = 4 + HDR_LEN + len(body)
        stream += struct.pack(">iii", total, 10, i) + body
    return stream


def build_codec():
    """混合编码：zlib / raw-deflate@6 / 单字节异或"""
    stream = b""
    key = 0x5B ^ ord("{")
    for i in range(12):
        kind = i % 3
        obj = json.dumps({"i": i, "kind": kind}).encode()
        if kind == 0:
            body = zlib.compress(obj)
        elif kind == 1:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            body = b"\x00" * 6 + co.compress(obj) + co.flush()
        else:
            body = bytes(b ^ key for b in obj)
        total = 4 + HDR_LEN + len(body)
        stream += struct.pack(">iii", total, 20, i) + body
    return stream


DEMO_CFG = {
    "ports": [DPORT],
    "frame": {
        "header_len": HDR_LEN,
        "length_offset": 0,
        "length_size": 4,
        "endian": "big",
        "length_includes_self": True,
        "min_frame_len": 5,
        "max_frame_len": 1 << 22,
    },
    "codecs": [
        {"type": "plain"},
        {"type": "gzip"},
        {"type": "zlib", "offset_scan": [0, 4]},
        {"type": "deflate", "offset_scan": [0, 4, 6, 8]},
        {"type": "xor", "key": None, "prefixes": ["[", "{"]},
        {"type": "binary"},
    ],
    "tables": {"snapshot_cmd": None, "update_cmd": None},
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="demo")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    p1 = os.path.join(args.out, "demo_plain.pcap")
    n_pkt, n_byte = _write_pcap(p1, build_plain())
    print("%-28s %d 包 %d 字节流 40 帧(明文)" % (p1, n_pkt, n_byte))

    p2 = os.path.join(args.out, "demo_codec.pcap")
    n_pkt, n_byte = _write_pcap(p2, build_codec(), seq0=2000, chunk=150)
    print("%-28s %d 包 %d 字节流 12 帧(混合编码)" % (p2, n_pkt, n_byte))

    p3 = os.path.join(args.out, "demo.json")
    with open(p3, "w", encoding="utf-8") as f:
        json.dump(DEMO_CFG, f, ensure_ascii=False, indent=1)
    print("%-28s 配置（header_len=%d）" % (p3, HDR_LEN))

    print("\n验证命令：")
    print("  python -m src.cli stats       %s" % p1)
    print("  python -m src.cli probe       %s --port %d" % (p1, DPORT))
    print("  python -m src.cli pcap-frames %s -c %s" % (p1, p3))
    print("  python -m src.cli codecs      %s -c %s" % (p2, p3))
    return 0


if __name__ == "__main__":
    sys.exit(main())
