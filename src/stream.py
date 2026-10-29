# -*- coding: utf-8 -*-
"""TCP 流重组

从 pcap 里按 (src, sport, dst, dport) 归并 TCP 流，按 seq 重排、去重传、记空洞。

只依赖标准库。支持：
  * pcap（us / ns 精度、大小端）
  * pcapng（最小实现，仅 Ethernet）
  * 链路层：Ethernet / Linux SLL / Raw IP
  * IPv4 / IPv6
  * TCP（无分片重组，游戏流量基本不会 IP 分片）

用法：
    from src.stream import collect_streams
    streams = collect_streams('cap.pcap', ports=[12345])
    for key, s in streams.items():
        print(key, len(s.data), s.gaps)
"""

import struct
from dataclasses import dataclass, field

# ---------------------------------------------------------------- 链路层类型
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


@dataclass
class Stream:
    key: tuple
    data: bytes = b""
    nseg: int = 0
    gaps: int = 0
    dup: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn_seen: bool = False

    @property
    def src(self):
        return self.key[0]

    @property
    def sport(self):
        return self.key[1]

    @property
    def dst(self):
        return self.key[2]

    @property
    def dport(self):
        return self.key[3]

    @property
    def reliable(self):
        """重组是否可信：无空洞即可信"""
        return self.gaps == 0

    def is_uplink(self, ports):
        """目的端口在 ports 里 = 客户端 → 服务端"""
        return self.dport in ports

    def __repr__(self):
        return "<Stream %s:%s -> %s:%s %dB segs=%d gaps=%d>" % (
            self.src, self.sport, self.dst, self.dport,
            len(self.data), self.nseg, self.gaps)


# ================================================================== pcap 读取
def read_pcap(path):
    """流式读出 [(ts, linktype, raw_packet), ...] 的生成器

    自动识别：
      * 经典 pcap（LE/BE，us/ns）
      * pcapng（SHB/EPB/SPB，仅取 Ethernet）
    """
    with open(path, "rb") as f:
        magic = f.read(4)

        # ---------------- pcapng ----------------
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(f)
            return

        # ---------------- 经典 pcap ----------------
        table = {
            b"\xd4\xc3\xb2\xa1": ("<", False),
            b"\xa1\xb2\xc3\xd4": (">", False),
            b"\x4d\x3c\xb2\xa1": ("<", True),
            b"\xa1\xb2\x3c\x4d": (">", True),
        }
        if magic not in table:
            raise ValueError("未知 pcap 魔数: %r" % magic)
        endian, nano = table[magic]

        hdr = f.read(20)                     # 版本(4)+thiszone(4)+sigfigs(4)+snaplen(4)+network(4)
        if len(hdr) < 20:
            return
        network = struct.unpack_from(endian + "I", hdr, 16)[0]
        rec_hdr = 16
        if nano:
            ts_scale = 1e-9
        else:
            ts_scale = 1e-6

        while True:
            rh = f.read(rec_hdr)
            if len(rh) < rec_hdr:
                break
            ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rh)
            if incl <= 0:
                continue
            data = f.read(incl)
            if len(data) < incl:
                break
            yield (ts_sec + ts_frac * ts_scale, network, data)


def _read_pcapng(f):
    """最小 pcapng 实现：解析 SHB 拿 linktype，EPB 拿包"""
    endian = "<"
    linktype = LINKTYPE_ETHERNET
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            break
        btype, blen = struct.unpack_from(endian + "II", hdr, 0)
        if btype == 0x0A0D0D0A:              # SHB：用它的 BOM 定端序
            bom = f.read(4)
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            rest = f.read(blen - 12)
            if len(rest) >= 4:
                # 剩余：major(2) minor(2) section_len(8) ... opt
                try:
                    linktype = struct.unpack_from(endian + "I", rest, 0)[0]
                except struct.error:
                    linktype = LINKTYPE_ETHERNET
            continue
        if blen < 12 or blen > (1 << 24):
            break
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            break
        if btype == 0x06:                    # EPB
            if len(body) < 20:
                continue
            iface, ts_hi, ts_lo, cap, _orig = struct.unpack_from(
                endian + "IIIII", body, 0)
            ts = ((ts_hi << 32) | ts_lo) / 1e6
            pkt = body[20:20 + cap]
            if pkt:
                yield (ts, linktype, pkt)
        # 其他块（IDB/NRB/ISB）忽略


# ================================================================== 解包
def _parse_link(linktype, raw):
    """剥链路层，返回 (ethertype, payload)"""
    if linktype == LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return None, b""
        et = struct.unpack_from(">H", raw, 12)[0]
        off = 14
        # 802.1Q VLAN
        while et in (0x8100, 0x88A8) and len(raw) >= off + 4:
            et = struct.unpack_from(">H", raw, off + 2)[0]
            off += 4
        return et, raw[off:]

    if linktype == LINKTYPE_LINUX_SLL:
        if len(raw) < 16:
            return None, b""
        et = struct.unpack_from(">H", raw, 14)[0]
        return et, raw[16:]

    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LOOP,
                    LINKTYPE_NULL):
        if not raw:
            return None, b""
        ver = raw[0] >> 4
        return (ETHERTYPE_IPV4 if ver == 4 else
                ETHERTYPE_IPV6 if ver == 6 else None), raw

    return None, raw


def _parse_ipv4(pkt):
    """返回 (proto, src, dst, payload) 或 None"""
    if len(pkt) < 20:
        return None
    ver = pkt[0] >> 4
    ihl = (pkt[0] & 0x0F) * 4
    if ver != 4 or ihl < 20 or len(pkt) < ihl:
        return None
    proto = pkt[9]
    total_len = struct.unpack_from(">H", pkt, 2)[0]
    src = ".".join(str(b) for b in pkt[12:16])
    dst = ".".join(str(b) for b in pkt[16:20])
    end = min(total_len, len(pkt)) if total_len else len(pkt)
    return proto, src, dst, pkt[ihl:end]


def _parse_ipv6(pkt):
    if len(pkt) < 40:
        return None
    if pkt[0] >> 4 != 6:
        return None
    nxt = pkt[6]
    plen = struct.unpack_from(">H", pkt, 4)[0]
    src = _fmt_ipv6(pkt[8:24])
    dst = _fmt_ipv6(pkt[24:40])
    return nxt, src, dst, pkt[40:40 + plen]


def _fmt_ipv6(b):
    parts = ["%02x%02x" % (b[i], b[i + 1]) for i in range(0, 16, 2)]
    return ":".join(parts)


def _parse_tcp(payload):
    """返回 (sport, dport, seq, flags, data) 或 None"""
    if len(payload) < 20:
        return None
    sport, dport, seq = struct.unpack_from(">HHI", payload, 0)
    doff = (payload[12] >> 4) * 4
    if doff < 20 or len(payload) < doff:
        return None
    flags = payload[13]
    return sport, dport, seq, flags, payload[doff:]


def parse_packet(linktype, raw):
    """剥到 TCP：返回 (src, sport, dst, dport, seq, flags, data) 或 None"""
    et, body = _parse_link(linktype, raw)
    if et == ETHERTYPE_IPV4:
        r = _parse_ipv4(body)
    elif et == ETHERTYPE_IPV6:
        r = _parse_ipv6(body)
    else:
        return None
    if not r:
        return None
    proto, src, dst, payload = r
    if proto != 6:                            # 只要 TCP
        return None
    t = _parse_tcp(payload)
    if not t:
        return None
    sport, dport, seq, flags, data = t
    return src, sport, dst, dport, seq, flags, data


# ================================================================== 流重组
def collect_streams(path, ports=(), keep_all=False):
    """按 (src,sport,dst,dport) 重组 TCP 流

    ports       : 端口白名单；空表示全部保留
    keep_all    : True 时保留没有 payload 的流（便于看握手）

    返回 dict[key] = Stream
    """
    ports = set(int(p) for p in (ports or ()))
    segs = {}

    for ts, linktype, raw in read_pcap(path):
        p = parse_packet(linktype, raw)
        if not p:
            continue
        src, sport, dst, dport, seq, flags, data = p
        if ports and sport not in ports and dport not in ports:
            continue
        if not data and not keep_all and not (flags & TCP_SYN):
            continue
        key = (src, sport, dst, dport)
        segs.setdefault(key, []).append((ts, seq, flags, data))

    streams = {}
    for key, lst in segs.items():
        streams[key] = _reassemble(key, lst)
    return streams


def _reassemble(key, lst):
    """按 seq 排序拼接，处理重传与空洞"""
    lst.sort(key=lambda x: x[0])              # 按时间
    st = Stream(key=key,
                first_ts=lst[0][0] if lst else 0.0,
                last_ts=lst[-1][0] if lst else 0.0,
                nseg=len(lst))

    # 找起始 seq：优先 SYN 的 seq+1，否则取第一个带 payload 的
    base = None
    for ts, seq, flags, data in lst:
        if flags & TCP_SYN:
            base = (seq + 1) & 0xFFFFFFFF
            st.syn_seen = True
            break
    if base is None:
        for ts, seq, flags, data in lst:
            if data:
                base = seq
                break
    if base is None:
        st.data = b""
        return st

    # 收集 (相对偏移, payload)，用 dict 去重
    chunks = {}
    for ts, seq, flags, data in lst:
        if not data:
            continue
        rel = (seq - base) & 0xFFFFFFFF
        # 回绕处理：偏移过大视为乱序/异常
        if rel > (1 << 31):
            continue
        if rel in chunks:
            st.dup += 1
            continue
        chunks[rel] = data

    if not chunks:
        st.data = b""
        return st

    buf = bytearray()
    next_off = 0
    for off in sorted(chunks):
        if off > next_off:
            st.gaps += 1                      # 中间有洞
            buf.extend(b"\x00" * (off - next_off))
        elif off < next_off:
            # 与已写入部分重叠：只补新字节
            overlap = next_off - off
            payload = chunks[off]
            if overlap >= len(payload):
                st.dup += 1
                continue
            chunks[off] = payload[overlap:]
            off = next_off
        payload = chunks[off]
        buf.extend(payload)
        next_off = off + len(payload)

    st.data = bytes(buf)
    return st


# ================================================================== 便捷函数
def summary(streams, ports=()):
    """生成 [(key, direction, nbytes, segs, gaps), ...] 按流量降序"""
    ports = set(int(p) for p in (ports or ()))
    rows = []
    for key, s in streams.items():
        up = (s.dport in ports) if ports else None
        rows.append({
            "key": key,
            "src": "%s:%s" % (s.src, s.sport),
            "dst": "%s:%s" % (s.dst, s.dport),
            "direction": "up" if up else ("down" if up is False else "?"),
            "bytes": len(s.data),
            "segs": s.nseg,
            "gaps": s.gaps,
            "dup": s.dup,
            "reliable": s.reliable,
        })
    rows.sort(key=lambda r: -r["bytes"])
    return rows


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    streams = collect_streams(sys.argv[1])
    for r in summary(streams):
        print("%-22s -> %-22s %8dB segs=%-4d gaps=%-2d dup=%-3d %s" % (
            r["src"], r["dst"], r["bytes"], r["segs"], r["gaps"], r["dup"],
            "OK" if r["reliable"] else "HOLE"))
