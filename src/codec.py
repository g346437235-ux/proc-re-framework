# -*- coding: utf-8 -*-
"""编码探测链

真实游戏的载荷编码通常是混合的：
  * 有的帧是明文 JSON
  * 有的是压缩（zlib / raw deflate / gzip）
  * 有的是单字节异或
  * 有的是二进制（protobuf）

本模块用**策略链**处理：每个 codec 先 probe，命中就 decode，
第一个成功解出结构化数据的胜出。

设计要点：
  * 不含任何游戏密钥；XorCodec 的 key 由配置提供或运行时用已知明文猜
  * 所有"像不像结构化数据"的判断收敛到 looks_structured()
  * 允许注册自定义 codec（继承 Codec 即可）

用法：
    from src.codec import build_chain, looks_structured
    chain = build_chain(cfg.codecs)
    plain = chain.decode(frame)
"""

import json
import re
import zlib
from abc import ABC, abstractmethod


# ================================================================== 结构化判定
_JSON_PREFIX = (b"[", b"{", b'"')
_DIGIT_PREFIX = re.compile(rb"^-?\d")


def looks_structured(b, min_len=2):
    """判断一段字节像不像"结构化数据"

    这函数是整套编码探测的裁判，必须严格：
      * 合法 JSON（数组/对象/字符串/数字）
      * 或者明显是 UTF-8 的 JSON 片段
    宽松判定会引入大量误报。
    """
    if not isinstance(b, (bytes, bytearray)) or len(b) < min_len:
        return False
    b = bytes(b)
    try:
        txt = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    s = txt.strip()
    if not s:
        return False
    if s[0] not in "[{":
        # 纯数字/字符串也可能是合法标量，但游戏协议基本不用
        return False
    try:
        json.loads(s)
        return True
    except Exception:
        pass
    # 允许"截断的 JSON 数组"（流中间开始的情况）
    if s[0] == "[" and s.count("[") >= 1 and len(s) > 8:
        return s.count('"') >= 2          # 至少有引号，说明是结构化而非随机
    return False


def entropy(b):
    if not b:
        return 0.0
    from collections import Counter
    import math
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


# ================================================================== 基类
class Codec(ABC):
    """编解码器基类

    probe(frame)  : 快速判断「这帧归我管吗」，应尽量 O(1)
    decode(frame) : 返回明文 bytes，失败返回 None
    """

    name = "base"
    priority = 50          # 越小越先试

    def __init__(self, **opts):
        self.opts = opts

    @abstractmethod
    def probe(self, frame): ...

    @abstractmethod
    def decode(self, frame): ...

    def encode(self, obj):
        raise NotImplementedError("%s 不支持编码" % self.name)

    def __repr__(self):
        return "<%s>" % self.name


# ================================================================== 具体实现
class PlainCodec(Codec):
    """明文：body 就是 JSON"""

    name = "plain"
    priority = 10

    def probe(self, frame):
        body = getattr(frame, "body", b"")
        return looks_structured(body)

    def decode(self, frame):
        body = getattr(frame, "body", b"")
        return body if looks_structured(body) else None

    def encode(self, obj):
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class GzipCodec(Codec):
    name = "gzip"
    priority = 20

    def probe(self, frame):
        body = getattr(frame, "body", b"")
        return body[:2] == b"\x1f\x8b"

    def decode(self, frame):
        body = getattr(frame, "body", b"")
        try:
            return zlib.decompress(body, 16 + 15)
        except Exception:
            return None


class ZlibCodec(Codec):
    """zlib 容器：78 9C / 78 01 / 78 DA / 78 5E"""

    name = "zlib"
    priority = 30
    MAGIC = (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e")

    def probe(self, frame):
        body = getattr(frame, "body", b"")
        return body[:2] in self.MAGIC

    def decode(self, frame):
        body = getattr(frame, "body", b"")
        for off in self.opts.get("offset_scan", [0]):
            for wbits in (15, 47, -15):
                try:
                    dec = zlib.decompress(body[off:], wbits)
                except Exception:
                    continue
                if looks_structured(dec):
                    return dec
        return None


class DeflateCodec(Codec):
    """raw deflate：没有 magic，必须在偏移空间里扫

    ★ 关键经验：真实协议常是「N 字节头 + raw deflate」，
      N 可能是 4 / 6 / 8，必须全扫一遍。
    """

    name = "deflate"
    priority = 40
    DEFAULT_OFFSETS = (0, 4, 6, 8, 5, 7, 10, 12, 16)

    def probe(self, frame):
        return len(getattr(frame, "body", b"")) > 8

    def decode(self, frame):
        body = getattr(frame, "body", b"")
        offsets = self.opts.get("offset_scan", self.DEFAULT_OFFSETS)
        for off in offsets:
            if off >= len(body):
                continue
            for wbits in (-15, 15, 47):
                try:
                    dec = zlib.decompress(body[off:], wbits)
                except Exception:
                    continue
                if looks_structured(dec):
                    return dec
        return None


class XorCodec(Codec):
    """单字节异或

    key 三种来源（按优先级）：
      1. 配置里显式给的 key
      2. 已知明文攻击：假设明文以某前缀开头，反推 key，再用整段校验
      3. 暴力 256（最慢，最后兜底）
    """

    name = "xor"
    priority = 60

    def __init__(self, key=None, prefixes=("[", "{"), brute=True, **kw):
        super().__init__(**kw)
        self.key = key
        self.prefixes = [p.encode() if isinstance(p, str) else p
                         for p in prefixes]
        self.brute = brute

    def _apply(self, body, k):
        return bytes(b ^ k for b in body)

    def probe(self, frame):
        """便宜的准入判断：只要 body 不是明文结构化数据，就值得交给 decode 试

        注意：不要用「熵 > 阈值」来筛选。异或会把 ASCII 映射成另一段 ASCII，
        熵和原文接近，高熵阈值会误杀。
        """
        body = getattr(frame, "body", b"")
        if len(body) < 4:
            return False
        if self.key is not None:
            return looks_structured(self._apply(body, self.key))
        # 已经是明文就不用异或
        return not looks_structured(body)

    def guess_key(self, body):
        """已知明文攻击：从前缀反推 key，用整段 JSON 合法性自校验"""
        if not body:
            return None
        for pref in self.prefixes:
            k = body[0] ^ pref[0]
            if looks_structured(self._apply(body, k)):
                return k
        return None

    def decode(self, frame):
        body = getattr(frame, "body", b"")
        if not body:
            return None
        # 1 配置 key
        if self.key is not None:
            dec = self._apply(body, self.key)
            return dec if looks_structured(dec) else None
        # 2 已知明文
        k = self.guess_key(body)
        if k is not None:
            return self._apply(body, k)
        # 3 暴力
        if self.brute and len(body) <= 4096:
            for k in range(256):
                dec = self._apply(body, k)
                if looks_structured(dec):
                    return dec
        return None


class BinaryCodec(Codec):
    """二进制载荷（protobuf 启发式）

    只做「判定为二进制」并原样返回，语义交给上层。
    """

    name = "binary"
    priority = 90

    def probe(self, frame):
        body = getattr(frame, "body", b"")
        if len(body) < 2:
            return False
        # protobuf: 首字节 tag，(tag & 7) 是合法 wire type
        wire = body[0] & 0x07
        return wire in (0, 1, 2, 5)

    def decode(self, frame):
        return getattr(frame, "body", b"")


# ================================================================== 链
class CodecChain:
    """按 priority 排序的编码探测链"""

    def __init__(self, codecs=None):
        self.codecs = sorted(codecs or [], key=lambda c: c.priority)
        self.stats = {c.name: 0 for c in self.codecs}

    def add(self, codec):
        self.codecs.append(codec)
        self.codecs.sort(key=lambda c: c.priority)
        self.stats.setdefault(codec.name, 0)
        return self

    def decode(self, frame):
        """返回 (plain_bytes, codec_name) 或 (None, None)"""
        for c in self.codecs:
            try:
                if not c.probe(frame):
                    continue
                dec = c.decode(frame)
            except Exception:
                continue
            if dec is not None:
                self.stats[c.name] = self.stats.get(c.name, 0) + 1
                return dec, c.name
        return None, None

    def decode_json(self, frame):
        plain, name = self.decode(frame)
        if plain is None:
            return None, name
        try:
            return json.loads(plain.decode("utf-8", "replace")), name
        except Exception:
            return None, name

    def __repr__(self):
        return "<CodecChain %s>" % [c.name for c in self.codecs]


# ================================================================== 工厂
def build_chain(specs):
    """从配置列表构造链

    specs 例：
        [{"type":"plain"},
         {"type":"zlib","offset_scan":[0,4]},
         {"type":"xor","key":null,"prefixes":["[","{"]}]
    """
    REG = {
        "plain": PlainCodec,
        "gzip": GzipCodec,
        "zlib": ZlibCodec,
        "deflate": DeflateCodec,
        "xor": XorCodec,
        "binary": BinaryCodec,
    }
    chain = CodecChain()
    for spec in specs or []:
        t = (spec or {}).get("type")
        cls = REG.get(t)
        if cls is None:
            raise ValueError("未知 codec 类型: %r（可用: %s）"
                             % (t, list(REG)))
        opts = {k: v for k, v in spec.items() if k != "type"}
        chain.add(cls(**opts))
    return chain


if __name__ == "__main__":
    print("已注册 codec:", list(("plain", "gzip", "zlib",
                                 "deflate", "xor", "binary")))
    demo = b'\x1b\x18\x1a\x1c\x0c'
    print("已知明文攻击演示: key =", XorCodec().guess_key(
        bytes(b ^ 0x5B ^ ord('[') for b in b'[1,2,3]')))
