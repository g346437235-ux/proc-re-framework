# -*- coding: utf-8 -*-
"""配置加载

所有游戏相关常量（端口、帧头布局、编码方式、命令号）都放在外部 JSON，
本模块只负责加载与校验，不含任何默认的敏感值。

用法：
    from src.config import Config
    cfg = Config.load('private.json')
    cfg.ports            # [12345]
    cfg.frame['header_len']
"""

import json
import os


class ConfigError(Exception):
    pass


DEFAULTS = {
    "ports": [],
    "frame": {
        "header_len": 0,
        "length_offset": 0,
        "length_size": 4,
        "endian": "big",
        "length_includes_self": True,
        "min_frame_len": 5,
        "max_frame_len": 1 << 22,
    },
    "codecs": [{"type": "plain"}],
    "tables": {
        "snapshot_cmd": None,
        "update_cmd": None,
    },
}


def _deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    """配置对象。所有字段都有安全默认值，缺失不会崩。"""

    def __init__(self, data=None):
        self.raw = _deep_merge(DEFAULTS, data or {})

    # ---- 加载 ----
    @classmethod
    def load(cls, path=None):
        if not path:
            return cls()
        if not os.path.exists(path):
            raise ConfigError("配置文件不存在: %s" % path)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ConfigError("配置文件 JSON 解析失败: %r" % (e,))
        return cls(data)

    @classmethod
    def from_dict(cls, data):
        return cls(data)

    # ---- 访问器 ----
    @property
    def ports(self):
        return list(self.raw.get("ports") or [])

    @property
    def frame(self):
        return dict(self.raw.get("frame") or {})

    @property
    def codecs(self):
        return list(self.raw.get("codecs") or [])

    @property
    def tables(self):
        return dict(self.raw.get("tables") or {})

    def get(self, *path, **kw):
        """cfg.get('frame', 'header_len', default=12)"""
        default = kw.get("default")
        cur = self.raw
        for p in path:
            if not isinstance(cur, dict) or p not in cur:
                return default
            cur = cur[p]
        return cur

    # ---- 校验 ----
    def validate(self):
        """返回问题列表；空列表表示配置可用于分析"""
        problems = []
        fr = self.frame
        if not self.ports:
            problems.append("ports 为空：不知道要分析哪个端口的流")
        if fr.get("header_len", 0) <= 0:
            problems.append("frame.header_len 未设置")
        if fr.get("length_size", 4) not in (1, 2, 4, 8):
            problems.append("frame.length_size 只能是 1/2/4/8")
        if fr.get("endian") not in ("big", "little"):
            problems.append("frame.endian 只能是 big/little")
        for i, c in enumerate(self.codecs):
            if "type" not in c:
                problems.append("codecs[%d] 缺 type" % i)
        return problems

    def require_valid(self):
        p = self.validate()
        if p:
            raise ConfigError("配置不完整:\n  - " + "\n  - ".join(p))

    def __repr__(self):
        return "<Config ports=%s header_len=%s codecs=%s>" % (
            self.ports, self.frame.get("header_len"),
            [c.get("type") for c in self.codecs])
