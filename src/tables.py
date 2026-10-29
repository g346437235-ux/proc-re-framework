# -*- coding: utf-8 -*-
"""schema 感知的表存储

游戏协议里的"表"通常长这样：

    ["demo_table,col_a,col_b,col_c", [row1...], [row2...]]

或者

    [["demo_table", [cols], [rows]], ...]

本模块做三件事：
  1. 从响应里识别出「列名 + 行」并建成表
  2. 维护「快照层 + 增量叠加层」
  3. 提供按列名的查询

★ 核心设计：快照与增量必须分层
    snapshot = 登录那一刻的基线（永不变）
    overlay  = 之后的每个 patch
    get()    = 两者合并后的实时视图

用法：
    from src.tables import TableStore
    st = TableStore()
    st.load_from_response(login_payload)     # 或 st.load_table(name, cols, rows)
    st.apply_update(table, payload)          # 增量
    rows = st.get('demo_table')
"""

import csv
import io
import json


# ================================================================== 单表
class Table:
    def __init__(self, name, columns):
        self.name = name
        self.columns = list(columns or [])
        self.key = self.columns[0] if self.columns else None
        self._snap = {}        # key -> dict
        self._order = []
        self._overlay = {}     # key -> {col: val}
        self.n_update = 0

    # ---- 写入 ----
    def load_rows(self, rows, replace=True):
        if replace:
            self._snap.clear()
            self._order.clear()
        for r in rows:
            d = self._as_dict(r)
            if d is None:
                continue
            k = d.get(self.key)
            if k not in self._snap:
                self._order.append(k)
            self._snap[k] = d

    def _as_dict(self, r):
        if isinstance(r, dict):
            return dict(r)
        if isinstance(r, (list, tuple)):
            return {c: (r[i] if i < len(r) else None)
                    for i, c in enumerate(self.columns)}
        return None

    def insert(self, row):
        d = self._as_dict(row)
        if d is None:
            return False
        k = d.get(self.key)
        if k is None:
            return False
        if k not in self._snap:
            self._order.append(k)
        self._snap[k] = d
        return True

    def update_by_index(self, key, pairs):
        """pairs = [col_idx, value, col_idx, value, ...]（协议里的紧凑格式）"""
        patch = {}
        for i in range(0, len(pairs) - 1, 2):
            idx, val = pairs[i], pairs[i + 1]
            if isinstance(idx, int) and 0 <= idx < len(self.columns):
                patch[self.columns[idx]] = val
        if not patch:
            return 0
        tgt = self._overlay.setdefault(key, {})
        tgt.update(patch)
        self.n_update += 1
        return len(patch)

    def update_by_name(self, key, patch):
        tgt = self._overlay.setdefault(key, {})
        tgt.update(patch or {})
        self.n_update += 1
        return len(patch or {})

    def delete(self, key):
        self._snap.pop(key, None)
        self._overlay.pop(key, None)
        return True

    # ---- 读取 ----
    def _merged(self, k):
        base = self._snap.get(k)
        ov = self._overlay.get(k)
        if base is None and ov is None:
            return None
        d = dict(base or {})
        d.setdefault(self.key, k)
        if ov:
            d.update(ov)
        return d

    def get(self):
        out = []
        for k in self._order:
            d = self._merged(k)
            if d is not None:
                out.append(d)
        # 只在 overlay 里出现的新行
        for k in self._overlay:
            if k not in self._snap:
                d = self._merged(k)
                if d is not None:
                    out.append(d)
        return out

    def one(self, key=None):
        if key is None:
            rows = self.get()
            return rows[0] if rows else None
        return self._merged(key)

    def find(self, **kw):
        return [r for r in self.get()
                if all(r.get(k) == v for k, v in kw.items())]

    def diff(self):
        """只看增量部分"""
        return {k: dict(v) for k, v in self._overlay.items()}

    def __len__(self):
        return len(self.get())

    def __repr__(self):
        return "<Table %s cols=%d rows=%d upd=%d>" % (
            self.name, len(self.columns), len(self), self.n_update)


# ================================================================== 多表
class TableStore:
    def __init__(self):
        self.tables = {}
        self.dropped = []      # 解析失败的表，便于排查

    # ---- 建表 ----
    def ensure(self, name, columns):
        t = self.tables.get(name)
        if t is None or (columns and not t.columns):
            t = Table(name, columns)
            self.tables[name] = t
        return t

    def load_table(self, name, columns, rows, replace=True):
        t = self.ensure(name, columns)
        if columns:
            t.columns = list(columns)
            t.key = t.columns[0] if t.columns else None
        t.load_rows(rows, replace=replace)
        return t

    # ---- 自动识别响应结构 ----
    def load_from_response(self, payload, replace=True):
        """尽量从各种响应形状里抽出表

        支持四种常见形状：

          A) 扁平：一个列表里，第 0 项是 "表名,列1,列2,…"，后面全是行
             ["demo_a,owner_id,level", [1,10], [2,20], ...]

          B) 嵌套：每一项自己是 [表头, 行, 行, ...]
             [["demo_a,owner_id,level", [1,10], [2,20]],
              ["demo_b,id,name",    [7,"a"]]]

          C) 带列数组：[["demo_a", ["owner_id","level"], [[1,10],[2,20]]]]

          D) 字典：{"demo_a": [{...}, {...}]}
        """
        n = 0
        if isinstance(payload, dict):
            for k, v in payload.items():
                if isinstance(v, list) and v:
                    self._load_dict_rows(k, v, replace)
                    n += 1
                elif isinstance(v, dict) and v and isinstance(
                        next(iter(v.values())), dict):
                    self.load_table(k, list(next(iter(v.values())).keys()),
                                    list(v.values()), replace)
                    n += 1
            return n
        if not isinstance(payload, list) or not payload:
            return 0

        # ---- A 扁平 ----
        head = payload[0]
        if isinstance(head, str) and "," in head:
            name, cols = self._split_header(head)
            rows = [x for x in payload[1:] if isinstance(x, (list, dict))]
            if rows:
                self.load_table(name, cols, rows, replace)
                return 1

        # ---- B / C 嵌套 ----
        for item in payload:
            if not isinstance(item, list) or not item:
                continue
            h = item[0]
            if isinstance(h, str) and "," in h:
                name, cols = self._split_header(h)
                rows = [x for x in item[1:] if isinstance(x, (list, dict))]
                self.load_table(name, cols, rows, replace)
                n += 1
            elif isinstance(h, str) and len(item) >= 3 and isinstance(item[1], list) \
                    and all(isinstance(c, str) for c in item[1]):
                # C: [name, cols, rows]
                name, cols = h, [str(c) for c in item[1]]
                rows = item[2] if isinstance(item[2], list) else []
                if rows and isinstance(rows[0], list):
                    self.load_table(name, cols, rows, replace)
                else:
                    self.load_table(name, cols, [rows, *(item[3:] or [])], replace)
                n += 1
        return n

    @staticmethod
    def _split_header(head):
        """'demo_a,owner_id,level' → ('demo_a', ['owner_id','level'])"""
        parts = [p.strip() for p in head.split(",") if p.strip()]
        return (parts[0], parts[1:]) if parts else ("?", [])

    def _load_dict_rows(self, name, rows, replace):
        first = rows[0]
        if isinstance(first, dict):
            self.load_table(name, list(first.keys()), rows, replace)
        elif isinstance(first, list) and len(first) == 0:
            self._dropped(name, "空行无法推断列名")
        else:
            self._dropped(name, "dict 模式的表缺少列名，请用 load_table 显式指定")

    def _dropped(self, name, why):
        self.dropped.append((name, why))

    # ---- 增量 ----
    def apply_update(self, table, payload):
        """协议里的 DELTA_UPDATE 载荷

        safe 解析：
          [op, table, ...] 由上层拆好
          payload 在这里是 op 之后的部分
        """
        t = self.tables.get(table)
        if t is None:
            self._dropped(table, "update 时表不存在")
            return 0
        if not isinstance(payload, (list, tuple)):
            return 0
        if len(payload) == 1:
            return 1 if t.delete(payload[0]) else 0
        # 约定：[ignore, key, idx, val, idx, val, ...]
        if len(payload) >= 2:
            key = payload[1]
            return t.update_by_index(key, list(payload[2:]))
        return 0

    # ---- 读取 ----
    def get(self, name):
        t = self.tables.get(name)
        return t.get() if t else []

    def one(self, name, key=None):
        t = self.tables.get(name)
        return t.one(key) if t else None

    def names(self):
        return sorted(self.tables)

    def sizes(self):
        return {n: len(t) for n, t in sorted(self.tables.items())}

    def nonempty(self):
        return {n: len(t) for n, t in self.tables.items() if len(t)}

    # ---- 导出 ----
    def to_csv(self, name, path):
        rows = self.get(name)
        if not rows:
            return 0
        cols = list(rows[0].keys())
        with io.open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for r in rows:
                w.writerow({c: r.get(c) for c in cols})
        return len(rows)

    def to_json(self, path, names=None):
        data = {n: self.get(n) for n in (names or self.names())}
        with io.open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        return len(data)

    def __repr__(self):
        return "<TableStore tables=%d rows=%d>" % (
            len(self.tables), sum(len(t) for t in self.tables.values()))


if __name__ == "__main__":
    st = TableStore()
    st.load_table("demo_users", ["owner_id", "name", "level"],
                  [[1, "a", 10], [2, "b", 20]])
    print(st, st.get("demo_users"))
    st.apply_update("demo_users", [0, 1, 2, 99])     # 改 owner_id=1 的第 2 列
    print("after update:", st.one("demo_users", 1))
