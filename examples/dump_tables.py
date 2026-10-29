# -*- coding: utf-8 -*-
"""示例 2：把协议里的「表」导出成 CSV

演示 table store 的用法：
    1 手工建表
    2 从响应载荷自动识别
    3 应用增量（快照 + overlay 双层模型）
    4 导出

运行：
    python examples/dump_tables.py            # 跑内置 demo
    python examples/dump_tables.py --out ./out
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tables import TableStore        # noqa: E402


DEMO_SNAPSHOT = [
    "demo_users,owner_id,entity_id,level,amount",
    [1001, 10001, 20, 5000],
    [1002, 10002, 15, 3000],
    [1003, 10003, 30, 9000],
]

DEMO_UPDATES = [
    # [op, table, payload]
    # op=1 insert, op=2 update, op=3 delete
    [1, "demo_users", [1004, 10004, 5, 800]],
    [2, "demo_users", [0, 1001, 3, 7777]],          # 改 index=3 列（amount）
    [3, "demo_users", [1002]],                       # 删
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="./out")
    ap.add_argument("--json", action="store_true", help="同时导出 JSON")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    st = TableStore()

    # ---------- 1 自动识别 ----------
    print("[1] 从响应载荷识别表")
    n = st.load_from_response(DEMO_SNAPSHOT)
    print("  识别到 %d 个表: %s" % (n, st.sizes()))

    # ---------- 2 应用增量 ----------
    print("\n[2] 应用增量")
    for op, table, payload in DEMO_UPDATES:
        if op == 1:
            st.tables[table].insert(payload) if table in st.tables else None
            print("  insert %s %s" % (table, payload))
        elif op == 2:
            k = st.apply_update(table, payload)
            print("  update %s -> %d 列" % (table, k))
        elif op == 3:
            st.tables[table].delete(payload[0])
            print("  delete %s key=%s" % (table, payload[0]))

    # ---------- 3 查看 ----------
    print("\n[3] 当前视图")
    for row in st.get("demo_users"):
        print("  ", row)

    # ---------- 4 导出 ----------
    print("\n[4] 导出")
    for name in st.names():
        p = os.path.join(args.out, name + ".csv")
        cnt = st.to_csv(name, p)
        print("  %-24s %d 行 -> %s" % (name, cnt, p))
    if args.json:
        p = os.path.join(args.out, "tables.json")
        st.to_json(p)
        print("  tables.json -> %s" % p)

    print("\n完成。真实使用时：")
    print("  st.load_from_response(登录响应的载荷)")
    print("  for op, table, payload in 增量消息: st.apply_update(...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
