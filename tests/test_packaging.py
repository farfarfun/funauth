"""打包相关的约束。"""

from __future__ import annotations

from pathlib import Path

import funauth


def test_package_ships_py_typed() -> None:
    """按 PEP 561，没有这个标记文件，下游的 mypy / pyright 看不到本包的**任何**
    类型标注 —— 全部退化成 `Any`。

    本包代码里标注写得很全，漏掉这个文件等于白写。它是个空文件，容易在重构目录
    结构时被顺手删掉或漏拷，所以钉一条测试。
    """
    marker = Path(funauth.__file__).parent / "py.typed"
    assert marker.is_file(), "缺 py.typed，下游拿不到本包的类型标注"
