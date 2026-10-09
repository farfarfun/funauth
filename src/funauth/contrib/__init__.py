"""各 web 框架的现成适配。

每个子模块的依赖都在对应的 extra 里，**不进主依赖** —— 纯 CLI 或后台任务的
宿主不该因为装了 funauth 就被拖进一个 web 框架。

- `funauth.contrib.fastapi`：`pip install "funauth[fastapi]"`
"""
