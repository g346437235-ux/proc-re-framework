"""游戏协议逆向分析框架 —— 核心包

设计目标：
  * 零第三方依赖（仅标准库）
  * 所有游戏相关常量走外部 JSON，不写死在代码里
  * 每层可单独使用：只想重组就 import stream，只想切帧就 import frame
"""

__version__ = "1.0.0"
__all__ = ["config", "stream", "frame", "codec", "tables"]
