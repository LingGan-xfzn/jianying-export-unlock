# 剪映导出限制解除器

一个独立的 Windows 小工具，用于让剪映专业版在导出时不再拦截已使用的会员功能（例如「人声&背景音分离」）。

不注入、不修改客户端文件、不联网。只通过系统接口读写剪映进程的内存。

## 背景

剪映的会员功能（音频分离、AI 相关、部分素材）在时间线上是可以直接预览和使用的，但导出时会被拦成「**开通会员并导出**」。

本工具在内存里把那个拦截标志清零，让你点原来的导出按钮就能正常出片。

## 原理

剪映的导出面板由 `VECreator.dll` 里的 Qt QML 模块渲染，数据由 C++ ViewModel 驱动。

- 目标类：`ExportVipRightsViewModel`（导出权益模型）
- 拦截标记：对象 `+0x18` 处的布尔字段（原值 `01`，清零即放行）
- 定位方式：扫描堆，找首 8 字节等于 `模块基址 + 虚表RVA` 的对象

虚表 RVA 通过解析 PE 的 MSVC RTTI（TypeDescriptor → Complete Object Locator → vtable）得到。

### 支持版本

| 剪映版本 | `ExportVipRightsViewModel` 虚表 RVA |
|---|---|
| 11.8.0.14778 | `0xE8BBED0` |
| 11.7.0.14652 | `0xE0A19A0` |
| 11.6.0.14552 | `0xD3485C0` |

程序内置全部偏移，扫描时一次遍历同时匹配，装哪个版本都能用。

## 使用

1. 打开剪映，载入项目
2. 点右上角【导出】，把导出面板打开
3. 运行 `JianyingUnlock_clean.exe`
4. 点【解除限制】，等待进度条走完
5. 回到剪映，点导出按钮 —— 正常导出

**每次打开导出面板都要重新点一次**：面板重建时对象会重新创建，标志恢复原值。

## 构建

需要 Python 3.12 与 PyInstaller：

```bash
pip install pyinstaller pillow
python -m PyInstaller --onefile --noconsole --icon app.ico ^
  --add-data "app.ico;." ^
  --add-binary "path/to/vcruntime140.dll;." ^
  --add-binary "path/to/vcruntime140_1.dll;." ^
  --name JianyingUnlock_clean jy_unlock_clean.py
```

也可以直接运行源码：

```bash
python jy_unlock_clean.py          # 图形界面
python jy_unlock_clean.py --cli    # 命令行，结果写入 unlock_log.txt
```

## 目录

| 文件 | 说明 |
|---|---|
| `jy_unlock_clean.py` | 主程序（图形界面 + 命令行） |
| `tools/jy_mem.py` | 进程内存读写封装（Win32 API） |
| `tools/jyfix.py` | 对象定位与探测 |
| `tools/snapdiff.py` | 内存快照差分（用于定位字段偏移） |
| `tools/scan.py` | 字符串/特征扫描 |
| `app.ico` | 图标 |
| `使用说明.md` | 中文使用说明 |
| `可行性报告.md` | 前期可行性分析 |
| `第二阶段报告.md` | 深入分析（导出闸门定位过程） |

## 已知限制

- 剪映大版本更新会重排代码，虚表偏移失效，程序会提示「未找到权益模型实例」，需要重新解析 RTTI
- 只影响当前会话，重启剪映即恢复
- 纯用户态实现，不涉及驱动

## 免责声明

本项目仅供技术研究与个人学习使用，用于理解 Qt/QML 应用的内存结构与授权判断机制。

请在遵守软件许可协议的前提下使用。因使用本工具产生的一切后果由使用者自行承担。