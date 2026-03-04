---
description: WSL 环境下常见坑和解决方案（基于 Z-Scope SVF 验证经验总结）
---

# WSL 环境常见坑和解决方案

## 基本命令格式

本机器 WSL 发行版为 **Ubuntu 24.04**，用户名 `zeal`。执行命令的标准格式：

```powershell
# 基本格式
wsl -d Ubuntu -e /bin/sh -c "你的命令"

# 拼接 PATH（必须，否则 ls/grep/which 等不可用）
wsl -d Ubuntu -e /bin/sh -c "export PATH=/usr/bin:/usr/local/bin:$PATH && 你的命令"

# 使用 Python 虚拟环境
wsl -d Ubuntu -e /bin/sh -c ". /home/zeal/.local/zscope_venv/bin/activate && python /mnt/c/.../script.py"

# 多行复杂命令：写成 .py 文件执行（避免引号地狱）
wsl -d Ubuntu -e /bin/sh -c ". /home/zeal/.local/zscope_venv/bin/activate && python /mnt/c/.../tmp/my_script.py 2>&1"
```

**关键工具路径**:
- clangd: `/home/zeal/.local/clangd/clangd_18.1.3/bin/clangd`
- gclang/get-bc: `/home/zeal/go/bin/`
- llvm-link: `/usr/lib/llvm-18/bin/llvm-link`
- SVF (wpa/saber): `/home/zeal/.local/svf/SVF-linux-x86_64/bin/`
- zscope venv: `/home/zeal/.local/zscope_venv/`

---

## 1. `/bin/sh` 极简环境缺少常用命令

**现象**: `ls`, `grep`, `find`, `mkdir`, `tail`, `which`, `head` 等命令全部 `not found`。

**原因**: WSL 默认的 `/bin/sh` 可能是 `dash` 而非 `bash`，且 `PATH` 非常精简，只包含 `/bin`。

**解决**:
- 使用 Python 替代 shell 命令（`pathlib`, `os.listdir`, `shutil.which` 等）
- 或在命令开头拼接 PATH: `export PATH=/usr/bin:/usr/local/bin:$PATH`
- 长脚本写成 `.py` 文件执行，避免 shell 内联

---

## 2. NTFS 文件系统 (`/mnt/c/...`) 与 Linux 原生工具不兼容

**现象**: gclang 的 `objcopy --add-section` 在 `/mnt/c/` 上静默失败，`.o` 文件虽然生成但不包含 bitcode 段。

**原因**: WSL 通过 drvfs 挂载 NTFS，不完全支持 `objcopy` 的 section 操作。

**解决**:
```python
# 检测 /mnt/ 路径，自动重定向到 Linux 原生临时目录
if str(source_root).startswith("/mnt/"):
    import tempfile
    output_dir = Path(tempfile.mkdtemp(prefix="zscope_bc_"))
```

---

## 3. `subprocess.run()` 中的 PATH 继承问题

**现象**: Python 脚本内的 `subprocess.run()` 找不到 `objcopy`、`clang-18` 等系统工具。

**原因**: `/bin/sh` 的 PATH 极简，只包含 `/bin`，不含 `/usr/bin`。`os.environ.copy()` 继承的也是这个极简 PATH。

**解决**:
```python
env = os.environ.copy()
path = env.get("PATH", "")
for d in ["/usr/bin", "/usr/local/bin", "/usr/sbin"]:
    if d not in path:
        path = d + ":" + path
env["PATH"] = path
```

---

## 4. gllvm (gclang) 需要 LLVM_COMPILER 和 LLVM_CC_NAME 环境变量

**现象**: gclang 报错 `executable file not found in $PATH: clang` 或 `clang-18`。

**原因**: gclang 依赖 `LLVM_COMPILER=clang` 知道使用 clang 家族，`LLVM_CC_NAME=clang-18` 指定带版本号的二进制。

**解决**: 自动检测:
```python
env["LLVM_COMPILER"] = "clang"
for v in range(20, 14, -1):
    if shutil.which(f"clang-{v}"):
        env["LLVM_CC_NAME"] = f"clang-{v}"
        break
```

---

## 5. SVF 预编译二进制需要自带 LLVM 共享库

**现象**: wpa/saber 报错 `libLLVM.so.18.1rc: cannot open shared object file`。

**原因**: SVF 预编译二进制是用 SVF 自建的 LLVM 链接的（版本号带 `rc` 后缀），与 apt 安装的 LLVM 18.1.3 不兼容。

**解决**:
1. 下载 SVF Release 中配套的 LLVM tarball（如 `llvm-18.1.0-ubuntu20-rtti-x86-64.tar.gz`）
2. 设置 `LD_LIBRARY_PATH`:
```python
# 自动发现 SVF/LLVM 库目录
lib_dir = svf_bin_dir / ".." / "lib"
llvm_dirs = glob.glob(str(svf_parent / "llvm-*.obj/lib"))
env["LD_LIBRARY_PATH"] = ":".join(all_lib_dirs)
```

---

## 6. SVF 3.x API 和输出格式变化

**DOT 调用图格式变化**:
```
# SVF 2.x
Node0x... [label="{ funcName }"]
Node0x... -> Node0x...

# SVF 3.x
Node0x... [label="{CallGraphNode ID: 0 \{fun: funcName\}|{<s0>1|<s1>2}}"]
Node0x...:s0 -> Node0x...[color=red]
```

**Saber 输出格式变化**:
```
# SVF 2.x
BUG: Memory Leak at   File: foo.c  Line: 42

# SVF 3.x
NeverFree : memory allocation at : (CallICFGNode: { "ln": 19, "cl": 25, "fl": "main.c" })
```

**Saber CLI 标志变化**:
- `-uaf` 已移除（SVF 3.x 不再支持）
- `-leak` 和 `-dfree` 仍然可用
- 默认不带标志运行 saber 会执行所有分析

---

## 7. `Path.with_suffix()` 对复合后缀不可靠

**现象**: `Path("foo.o").with_suffix(".o.bc")` 的行为因 Python 版本而异，可能产生 `foo.o.bc` 或报 `ValueError`。

**解决**: 直接用字符串拼接:
```python
bc_path = Path(str(obj_path) + ".bc")  # 而非 obj_path.with_suffix(".o.bc")
```

---

## 8. WSL 命令行中多行 Python 的引号问题

**现象**: 通过 PowerShell 调用 `wsl` 执行包含引号的多行 Python 代码时，引号嵌套导致 `Unterminated quoted string`。

**解决**: 将 Python 代码写成 `.py` 文件，然后 `wsl python /path/to/script.py` 执行。

---

## 9. sudo 需要密码

**现象**: WSL 中 `sudo apt-get install` 需要密码，自动化脚本无法交互输入。

**解决**:
```bash
# 用户手动执行一次（最小权限原则）
sudo visudo -f /etc/sudoers.d/zscope-agent
# 添加: zeal ALL=(ALL) NOPASSWD: /usr/bin/apt-get
# 用完后删除: sudo rm /etc/sudoers.d/zscope-agent
```

---

## 10. WSL 命令长时间无输出

**现象**: clangd 在 `/mnt/c/` 路径上索引极慢，命令看起来像卡住了。

**原因**: NTFS 文件系统通过 drvfs 的 I/O 性能远低于 ext4。大量小文件读取（如 clangd 索引）尤其明显。

**解决**:
- 将项目文件复制到 WSL Linux 文件系统（`/home/...`）中操作
- 或接受较慢速度，设置足够长的超时
- 对于 bitcode 构建等中间产物，使用 `/tmp` 目录
