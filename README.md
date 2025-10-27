# FridaDetector - Android Frida 检测测试应用

这是一个简单的 Android 应用程序，用于演示和测试常见的 Frida 检测技术。它主要用作测试反检测方法（例如，经过修改/打补丁的 Frida 版本）有效性的“靶机”应用程序。

## 功能 (检测方法)

该应用实现了多种基于常见 Frida 特征的检测方法，这些方法主要通过 JNI 调用原生 C++ 代码实现：

1.  **Frida 端口扫描 (Port Scan)**
    * 尝试连接本地回环地址 (`127.0.0.1`) 的 Frida 默认端口 (`27042`)。
    * 对应伪代码: `portCheck`

2.  **线程检测 (Thread Check)**
    * 遍历 `/proc/self/task/` 目录。
    * 读取每个线程的 `/proc/self/task/[tid]/status` 文件。
    * 查找 Frida 相关的特征线程名 (如 `gmain`, `gum-js-loop`, `gdbus`, `pool-frida`) 或特定的 `SigBlk` 值。
    * 对应伪代码: `threadCheck`

3.  **Maps 记录检查 (Maps Check)**
    * 扫描 `/proc/self/maps` 文件。
    * 查找包含特定字符串（如 `agent`）或特定路径（如 `/data/local/tmp`）的内存映射条目。
    * 额外检查 `/data/local/tmp/re.frida.server/frida-agent-32.so` 文件是否存在。
    * 对应伪代码: `mapsCheck`

4.  **文件描述符检测 (FD Check)**
    * 遍历 `/proc/self/fd/` 目录下的符号链接。
    * 使用 `readlink` 读取链接指向的目标。
    * 查找包含特定字符串（如 `linjector`, `/data/local/tmp`）的链接目标。
    * 额外检查 `/data/local/tmp/re.frida.server` 目录是否存在。
    * 对应伪代码: `sub_1940` / `fdCheck`

5.  **内存特征扫描 (Memory Scan)**
    * 扫描 `/proc/self/maps` 中符合特定条件（可读、私有、有文件路径、非 `/dev/`）的内存区域。
    * 在这些区域中**逐字节搜索**硬编码的 Frida 特征字符串（如 `frida:rpc`, `FridaScriptEngine`, `GLib-GIO`, `GDBusProxy`, `GumScript`），`但不`检查空终止符。
    * **注意**: 此方法可能因搜索非 Frida 独有字符串（如 `GLib-GIO`）而产生误报，并且由于逐字节扫描性能较低。代码已通过动态构建字符串避免了自检问题。
    * 对应伪代码: `sub_1C20` / `memoryCheck`

6.  **Trace 状态检查 (Trace Check)**
    * 检查 `/proc/self/status` 和 `/proc/self/task/[tid]/status` 中的 `TracerPid` 字段是否非零。
    * 检查 `/proc/self/stat` 和 `/proc/self/task/[tid]/stat` 中的进程状态是否为 't' (tracing stop)。
    * 对应伪代码: `sub_2388` / `traceCheck`

## 构建

1.  在 Android Studio 中打开项目。
2.  确保已安装 Android NDK（通常由 Android Studio 自动管理）。
3.  使用菜单栏 `Build -> Make Project` 或 `Build -> Build Bundle(s) / APK(s) -> Build APK(s)` 来构建项目。
4.  生成的调试版 APK 位于 `app/build/outputs/apk/debug/app-debug.apk`。

## 使用

1.  将生成的 `app-debug.apk` 安装到 Android 设备或模拟器上。
2.  启动 "FridaDetector" 应用。
3.  点击 "Refresh" 按钮运行所有检测。
4.  界面会显示每个检测项的结果：
    * **未发现Frida / 绿色**: 表示该项检测通过（未检测到 Frida）。
    * **发现Frida / 红色**: 表示该项检测失败（检测到了 Frida）。
5.  下方的文本框会显示每个检测项更详细的原因或日志（如果检测失败）。

## 注意

* **用途**: 此应用主要用于**教育和测试目的**，以了解 Frida 检测和反检测技术。
* **非完全可靠**: 应用中实现的检测方法是常见的示例，但**并非无法绕过**。使用经过修改的 Frida 版本（例如应用了反-反调试补丁）通常可以轻松绕过这些检测。
* **性能**: 内存扫描功能（特别是严格模仿汇编的版本）可能比较耗时。当前版本已将其放入后台线程执行以避免 ANR。
* **误报**: 如上所述，某些检测（特别是基于非唯一字符串的内存扫描）可能在未运行 Frida 的情况下产生误报。
