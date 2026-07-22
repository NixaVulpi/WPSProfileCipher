# WPS Profile Cipher

跨平台的 WPS 配置文件加密、解密与 OEM 签名工具。项目使用 C++20、CMake、Ninja 和 vcpkg，基于 Crypto++、CLI11、SimpleIni 和 Catch2 构建。

## 功能

- 加密或解密普通配置字段：AES-256/ECB/PKCS#7 与 WPS Base64 变体。
- 自动处理 `[Feature]` 节：IDEA、WPS C64 编码和兼容性校验帧。
- 为加密后的 OEM INI 追加 `OemSignType1` 签名。
- 在 Windows x86/x64/arm64、Linux x64/arm64 和 macOS x64/arm64 构建。
- 默认使用平台原生换行，也可显式指定 CRLF 或 LF。

> 这些算法和固定密钥用于兼容已有 WPS 文件格式，不适合保护新的敏感数据。

## 命令行

程序使用子命令区分操作：

```text
wps-profile-cipher encrypt-text [--codec profile|feature] <text>
wps-profile-cipher decrypt-text [--codec profile|feature] <text>
wps-profile-cipher encrypt-file [--sign] [--header-comment <text>]
                                [--line-ending native|crlf|lf] <input> <output>
wps-profile-cipher decrypt-file [--line-ending native|crlf|lf] <input> <output>
```

普通文本加密与解密：

```powershell
wps-profile-cipher encrypt-text "true"
wps-profile-cipher decrypt-text "NsbhfV4nLv_oZGENyLSVZA.."
```

`[Feature]` 条目加密与解密：

```powershell
wps-profile-cipher encrypt-text --codec feature "16777331=0"
wps-profile-cipher decrypt-text --codec feature `
  "5HsDS8UAjZnKSU9I2xbCubqA10=KHsDS8UAjZn4U3A385v-NVsE10"
```

配置文件转换：

```powershell
wps-profile-cipher encrypt-file product.plain.ini product.dat
wps-profile-cipher decrypt-file product.dat product.plain.ini
```

默认的 `native` 在 Windows 写 CRLF，在 Linux/macOS 写 LF。需要跨平台固定字节布局时可以指定：

```powershell
wps-profile-cipher encrypt-file --line-ending crlf product.plain.ini product.dat
wps-profile-cipher decrypt-file --line-ending lf product.dat product.plain.ini
```

生成带头注释和 OEM 签名的配置：

```powershell
wps-profile-cipher encrypt-file --sign `
  --header-comment "WPS OEM configuration" `
  --line-ending crlf `
  oem.plain.ini oem.ini
```

文件转换会按节名自动选择编码器；`[Feature]` 不需要额外参数。普通节的逗号分隔值会逐项转换。

## Windows 构建

需要安装包含“使用 C++ 的桌面开发”工作负载的 Visual Studio，以及 CMake、Ninja 和
vcpkg。`VCPKG_ROOT` 必须指向 vcpkg 仓库根目录。

从开始菜单打开 **Developer PowerShell for Visual Studio**，x64 构建使用其默认的
MSVC x64 工具链：

```powershell
$env:VCPKG_ROOT = "D:\path\to\vcpkg"

cmake --preset windows-x64-mt-release
cmake --build --preset windows-x64-mt-release --parallel
ctest --preset windows-x64-mt-release
```

Windows 下项目和 vcpkg 库均静态链接，同时提供静态与动态 MSVC CRT 版本：

- `/MT`：`windows-x64-mt-release`、`windows-x86-mt-release`、`windows-arm64-mt-release`
- `/MD`：`windows-x64-md-release`、`windows-x86-md-release`、`windows-arm64-md-release`
- Debug：`windows-x64-mt-debug` 使用 `/MTd`，`windows-x64-md-debug` 使用 `/MDd`

例如构建 x64 `/MD` 版本：

```powershell
cmake --preset windows-x64-md-release
cmake --build --preset windows-x64-md-release --parallel
ctest --preset windows-x64-md-release
```

交叉编译时，从 Visual Studio 开始菜单打开与目标匹配的工具命令行：

- x86：**x64_x86 Cross Tools Command Prompt for Visual Studio**
- arm64：**x64_arm64 Cross Tools Command Prompt for Visual Studio**

在对应终端设置 `VCPKG_ROOT` 后运行相应 preset。以下示例构建 x86 `/MD` 版本：

```text
cmake --preset windows-x86-md-release
cmake --build --preset windows-x86-md-release --parallel
ctest --preset windows-x86-md-release
```

arm64 的 `/MT` 与 `/MD` preset 分别为：

```text
cmake --preset windows-arm64-mt-release
cmake --build --preset windows-arm64-mt-release --parallel

cmake --preset windows-arm64-md-release
cmake --build --preset windows-arm64-md-release --parallel
```

arm64 测试需要在 arm64 Windows 主机或对应的 GitHub Actions runner 上执行。

Windows 发布包以 `-mt` 或 `-md` 后缀区分 CRT 类型。仓库内的 VSCode 配置包含 Windows x86/x64/arm64 的 `/MT` 与 `/MD` 版本，以及 Linux x64/arm64 和 macOS x64/arm64。先在 CMake Tools 中选择并配置当前平台的 Release preset，再通过 “C/C++: Select a Configuration” 选择同名配置；对应的 `compile_commands.json` 会用于 IntelliSense。若编辑器仍保留旧诊断，执行 “C/C++: Reset IntelliSense Database”。

## Linux 与 macOS 构建

```bash
export VCPKG_ROOT=/path/to/vcpkg
preset=linux-x64-release  # 改为当前平台和架构对应的 preset

cmake --preset "$preset"
cmake --build --preset "$preset" --parallel
ctest --preset "$preset"
```

其他可选值为 `linux-arm64-release`、`macos-x64-release` 和 `macos-arm64-release`。

Crypto++ 在所有目标上静态链接；Linux 的系统 C 运行库和 macOS 的系统库仍由操作系统动态提供。

## 项目结构

```text
include/wps_profile_cipher/  公共 C++ API
src/crypto/                  密码原语适配与 WPS 格式编解码
src/profile/                 INI 文档模型与文件转换
src/cli/                     命令行入口
tests/                       兼容性向量和功能测试
cmake/triplets/              跨架构 vcpkg triplet
```

Crypto++ 提供 AES、IDEA、MD5 和安全随机数，CLI11 负责命令行解析，SimpleIni 负责INI 读写，Catch2 负责测试发现和断言。WPS 私有的 C64 位序、Feature 帧尾、位交换、逗号分项转换和 OEM 签名布局属于文件协议，保留在独立的格式层中。

## 许可证

项目使用 [MIT License](LICENSE.md)。第三方依赖遵循各自许可证。
