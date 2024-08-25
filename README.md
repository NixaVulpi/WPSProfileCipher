# WPS Office 配置文件加解密工具

从某个版本开始，WPS Office 的 OEM.INI 中所有的配置项都被加密了，本工具即可实现对配置文件的加解密。

## 使用方式

```txt
java -jar wps-profile-converter.jar <options_list>
```

### 选项列表

- `--originalFile, -o`
    - 原始的 INI 文件（必填项）
    - 类型：String

- `--newFile, -n`
    - 新的 INI 文件（必填项）
    - 类型：String

- `--shouldEncrypt, -e`
    - 是否加密文件（否则为解密）
    - 类型：Boolean
    - 默认值：false

- `--shouldEscapeContent, -s`
    - 是否转义内容（否则带换行的内容会导致无法解析）
    - 类型：Boolean
    - 默认值：false

- `--help, -h`
    - 显示帮助信息

## 开源许可

本项目根据 MIT 许可证授权，详见 [LICENSE](LICENSE.md) 文件。
