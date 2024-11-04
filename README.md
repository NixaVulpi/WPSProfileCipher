# WPS Office 配置文件加解密工具

本工具旨在实现对 WPS Office 配置文件（oem.ini/product.dat）的加解密。

## 使用方式

```txt
java -jar wps-profile-cipher.jar <options_list>
```

### 选项列表

- `--originalFile, -o`
    - 原始的 INI 文件（如果未提供 `text` 则必填）
    - 类型：String

- `--newFile, -n`
    - 新的 INI 文件（如果未提供 `text` 则必填）
    - 类型：String

- `--text, -t`
    - 文本（如果提供则 `originalFile` 和 `newFile` 将被忽略）
    - 类型：String

- `--shouldEncrypt, -e`
    - 是否加密内容（否则为解密）
    - 类型：Boolean
    - 默认值：false

- `--shouldNotEscape, -s`
    - 是否不转义内容（例如带换行的内容会导致无法解析）
    - 类型：Boolean
    - 默认值：false

- `--help, -h`
    - 显示帮助信息

## 开源许可

本项目根据 MIT 许可证授权，详见 [LICENSE](LICENSE.md) 文件。
