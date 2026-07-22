# WPS 配置文件加解密工具

本工具旨在实现对 WPS 配置文件（oem.ini/product.dat）的加解密。

## 使用方式

```text
java -jar wps-profile-cipher.jar <options_list>
```

### 选项列表

- `--cipherIniFile, -c`
    - 密文 INI 文件（如果未提供 `text` 则必填）
    - 类型：String

- `--plainIniFile, -p`
    - 明文 INI 文件（如果未提供 `text` 则必填）
    - 类型：String

- `--text, -t`
    - 文本（如果提供则两个 INI 文件参数将被忽略）
    - 类型：String

- `--shouldEncrypt, -e`
    - 是否加密内容（否则为解密）
    - 类型：Boolean
    - 默认值：false

- `--shouldSign, -s`
    - 从明文 INI 生成密文 INI 时追加 OEM AES 签名
    - 仅能与 `--shouldEncrypt` 一起用于文件转换
    - 类型：Boolean
    - 默认值：false

- `--headerComment, -m`
    - 密文 INI 首行 `;` 后的注释内容
    - 注释后写入一个空行，再开始第一个 INI 段
    - 生成签名时，该注释和空行也包含在签名覆盖范围内

- `--algorithm, -a`
    - 文本模式使用的算法：`profile`（普通配置 AES）或 `feature`（`[Feature]` IDEA/C64）
    - 默认值：`profile`
    - 文件转换会自动识别 `[Feature]` 段，不需要指定此参数

- `--help, -h`
    - 显示帮助信息

## 示例

- 从明文 INI 文件加密生成密文 INI 文件：
  ```shell
  java -jar wps-profile-cipher.jar -p product.plain.ini -c product.dat -e
  ```

- 从明文 INI 文件生成带 OEM AES 签名的密文 INI 文件：
  ```shell
  java -jar wps-profile-cipher.jar -p oem.plain.ini -c oem.ini -e -s
  ```

- 生成带首行注释和 OEM AES 签名的密文 INI：
  ```shell
  java -jar wps-profile-cipher.jar -p oem.plain.ini -c oem.ini -e -s --headerComment "WPS OEM configuration"
  ```

  输出开头：
  ```ini
  ;WPS OEM configuration

  [section]
  ```

- 从密文 INI 文件解密生成明文 INI 文件：
  ```shell
  java -jar wps-profile-cipher.jar -c product.dat -p product.plain.ini
  ```

- 加密文本：
  ```shell
  java -jar wps-profile-cipher.jar -t "true" -e
  ```

  程序输出：
  ```text
  WHfH10HHgeQrW2N48LfXrA..
  ```

- 解密文本：
  ```shell
  java -jar wps-profile-cipher.jar -t "NsbhfV4nLv_oZGENyLSVZA.."
  ```
  
  程序输出：
  ```text
  false
  ```

- 生成 `[Feature]` 条目：
  ```shell
  java -jar wps-profile-cipher.jar -a feature -t "16777331=0" -e
  ```

  程序输出：
  ```text
  5HsDS8UAjZnKSU9I2xbCubqA10=KHsDS8UAjZn4U3A385v-NVsE10
  ```

- 解密 `[Feature]` 条目：
  ```shell
  java -jar wps-profile-cipher.jar -a feature -t "5HsDS8UAjZnKSU9I2xbCubqA10=KHsDS8UAjZn4U3A385v-NVsE10"
  ```

  程序输出：
  ```text
  16777331=0
  ```

## 开源许可

本项目根据 MIT 许可证授权，详见 [LICENSE](LICENSE.md) 文件。
