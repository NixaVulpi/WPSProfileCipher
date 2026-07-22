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

- `--plainJsonFile, -p`
    - 明文 JSON 文件（如果未提供 `text` 则必填）
    - 类型：String

- `--text, -t`
    - 文本（如果提供则 `cipherIniFile` 和 `plainJsonFile` 将被忽略）
    - 类型：String

- `--shouldEncrypt, -e`
    - 是否加密内容（否则为解密）
    - 类型：Boolean
    - 默认值：false

- `--shouldSign, -s`
    - 从 JSON 生成密文 INI 时追加 OEM AES 签名
    - 仅能与 `--shouldEncrypt` 一起用于文件转换
    - 类型：Boolean
    - 默认值：false

- `--algorithm, -a`
    - 文本模式使用的算法：`profile`（普通配置 AES）或 `feature`（`[Feature]` IDEA/C64）
    - 默认值：`profile`
    - 文件转换会自动识别 `[Feature]` 段，不需要指定此参数

- `--help, -h`
    - 显示帮助信息

## 示例

- 从明文 JSON 文件加密生成密文 INI 文件：
  ```shell
  java -jar wps-profile-cipher.jar -p product.json -c product.dat -e
  ```

- 从明文 JSON 文件生成带 OEM AES 签名的密文 INI 文件：
  ```shell
  java -jar wps-profile-cipher.jar -p oem.json -c oem.ini -e -s
  ```

- 从密文 INI 文件解密生成明文 JSON 文件：
  ```shell
  java -jar wps-profile-cipher.jar -c product.dat -p product.json
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

明文 JSON 中的 `[Feature]` 段使用十进制 Feature ID 和整数值：

```json
{
  "Feature": {
    "16777331": "0"
  }
}
```

## 开源许可

本项目根据 MIT 许可证授权，详见 [LICENSE](LICENSE.md) 文件。
