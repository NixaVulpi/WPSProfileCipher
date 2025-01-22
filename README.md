# WPS Office 配置文件加解密工具

本工具旨在实现对 WPS Office 配置文件（oem.ini/product.dat）的加解密。

## 使用方式

> 本工具可以配合 [WPSHashVerificationPatch](https://github.com/YukiIsait/WPSHashVerificationPatch) 使用以实现更方便的配置文件自定义。

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

- `--help, -h`
    - 显示帮助信息

## 示例

- 从明文 JSON 文件加密生成密文 INI 文件：
  ```shell
  java -jar wps-profile-cipher.jar -p product.json -c product.dat -e
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

## 开源许可

本项目根据 MIT 许可证授权，详见 [LICENSE](LICENSE.md) 文件。
