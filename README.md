## Yubico FIDO2-Webauthn Demo

> 官网：https://developers.yubico.com/FIDO2/

> 官方github: https://github.com/Yubico/java-webauthn-server

### FIDO2/WebAuthn 优点

+ 全安性强：基于硬件公钥加密，防止网络钓鱼，会话劫持，中间人和恶意软件攻击

+ 隐私保护：FIDO2 身份验证器为每个服务生成一对新密钥，服务器存储公钥。这种方式防止了供应商之间共享问题。

+ 多种选择：开放式标准提供灵活性和产品选择。专为现有手机和计算机设计。使用于多种身份验证模式，以及不同的通信方式（USB，NFC，蓝牙）。

+ 成本: 买一个KEY贵啊！！！

+ 分层方法：对于需要更高级别身份验证安全性的组织，FIDO2支持带有PIN，生物识别或手势的硬件身份验证设备来提供额外保护。

### 工作流程

下面的流程图是 FIDO2/WebAuthn 的流程: