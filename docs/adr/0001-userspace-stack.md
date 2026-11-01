# ADR 0001：Packet Tunnel 用户态网络栈候选

- 状态：Implemented locally for v0.2.5; Xcode/physical-device gate pending

## v0.2.5 实施说明

本地 v0.2.5 在相同的 Tun2SocksKit `5.16.0` 与 loopback SOCKS bridge 边界上增加标准 UDP ASSOCIATE、本地 UDP relay、Fake DNS UDP/TCP interception 和 action 固定的 DIRECT/PROXY DNS resolver。HEV 配置使用 `udp: 'udp'`；每目标 UDP session、idle、DNS inflight 和 stop cleanup 均有明确边界，错误不得切换 routing action。

Tun2SocksKit 5.16.0 仍只在 tunnel 退出时给 completion，不提供可靠的成功 ready 回调。因此“utun 已就绪”、Apple target typecheck/link、HEV UDP mode、DNS interception、quit/join 和实际 TCP/UDP 数据路径仍是 Xcode + 物理 iPad 发布门禁；通过前不能称为完整 VPN。第三方来源与许可记录见 `THIRD_PARTY_NOTICES.md`。

## 背景

`NEPacketTunnelProvider` 提供 IP packet flow，但当前 core 处理的是 TCP/UDP flow。工程仍需要一个经过审查的用户态 TCP/IP 栈，将 IP packet 转为本地 SOCKS flow，再接入现有的 DIRECT/PROXY/REJECT 路由。当前 extension 必须继续 fail closed，不能用空实现或直接转发伪装成可运行 VPN。

本 ADR 的原始决策阶段只选择后续验证候选，当时不添加 package、源码、XCFramework 或预编译二进制；v0.2.4 的实际接线范围见上方实施说明。

## 候选比较

### Tun2SocksKit 5.16.0 / HEV

[Tun2SocksKit](https://github.com/EbrahimTahernejad/Tun2SocksKit) 面向 Apple 平台封装 tun2socks；其底层候选 [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) 支持 IPv4、IPv6、TCP 和 UDP。两者仓库声明 MIT 许可证；实际集成前仍需固定 5.16.0 tag/revision、核对 package checksum，并保留 Tun2SocksKit、HEV 及其传递依赖的许可证通知。

优点：Swift/Apple 接入面较小，HEV 是 C 实现，预计比嵌入完整 Go 运行时更容易控制 Packet Tunnel extension 的内存。

风险与缺口：Apple Packet Tunnel 集成通常通过扫描文件描述符并识别 utun socket 来取得接口 fd。这依赖未公开为高级 API 的底层行为，必须在目标 iOS/Xcode 版本和真机上验证。HEV 接收的是 SOCKS endpoint，而现有 core 提供的是 `FlowRouter` 和 transport；因此还必须实现一个有界、可取消、支持 TCP half-close 与 UDP 生命周期的本地 SOCKS bridge。没有该 bridge 时，加入 Tun2SocksKit 也不能接入现有规则和 relay 协议。

### NEAXCE

[NEAXCE](https://github.com/pinusmassoniana/NEAXCE) 是 Swift/C、lwIP 和 Xray-compatible transport 的整套 VPN engine。仓库声明 Apache-2.0 许可证，但同时明确标记为 alpha，公开 API 尚不稳定，部分 transport 也未完成。它包含的协议、路由和 transport 范围明显超过本项目需要，并会与现有 core 的职责重叠。

结论：许可证本身不是阻碍，但不引入 alpha 状态的整包 NEAXCE。后续可以把其公开架构作为调研输入；若复用任何代码，仍需按 Apache-2.0 和仓库第三方许可证文件履行通知义务。

### gVisor netstack

[gVisor](https://github.com/google/gvisor) 包含 Go 用户态网络栈，采用 [Apache License 2.0](https://github.com/google/gvisor/blob/master/LICENSE)。netstack 功能完整，并有成熟项目使用经验。

缺点：直接用于 iOS 需要维护 Go/mobile 或其他桥接、裁剪依赖并证明 extension 内存满足系统限制；它也会引入与当前 Swift/C 方向不同的构建链和较大供应链面。当前阶段的集成、内存和审计成本最高。

## 决策

后续 spike 的首选候选是 **Tun2SocksKit 5.16.0 / HEV**。v0.2.4 已采用该固定 package 版本，但真机验证仍未完成。

进入实现前必须全部满足：

1. 在依赖解析时固定并核验 Tun2SocksKit 5.16.0 的 tag/revision 和 checksum。
2. 完成源代码、传递依赖和 MIT 许可证通知审查。
3. 设计本地 SOCKS bridge，使每个 flow 继续经过现有 `RuleEngine`、`FlowRouter`、限流和 cleanup 路径；不得绕过规则，也不得在 PROXY 失败时回退 DIRECT。
4. 将 utun fd 扫描隔离在小型 adapter 中，并在支持的每个 iOS/Xcode 组合与物理 iPad 上验证。
5. 通过 IPv4/IPv6、TCP half-close、UDP idle expiry、DNS、网络切换、休眠唤醒、取消、内存压力和 stop cleanup 测试。
6. 在上述验证完成前，只能描述为本地 v0.2.5 UDP/DNS 接线；任何配置、凭据、规则或 runtime 缺失必须继续 fail closed。

Content was rephrased for compliance with licensing restrictions.
