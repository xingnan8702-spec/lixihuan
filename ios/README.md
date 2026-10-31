# iOS v0.2.1 core 与 Packet Tunnel 接入边界

`ios/` 包含一个可在 Linux 测试的 Swift 6 core package，以及不纳入 SwiftPM target 的 Apple Packet Tunnel 接入模板。core 已实现 v0.2.1 的协议、Fake IP lease 生命周期、有界资源原语、生命周期控制、DNS、规则存储、路由和传输边界；仓库仍不包含可运行 VPN 所需的 reviewed user-space TCP/IP stack、Xcode targets、entitlements 或 provisioning。

## Linux 验证

```sh
cd ios
swift test
swift test -c release
```

`IPadProxyCore` 只导入 Foundation，并以 Swift 6 strict concurrency 编译。`PacketTunnelTemplate/**` 导入 Network、Security 和 NetworkExtension，不参与 Linux target。

## 已实现

### Tunnel protocol 与 transport boundary

- v1 的 32-bit 大端 frame，以及 `Address`、认证 `Request`、`Response`、UDP `Datagram` 的严格编解码。
- `TCPByteStream` 定义可取消的 async send/receive、write-side half-close 与 idempotent close；`UDPDatagramAssociation` 固定一个目标并保留 datagram 边界；`TunnelTransport` 显式 `openTCP(to:)`/`openUDP(to:)`。
- send 返回前不能把数据视为已发送。生产 adapter 必须实施有限背压；测试 double 也有明确容量，不提供无限队列。
- `PacketTunnelTemplate/NetworkFrameworkTLSTransport.swift` 实现 Apple TLS PROXY adapter：TLS 1.3、ALPN `ipad-proxy/1`、默认系统 trust/hostname validation、协商结果断言、建连和认证超时、精确 frame 读取、每 TCP flow 独立连接和 fixed-target framed UDP association。
- `PacketTunnelTemplate/NetworkFrameworkDirectTransport.swift` 提供 fixed-target DIRECT TCP/UDP adapter；仍需在 Xcode 和真机编译验证。

### Fake IP

- `FakeIPStore` actor 提供双栈稳定映射、反查、固定权威 TTL、每族容量上限和明确池耗尽错误。`Configuration` 的 `correlationGrace` 与 `reuseQuarantine` 默认各 60 秒，并拒绝负数或非有限值。
- `acquireLease(for:)` 在一次 actor 操作中完成反查和 lease 计数。`FakeIPLease` 只能由 store 创建，公开规范化域名、地址和地址族；`release(_:)` 验证 store、映射和 lease identity，因此重复 release、迟到 release 和地址复用后的旧 lease 都不会影响新映射。
- DNS TTL 到期后，在 correlation grace 结束前仍可新建 lease；grace 后不能新建 lease。已有 lease 会保留映射。最后一个 lease 在 grace 后释放时，地址进入 quarantine；quarantine 到期后才回到 pool。
- 新 DNS 查询只要映射尚未进入 quarantine，就续订同一地址和一段新的固定 TTL。`existingAddress(for:)`、`domain(for:)` 和 `acquireLease(for:)` 都不会滑动 TTL。
- **`domain(for:)` 仅用于无 lease 的诊断。生产 packet-flow 接入必须调用 `acquireLease(for:)`，并持有 lease 到 TCP/UDP flow 完全关闭；不得用 `domain(for:)` 完成生产 flow 反查。**
- 默认 IPv4 pool 为 `198.18.0.0/15`。
- 默认 IPv6 pool 明确定为 `fd00:198:18:2::/64`。这是固定的 ULA，仅用于 Packet Tunnel 虚拟接口和内部 Fake IP，不应发布到外部路由。真实产品若同时运行多个相互连通的 ULA 网络，应配置部署专用的随机 RFC 4193 Global ID，避免固定前缀冲突。
- 两个 pool 都保留 host ID 0、1、2，分别用于网络、gateway 和 DNS；IPv4 额外保留广播地址。默认 gateway/DNS 是 `198.18.0.1`/`.2` 和 `fd00:198:18:2::1`/`::2`。
- 分配使用游标和隔离期后的回收栈，不逐次扫描地址池；TTL/grace 与 quarantine 都使用惰性失效最小堆并作摊销压缩。IPv6 `/64` 游标到达 `UInt64.max` 后会明确耗尽，不会重复分配最后一个 host。
- 域名转小写并移除末尾点；当前不执行 IDNA。

### DNS

- 严格解析恰好一个 question 的 query，边界检查所有长度。
- name reader 支持压缩指针，拒绝循环、越界、非法 label、截断和尾随数据。
- 支持 A(1)、AAAA(28) 及 DNS-over-TCP 两字节 framing。
- A/AAAA 根据 `RuleEngine`：PROXY 合成 Fake IP NOERROR answer，DIRECT 返回原 query 的明确 forward 决策，REJECT 返回 REFUSED。
- 保留 transaction ID 和 RD，answer 使用配置 TTL。其他 qtype/qclass 一律 forward，包括 HTTPS/SVCB，不伪造记录。
- malformed input 抛出有类型错误，不触发越界读取或崩溃。

### Rules 与 configuration

- JSON shape 保持 `rules/schema.json` 的严格字段、枚举和 first-match 语义；根对象与规则对象都拒绝未知字段。
- 为避免 Packet Tunnel 接受 500,000 条后在 keyword/CIDR 上出现不可控线性成本，v0.2 core 施加更严格的 20,000 条运行时上限。schema 的 500,000 是外部格式上限，不代表 iOS extension 的安全运行上限。
- exact domain、domain suffix 和 port 建立索引；domain keyword 与 CIDR 在 20,000 上限内保留有界线性 fallback。所有 matcher 最终比较原始 rule index，严格保留文件顺序。
- 测试包含最大规则数 exact lookup benchmark。
- `RuleStore` actor 从 Data/URL 严格导入，拒绝超过 32 MiB 的输入，先 decode/compile，再持久化，最后切换 active snapshot；任何失败保留旧 generation。
- Foundation `.atomic` 执行同目录临时写和 rename，完成后尽力同步文件。Foundation-only core 没有跨平台 directory-fsync API。
- snapshot 暴露 generation、configuration、active `RuleEngine` 和 trust。v0.2 没有签名格式，所有导入明确标记 `localImportOnly`。

### 有界资源与 lifecycle

- `BoundedByteQueue<Element>` 通过 `@Sendable` size closure 同时限制 item 数和 byte 数，等待消费者数也受 item 上限约束，不会形成无界 continuation 列表。admission 不等待；FIFO dequeue 可取消；`finish()` 保留并排空已接收元素后返回 `nil`，`cancel()` 丢弃缓存并以 typed error 唤醒等待者。metrics 包含 current、high-water、accepted、dequeued 和 rejected 指标。
- `FlowLimiter` 默认限制 active flow 1024、opening flow 128、active UDP flow 256。只有 limiter 能创建 `FlowPermit`；opening 到 active 的转换、失败释放、外部 permit 和重复释放都由 actor 内 identity/state 校验。snapshot 暴露 current、high-water 和 rejection 指标。
- `TunnelLifecycleController` 是 Foundation-only actor，不依赖 NetworkExtension。它管理 stopped/starting/running/stopping/failed、单调 generation、stop-during-start、启动失败回滚、fatal/stop 共享 cleanup gate 和 cleanup timeout。cleanup 超时或失败会标记 residual resources 并阻止 restart；后续 `stop()` 可重试 cleanup，只有成功后才解除阻止。
- 这些 core primitive 尚未接入 `PacketTunnelTemplate`，因为模板不属于 SwiftPM target。Apple adapter 接入时必须让每个 flow 持有 Fake IP lease 和 limiter permit，并用 controller 驱动 runtime 的 prepare/activate/quiesce/close。

### Routing 与 credentials

- `FlowRouter` 对 DIRECT、PROXY、REJECT 显式调度。每次调用独立，backend 错误原样向上传播，PROXY 失败绝不静默改为 DIRECT。
- `CredentialStore` 只定义安全存储协议。内存实现只存在于测试 target。
- `PacketTunnelTemplate/KeychainCredentialStore.swift` 提供 Apple Keychain adapter，处理 app/extension 首次并发写入并统一落实 `AfterFirstUnlockThisDeviceOnly`；错误不包含 token。
- `PacketTunnelTemplate/AppGroupConfigurationStore.swift` 只保存非敏感 provider 配置，并拒绝目录穿越形式的文件名；token 不进入 App Group JSON。

## Xcode 接入步骤

1. 在 containing app 的 Xcode 工程中将 `ios/` 作为 local Swift Package，引入 `IPadProxyCore`。
2. 创建 Packet Tunnel Extension target，加入 NetworkExtension、Network 和 Security。
3. 将 `PacketTunnelTemplate/*.swift` 加入 extension target；将 Keychain 配置界面和同一 access group 加入 containing app target。
4. 配置 NetworkExtension entitlement、App ID、extension provisioning、Info.plist provider class、App Group 和 Keychain access group。
5. 提供经过审查的 lwIP adapter 或同类 user-space TCP/IP stack，实现 `PacketStackAdapter`。adapter 必须为每个 flow 创建独立 task，提供有限 buffer、取消、deadline、TCP half-close 与 UDP idle expiry。
6. override `PacketTunnelProvider.makeDependencies()`，创建启动时的 `RuleStore` snapshot、`FakeIPStore`、`DNSProxyCore`、DIRECT `TunnelTransport`、`NetworkFrameworkTLSTransport`、`FlowRouter` 和 packet-stack adapter。缺少任何依赖时模板 fail closed。
7. provider 先安装 IPv4/IPv6 route 与 DNS network settings，再允许 adapter 开始 `packetFlow` reads；停止时 adapter 必须取消 packet reads、全部 flow、TLS 操作和 timers。
8. 使用 `AppGroupConfigurationStore` 传递 relay hostname/port 与 rules filename，使用 `KeychainCredentialStore` 传递 token。不要把 token 放进 provider configuration 或日志。

## 测试覆盖

- 原有 protocol golden frames、边界、strict decode 与 secret redaction。
- Fake IP 规范化、固定 TTL、correlation grace、lease pin/release、quarantine、ABA/重复 release、续订、耗尽和并发。
- `BoundedByteQueue` 的 item/byte 双限制、FIFO、指标、finish、cancel 和等待任务取消。
- `FlowLimiter` 的 opening/active/UDP caps、转换、typed errors、伪造/重复 release 防护和并发上限。
- lifecycle 的 stop-during-start、重复 stop、启动回滚、fatal cleanup、timeout residual block 和 generation。
- DNS A/AAAA、DIRECT、REJECT、带路由动作的 HTTPS/SVCB forward、EDNS(0)、非法 compression、malformed input 与 TCP framing。
- RuleStore atomic persistence、startup load，以及验证/持久化失败保留旧 active generation。
- FlowRouter 三分支、PROXY 失败不回退，以及有界 transport doubles、half-close 和测试用 credential store。
- 规则索引顺序、20,000 条上限与 exact lookup performance。

## 尚未验证或未包含

- Apple 模板未在 Xcode、iOS SDK 或真机编译。本环境只验证 SwiftPM/Linux core；Network.framework 和 NetworkExtension API 仍需在实际工程中通过编译与签名。
- 仓库没有 lwIP dependency/adapter、containing app、extension target、Info.plist、entitlements 或 UI，因此不能声称端到端 Packet Tunnel 已运行。DIRECT Network.framework backend 已提供模板，但尚未经过 Xcode/真机验证。
- 尚未真机验证 MTU、IPv4/IPv6 全流量 route、DNS recovery、TCP half-close、UDP idle expiry、休眠唤醒、网络切换、内存压力和 stop cancellation。
- v1 只支持 TLS over TCP，不实现或宣称 QUIC。
- 不实现指纹仿冒、主动探测规避、MITM、自定义密码学或 TLS trust 绕过。
