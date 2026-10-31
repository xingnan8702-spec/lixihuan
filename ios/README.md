# iOS v0.2.6 聚合诊断与 Packet Tunnel IPC

`ios/` 包含可在 Linux 测试的 Swift 6 core、SwiftUI iPad containing app、Packet Tunnel Extension 和 XcodeGen 工程描述。v0.2.6 在 v0.2.5 TCP/UDP/DNS 数据路径上增加隐私保护的聚合诊断、严格且限制为 64 KiB 的 app/extension JSON IPC、前台两秒刷新以及手动刷新/重置。诊断只包含 uptime、TCP/UDP active/high-water、上下行 bytes/packets、DNS total/failures、flow/resource rejection、transport failure 和固定 terminal error category，不包含目标、域名、IP、端口、token、路径、payload 或底层错误描述。

当前代码仍不能仅凭 Linux 测试称为可发布 VPN。Linux 没有 Apple SDK；Network.framework、NetworkExtension provider messaging、Tun2SocksKit 5.16.0、utun、路径 MTU、取消和资源回收都必须在 Xcode 与物理 iPad 验证。当前解析到的 Tun2SocksKit 5.16.0 没有稳定 `Socks5Tunnel.stats` API，因此没有猜测或重复合并 HEV packet counter，managed core counter 是权威来源。

## Linux 验证

```sh
cd ios
swift test
swift test -c release
```

`IPadProxyCore` 只导入 Foundation，并以 Swift 6 strict concurrency 编译。Linux 无 Apple SDK，因此 `App/**`、`PacketTunnelTemplate/**` 和 `PacketTunnelExtension/**` 不参与 SwiftPM typecheck；本地验证仅能对这些文件执行 `swiftc -parse` 语法检查。

## App 与工程骨架

- `project.yml` 定义 iOS 15、Swift 6 的 `IPadProxy` App target 和 `PacketTunnelExtension` target；两者使用本地 `IPadProxyCore` package，只有 Extension 依赖 Tun2SocksKit 5.16.0，App 嵌入 Extension。
- 占位 bundle IDs 是 `com.example.ipadproxy` 与 `com.example.ipadproxy.PacketTunnel`。App Group 是 `group.com.example.ipadproxy`；两个 target 使用同一 App Group 和共享 Keychain group。实际构建前必须在 Apple Developer 账户中建立匹配的 identifiers、capabilities 和 provisioning。
- App 使用 `NavigationView`/`Form` 显示 VPN 状态，编辑 relay endpoint、DIRECT/PROXY DNS literal，在 SecureField 接收 64 位 hex token，导入 JSON rules，并安装、连接或断开同一个 `NETunnelProviderManager` profile。
- token 只写入共享 Keychain，不写入 UserDefaults、App Group JSON 或 `NETunnelProviderProtocol.providerConfiguration`。App Group 只保存严格 Codable 的 relay/规则文件配置。
- 规则导入对 security-scoped URL 成对调用 start/stop，最多读取 32 MiB；`RuleStore` 先验证和编译，再原子替换共享规则文件。失败保留旧文件。
- Extension principal class `PacketTunnelEntry` 严格装配共享配置、规则 snapshot、Keychain token、受管 flow、两个 action 固定的 DNS resolver、`DNSProxyService`、loopback SOCKS TCP/UDP bridge 和 HEV adapter；任何缺项在安装 settings 前 fail closed。

在安装了 XcodeGen 和完整 Xcode/iOS SDK 的 macOS 上生成工程：

```sh
cd ios
xcodegen generate
```

生成工程不等于 VPN 可用。仍需配置开发团队、真实 capabilities/provisioning，并在物理 iPad 上完成 extension、App Group、共享 Keychain 和 packet stack 验证。

## 已实现

### v0.2.6 聚合诊断

- `TunnelDiagnostics` actor 的全部计数采用饱和加法，active 递减不会下溢；reset 保留当前 TCP/UDP active，将 high-water 重置为当前 active，并清空累计值与 terminal error。
- snapshot、request、response 都是 `Codable`/`Equatable`/`Sendable`；request/response 及嵌套 snapshot 拒绝未知字段，codec 拒绝空、malformed、版本不兼容和超过 64 KiB 的消息。
- `ManagedFlowCoordinator` 保持原有 initializer 调用兼容，通过可选 diagnostics 记录激活、策略拒绝、资源拒绝和 transport failure。managed TCP/UDP wrapper 只在成功 send/receive 后按 `Data.count` 记录，cleanup gate 确保并发 close/EOF/error 只递减一次 active。
- `DNSProxyService` 保持原有 initializer 调用兼容。每个 UDP query/TCP frame 计入 total；上游、timeout 和 response validation 失败对该 query 只计一次 failure；本地 REJECT response 不计 transport failure。
- Extension 强持有 core diagnostics 与 adapter diagnostics source。adapter 以 core 为累计值权威来源，并用 coordinator/limiter live snapshot 校验 active gauge；由于依赖中没有稳定 HEV stats API，不伪造 HEV byte/packet 数据。
- Provider app-message handler 严格处理 snapshot/reset，任何错误只返回固定错误枚举。App 仅在 connected/reasserting 时发消息，continuation 只完成一次；前台每两秒刷新，后台或断开立即取消，并支持手动刷新/reset。
- SwiftUI Diagnostics section 仅显示格式化上下行 bytes、active TCP/UDP、DNS failures、两类 rejection 与固定 last error，不显示任何目标信息。

### Tunnel protocol 与 transport boundary

- v1 的 32-bit 大端 frame，以及 `Address`、认证 `Request`、`Response`、UDP `Datagram` 的严格编解码。
- `TCPByteStream` 定义可取消的 async send/receive、write-side half-close 与 idempotent close；`UDPDatagramAssociation` 固定一个目标并保留 datagram 边界；`TunnelTransport` 显式 `openTCP(to:)`/`openUDP(to:)`。
- send 返回前不能把数据视为已发送。生产 adapter 必须实施有限背压；测试 double 也有明确容量，不提供无限队列。
- `PacketTunnelTemplate/NetworkFrameworkTLSTransport.swift` 实现 Apple TLS PROXY adapter：TLS 1.3、ALPN `ipad-proxy/1`、默认系统 trust/hostname validation、协商结果断言、建连和认证超时、精确 frame 读取、每 TCP flow 独立连接和 fixed-target framed UDP association。
- `PacketTunnelTemplate/NetworkFrameworkDirectTransport.swift` 提供 fixed-target DIRECT TCP/UDP adapter；仍需在 Xcode 和真机编译验证。

### Fake IP

- `FakeIPStore` actor 提供双栈稳定映射、反查、固定权威 TTL、每族容量上限和明确池耗尽错误。`Configuration` 的 `correlationGrace` 与 `reuseQuarantine` 默认各 60 秒，并拒绝负数或非有限值。
- `acquireLease(forFlow:)` 在一次 actor 调用中同时判断地址是否属于受管 Fake IP pool、执行反查并取得 lease。pool 内没有可用映射的地址会明确返回 `unknownManagedAddress`，供 flow 层 fail closed；pool 外地址保持普通 IP 语义。
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
- `DNSProxyService` 注入相互独立的 DIRECT/PROXY `DNSUpstreamResolver`。`DNSDecision.respond` 不访问上游；`forward` 只调用 decision 携带 action 对应的 resolver，resolver/backend 错误不触发另一条路径 fallback。
- resolver 接收未 framing 的 DNS message 和明确的 `.udp`/`.tcp` transport，并必须及时响应 task cancellation。`DNSProxyService.Configuration` 的 `upstreamTimeout` 必须为正有限值（默认 5 秒），`maximumInflight` 必须为正数（默认 256）；超限立即返回 typed error，不调用 resolver。每个 resolver call 独立执行超时竞速，超时会取消 resolver task，并在该任务退出后归还查询 permit。
- UDP 上游设置 TC 时，service 沿同一个 action 用 TCP 重试一次；重试的 TCP response 仍设置 TC 时抛出 `truncatedTCPResponse`。TCP 入口始终使用 TCP 上游、拒绝 TC response，并正确解码和重新生成两字节 framing。
- 每个上游 response 都验证 wire 长度、transaction ID、QR、opcode、规范化 question name、qtype 与 qclass，并安全跳过有边界检查的 resource records。malformed 与各类 mismatch 使用不含完整 QNAME 的 typed error。

### Rules 与 configuration

- JSON shape 保持 `rules/schema.json` 的严格字段、枚举和 first-match 语义；根对象与规则对象都拒绝未知字段。
- 为避免 Packet Tunnel 接受 500,000 条后在 keyword/CIDR 上出现不可控线性成本，v0.2 core 施加更严格的 20,000 条运行时上限。schema 的 500,000 是外部格式上限，不代表 iOS extension 的安全运行上限。
- exact domain、domain suffix 和 port 建立索引；domain keyword 与 CIDR 在 20,000 上限内保留有界线性 fallback。所有 matcher 最终比较原始 rule index，严格保留文件顺序。
- 测试包含最大规则数 exact lookup benchmark。
- `RuleStore` actor 从 Data/URL 严格导入，拒绝超过 32 MiB 的输入，先 decode/compile，再持久化，最后切换 active snapshot；任何失败保留旧 generation。
- Foundation `.atomic` 执行同目录临时写和 rename，完成后尽力同步文件。Foundation-only core 没有跨平台 directory-fsync API。
- snapshot 暴露 generation、configuration、active `RuleEngine` 和 trust。v0.2 没有签名格式，所有导入明确标记 `localImportOnly`。

### 受管 flow 与有界资源

- `ManagedFlowCoordinator.openTCP/openUDP` 先取得 opening permit，再原子分类并取得可选 Fake IP lease，恢复 domain 与原 port 后调用 `FlowRouter`，最后 activate permit。未知 pool 内 Fake IP 明确 fail closed；open、route 或 activate 失败会关闭已打开的底层 flow，并按 lease、permit 顺序释放资源。
- `ManagedTCPByteStream` 与 `ManagedUDPAssociation` 是 actor wrapper。`close()` 先幂等关闭底层，再释放 Fake IP lease 和 limiter permit。TCP remote EOF 只标记 read finished，仍允许 client→remote send；`finishSending()` 成功后禁止继续 send。读写两边都结束后自动 cleanup。显式 close 或底层 TCP send/receive/finishSending、UDP send/receive 错误仍立即 full cleanup。
- `ManagedFlowRegistry` 强持有所有已打开 wrapper，暴露 active/high-water snapshot，并由 coordinator 提供 `closeAll()`。wrapper cleanup 完成后注销并打破 registry retain cycle；并发 `closeAll()`、单 flow close、EOF 和 I/O error 都等待同一个 cleanup task，只关闭底层和释放 permit/lease 一次。registry 因此可以在 owner 遗忘 `close()` 时由 tunnel stop 统一回收。
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

1. 在 macOS 安装 XcodeGen，并从 `ios/` 运行 `xcodegen generate`。
2. 在 Apple Developer 账户中把占位 bundle IDs、App Group 和 Keychain group 替换为团队实际值，并配置两个 target 的签名与 provisioning。
3. 生成并编译工程，确认 App 能安装/更新唯一的 `NETunnelProviderManager` profile，且 App/Extension 能访问同一 App Group 与 Keychain item。
4. 验证缺少 App Group、provider.json、rules、Info.plist Keychain 字段或 token 时会在安装 settings 前 fail closed；不要移除这些检查，也不要加入 DIRECT fallback。
5. 验证 Tun2SocksKit 5.16.0 package resolution/checksum、Apple target typecheck/link 和 HEV 对当前 iOS/Xcode 的 utun 获取。
6. 在物理 iPad 验证 TCP/UDP IPv4/IPv6、half-close、DNS UDP/TCP、UDP idle expiry、立即启动失败、运行期 completion、quit/join、重复 stop、网络切换和内存上限。

## 测试覆盖

- SOCKS5 codec 覆盖 greeting/NO AUTH、CONNECT、UDP ASSOCIATE unspecified endpoint、三种 UDP target exact bytes、reply exact bytes、reply `0.0.0.0:0`、BIND/未知 command 的 REP `0x07`、空 UDP payload、FRAG/RSV/ATYP、zero port、截断、65,507 边界与 oversize。
- `ManagedFlowCoordinator` 覆盖普通 DIRECT/PROXY、Fake IP domain/port 恢复、未知 Fake IP fail closed、backend/activate 失败回滚、remote 先 FIN 后继续 send 再 finish、write 先 finish 后 remote EOF、TCP/UDP I/O error cleanup、registry active/high-water、遗忘 owner、并发 `closeAll`/close/EOF/finish、lease/permit 释放时机和并发 active cap。
- `DNSProxyService` 覆盖 DIRECT/PROXY resolver 隔离、错误与 timeout 无 fallback、A/AAAA 本地合成、HTTPS 转发、UDP TC 同 action TCP retry、TCP repeated TC 与 TCP 入口 TC 拒绝、TCP framing、response ID/QR/opcode/question/malformed 验证、重试响应复验、配置校验、无真实等待的可控 timeout、resolver cancellation、inflight cap、不调用 resolver 的超限拒绝、成功/失败/超时 permit 归还和 REJECT 本地响应。
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

- Apple 模板已将 `ManagedFlowCoordinator`、`DNSProxyService`、SOCKS5 UDP relay 与 Fake DNS TCP/UDP interception 接入 Packet Tunnel composition root；本环境没有 Apple SDK，只完成 SwiftPM/Linux core 测试与 Apple 文件语法解析，尚未 typecheck/link。
- DIRECT/PROXY DNS resolver 每次查询独立 open/send/receive/close，TCP 使用精确两字节 DNS framing；当前不实现连接池或额外 DNSSEC policy，且任何错误都不会切换 action。
- 受管 wrapper 没有也不能依赖 async `deinit`。正常主动放弃仍应显式 close；bridge/adapter stop 调用 coordinator `closeAll()`，回收 registry 强持有的遗忘 flow。
- 仓库已有 Tun2SocksKit dependency、HEV adapter 和 TCP bridge，但 Tun2SocksKit 没有可靠 positive-ready API，且尚未经过 Apple typecheck/link 和真机 utun 验证，因此不能声称端到端 Packet Tunnel 可用。
- 尚未真机验证 MTU、TCP/UDP IPv4/IPv6、TCP half-close、DNS UDP/TCP、UDP idle expiry、休眠唤醒、网络切换、内存压力和 stop cancellation。
- v1 只支持 TLS over TCP，不实现或宣称 QUIC。
- 不实现指纹仿冒、主动探测规避、MITM、自定义密码学或 TLS trust 绕过。
