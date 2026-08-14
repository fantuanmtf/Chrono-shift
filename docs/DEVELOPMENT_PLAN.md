# Chrono-shift 开发思路与路线图 (Development Plan)

> 版本: v7.7-dev · 日期: 2026-08-14 · 状态: P0 ✅ / P1 ✅ / P2 ✅ / P3 ✅ / P4 ✅ — 路线图全部完成
> 本文档是开发路线的唯一事实来源；协议细节见 PROTOCOL.md，实现与本文档冲突时以本文档为准（并修正实现）。

## 1. 核心认知：先修概念，再写代码

### 1.1 DC-Net 是"信任圈内的广播"，不是路由

- DC-Net 的 XOR 是**匿名化运算**，不是寻路机制。它没有路径概念：每个成员每轮都为整个消息长度提交一份份额，全局 XOR 后消息广播给**组内所有人**。
- 因此 "XOR 路由 DC-Net" 的说法不成立；正确的模型是 **一个频道 = 一个 DC-Net 组**（小规模，通常 3~20 人）。
- 三个硬约束必须写进架构：
  1. **规模上限**：每轮每个成员传输 O(消息长度) 份额，任何一人缺席/超时整轮作废 → 只用于小群组；
  2. **破坏问题**：任何成员可提交垃圾份额阻塞信道 → 用 F2F 信任 + Blame 协议定位并踢出破坏者（追责不破坏发送者匿名性）；
  3. **1:1 私聊不走 DC-Net**：私聊走 Double Ratchet；DC-Net 只服务频道广播。
- 需要大网络匿名路由时，另建 mixnet/中继层（relay.rs 的雏形），与 DC-Net 正交共存。

### 1.2 用户的开发主线（修正后）

原主线 "PGP F2F 信任 → XOR 路由 DC-Net" 修正为：

    PGP/WoT 身份信任（验签、BFS 信任路径）
            │  每个 F2F 好友边 = 线下建立的边密钥 (PSK)
            ▼
    DC-Net 组内匿名广播（边密钥派生 pairwise share，Blame 追责）
            │  消息内容保密性来自独立的 E2E 层
            ▼
    频道化 IRC 体验（#room = DC-Net 组；1:1 = Ratchet）

**核心设计决策：信任层的"边"直接变成 DC-Net 的密钥。**
每个 F2F 好友边携带一个线下建立的预共享密钥（扫二维码/对指纹确认），DC-Net 每轮 pairwise share 由 HKDF(edge_key, round_id, role_i, role_j) 派生。这样**完全不需要在线密钥交换**，天然免疫中间人——比临时 DH + 身份签名的方案更简单也更安全。在线建密钥仅作为未来的可选增强。

## 2. 分层架构与威胁模型

| 层 | 提供什么 | 不提供什么 | 对手假设 |
|----|----------|------------|----------|
| WoT 身份层 | 身份认证（防冒充）、信任路径 | 人际关系的隐私（签名图本身可见） | 主动攻击者可伪造签名 → 必须验签 |
| 边密钥 (F2F PSK) | pairwise 共享秘密的保密性 | 密钥更新（线下重协商） | MITM 在线攻击 → 线下建立免疫 |
| DC-Net 组广播 | **发送者匿名**（组内成员无法确定谁发的） | 消息保密性（明文对组内成员可见，保密性靠 E2E） | 组内恶意成员、全流量观察者 |
| E2E Ratchet | 保密性 + 完整性 + 前向安全 | 匿名性 | 记录密文的观察者 |
| 会话层 (session.rs) | 传输加密、防重放、防反射、防冒充（已知密钥） | 元数据隐私 | 被动+主动网络攻击者 |
| 传输层 | TCP 直连（Tor 可选） | 全局流量分析抵抗 | — |

**每个安全声明必须配一个攻击性测试**：例如"观察者用公开信息重算 pairwise 密钥必须失败"（2026-06 假 DH 的教训）。

## 3. 分阶段路线图

### P0 — 修根（信任层可信 + 工程基础）

1. **WoT 验签**：add_signature 必须用签名者公钥验签（subject_fp || trust_level || timestamp，域分离编码），伪造签名一律拒绝；计算信任时二次过滤未验签条目（防篡改持久化文件）。
2. **信任计算重写**：worklist 定点算法替代伪 BFS，规则 = min(签名者信任, 签名信任级别)，1 Full→Full、2 Marginal→Full、1 Marginal→Marginal；结果与查询顺序无关；修复 invalidate_cache 不清缓存的问题。
3. **信任口径统一**：F2F friend trust_level 固定 0..=2（UNVERIFIED/VERIFIED/FULL），Reputation 到信任的映射全项目用同一张表（≥0.8→2、≥0.5→1、否则 0）；删除 get_trust 的 +1。
4. **仓库卫生**：target/ 移出版本库（.gitignore 已有规则）、删除旧"墨竹"测试脚本与孤儿 Cargo.lock、commits.txt 等个人文件移除。
5. **CI**：cargo fmt --check + cargo clippy -D warnings + cargo test；rust-toolchain 固定版本。
6. **文档对齐**：SECURITY.md/README/help 与实现一致（删除已失效声明或标注"规划中"）。

### P1 — 边密钥 + 持久化接活

1. F2F 好友边新增 edge_key（32 字节 PSK），建立流程：双方展示指纹 → 线下确认 → 生成/导入密钥。
2. 边密钥派生规范：HKDF(edge_key, "chrono-dcnet-pair-v1" || round_id || min(peer) || max(peer))。
3. 把 WalStore 接入 AppState：好友/频道/信任变更先写 WAL 再改内存，启动时 replay；checkpoint 保持 tmp+fsync+rename 顺序。
4. 身份与边密钥文件 0600 + 启动时校验权限告警。

### P2 — DC-Net 轮次协议落地（核心）

1. round_network.rs 从死代码接活：参与者名单 = WoT 门控名单；share 用边密钥派生 + 签名认证；submit_share 校验 uid ∈ 名单、拒绝重复/超长份额。
2. 防脑裂修复：单一单调轮次计数器（mark_seen/next_round 口径统一），未来轮次超限拒绝。
3. Leader 轮换 + 踢人 failover：踢出当前 leader 自动改选（当前踢人后网络永久无主）。
4. 真 reputation/blame：传入真实 all/responded 名单（当前恒等映射）；dropout 惩罚回写 group（当前作用在 clone 上）。
5. 固定 payload 长度 + 长度前缀，消除 unpad 截断与尾部明文。
6. 攻击性测试：观察者重算密钥失败、冒充份额被拒、重复提交被拒、脑裂注入被拒。

### P3 — 频道化 + 私聊

1. /msg 走真实网络路径（当前只写内存）；频道消息 = DC-Net 轮次结果。✅
   - 实现：dcnet/round_driver.rs（mesh DC-Net 状态机）+ AppState 接线 +
     CLI 分发；双进程实测通过（认证加密会话上的 start→中性份额→末位消息份额，
     checksum 校验提取，冲突 uid 平局决胜 + 有界重试）。
   - 附带修复：REPL 轮询嵌套锁死锁、/nick 不更新 bridge uid、
     /connect 无重试、connect_to_peer 未接入入站队列。
2. 1:1 私聊接入 Ratchet：决策已定 ✅（实现见 P4 收尾）
   - **决策**：自研 ratchet 保持弃用（零接线、协议有已知缺陷）；1:1 私聊
     暂用本地 inbox，不提供任何"静默降级明文发送"路径；下一步优先评估
     vodozemac 或 matrix-sdk-crypto 作为经过审计的替代。
3. CLI 信任相关命令补齐（pgp 用户命令，README 已标"进行中"）。→ 移入 P4

### P4 — 扩展

1. 中继/mixnet ✅（2026-08 完成）：
   - RelayRequest/Response 增加 origin_key_hex + nonce + timestamp +
     hops_left + Ed25519 签名（签名不覆盖 hops_left，中继可递减）；
   - RelayVerifier：单调 nonce 防重放、±60s 新鲜度窗口、每发送者限速、
     TOFU 密钥固定（自携带密钥 + 首次固定 + 换钥拒绝）；
   - 直连消息用会话握手固定的密钥验签（更强）；中继消息用自携带密钥；
   - 真实转发路径：目标直连 → 直发，否则查 RelayRouter 路径转发，
     hops_left 防环；/relay send 命令；三节点实测通过
     （alice → carol 中继 → bob 收到 "relay from alice: 16 bytes"）。
   - 附带修复：会话层身份绑定误杀中继消息（originator ≠ session uid）；
     握手 TOFU 记录对端身份密钥（供 DC-Net 份额/中继验签）。
2. 可插拔传输 ✅（文档如实化）：docs/TRANSPORT.md 已标注 Tor/obfs4/
   WebTunnel 仅为配置层占位；真实接线留待后续版本决策。
3. 心跳/连接生命周期 ✅（2026-08 完成）：
   - 每连接出站队列改为 tokio 有界通道（256），满则 try_send 报错
     （背压替代无界内存增长）；
   - 写帧 15s 超时、读空闲 90s 超时（静默对端判定死亡并清理）；
   - 死连接清理：连接唯一 id，writer/reader 退出时仅移除自己的条目
     （同 uid 新连接不被误删）。
4. pgp CLI 命令 ✅（2026-08 完成）：
   - pgp me / import / sign / trust / list；密钥导入校验 64 hex、
     签名入库走 WoT 验签；信任等级+路径展示；wot.json 持久化（0600）；
   - 冒烟验证：import → sign(2) → trust 显示 Full (dcnet level 2)。

## 4. 工程规范

1. **文档即规格**：先改 PROTOCOL.md / 本文档，再改代码，最后让测试对齐文档。
2. **无占位代码**：任何声明"已实现"的特性必须可到达；否则删除代码并如实标注。死代码在安全项目里是负资产。
3. **安全清单**：密钥材料一律 zeroize；文件一律 0600；比较一律常量时间；外部输入一律长度校验；每个 panic 路径问一句"攻击者能触发吗"。
4. **测试标准**：每个安全属性一个攻击性测试；回归测试必须能复现修复前的缺陷。
5. **版本纪律**：版本号只在一处定义（Cargo.toml），其余（lib.rs/help/README）引用它。

## 5. 每阶段验收标准

- 全量 cargo test 通过；新增攻击性测试覆盖本阶段修复的缺陷；
- cargo clippy 无 error；新增代码 fmt 干净；
- 安全声明与实现一致（对照本文档第 2 节逐条核对）；
- 阶段结束时更新本文档状态与 CHANGELOG。
