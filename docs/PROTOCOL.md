# Chrono-shift v7.7.1 通信协议文档

## 加密层次

```
应用层: DC-Net XOR 广播 (信息论安全匿名)
   ↓
会话层: Double Ratchet E2E (前向安全)
   ↓
传输层: AES-256-GCM (认证加密，可选)
   ↓
网络层: TCP P2P 直连 (tokio async)
```

---

## 1. DC-Net 匿名层

### 原理 (Dissent 变种)

DC-Net 提供**信息论安全**匿名——即使攻击者监控全网通信，也无法确定发送者。

```
3 个参与者 (A, B, C):

1. 密钥共享: SHA-256(round_id || peer_i || peer_j)
   (确定性派生，双方独立计算相同值)

2. A 想发送消息 M:
   A 输出: M ⊕ share_AB ⊕ share_CA
   B 输出: share_AB ⊕ share_BC       (无消息)
   C 输出: share_BC ⊕ share_CA       (无消息)

3. 全局 XOR 提取消息:
   (M ⊕ AB ⊕ CA) ⊕ (AB ⊕ BC) ⊕ (BC ⊕ CA) = M

4. 所有共享密钥消去，仅剩 M
```

### 分布式轮次协议 (v7.7.1)

```
Phase 1 — 轮次启动:
  Leader → 所有成员: DcRoundStart { channel, round_id, participants, payload_len, deadline }

Phase 2 — 份额计算 (本地):
  每个参与者独立计算: pairwise_share = SHA-256(round_id || peer_a || peer_b)
  发送者: output = message XOR 所有 pairwise_shares
  非发送者: output = 所有 pairwise_shares (无消息嵌入)

Phase 3 — 份额提交:
  每个成员 → Leader: DcRoundShare { channel, round_id, peer_uid, xored_payload }

Phase 4 — 消息提取 (Leader):
  global_xor = XOR of all received shares
  Unpad → 提取原始消息

Phase 5 — 结果分发:
  Leader → 所有成员: DcRoundResult { channel, round_id, extracted_message, leader_signature }
```

### 防脑裂 (Split-Brain Prevention)

```
- round_id 单调递增
- 所有节点记录 last_seen_round_id
- 拒绝 round_id < last_seen_round_id 的消息
- Leader 变更时 round_id 递增，旧 Leader 的消息自动失效
```

### 轮次状态机

```
Collecting → Broadcasting → Complete
    │                          │
    └────────→ Failed ←────────┘
           (超时 30s / 掉线超过阈值)
```

---

## 2. 可验证洗牌 (Dissent Protocol)

```
Phase 1 — Commit:
  Leader 发布 N 个空槽位
  每个参与者: 选随机槽位 → AES-256-GCM 加密 → SHA-256(明文) 承诺

Phase 2 — Reveal:
  Leader 发布解密密钥
  参与者揭示消息

Phase 3 — Verify:
  恒定时间比较: SHA-256(揭示) == 承诺
  不匹配 → BlameProtocol 追责 (Offline / Cheating / Clean)
```

---

## 3. Double Ratchet E2E

```
DH Ratchet: X25519 ECDH → 新根密钥
Symmetric Ratchet: HKDF-SHA256 → 链密钥 → 消息密钥 (AES-256-GCM)

每条消息: 独立 nonce, 独立消息密钥, 链哈希防篡改
重放保护: msg_idx 单调递增
```

---

## 4. PeerMessage 协议 (20 种消息类型)

### 好友
```
FriendRequest  { from_uid, greeting }
FriendAccept   { from_uid }
```

### DC-Net 轮次
```
DcRound        { channel, round_id, xored_payload }         (旧格式)
DcRoundStart   { channel, round_id, leader_id, participants, deadline_secs, payload_len }
DcRoundShare   { channel, round_id, peer_uid, xored_payload }
DcRoundResult  { channel, round_id, extracted_message, leader_signature }
LeaderChange   { network, new_leader, reason, round_id }
```

### 群组管理
```
NetworkInvite       { from_uid, network_name, pgp_fingerprint, signature }
NetworkJoinRequest  { from_uid, network_name, pgp_fingerprint, signature }
NetworkJoinAccept   { from_uid, network_name, member_list, signature }
NetworkKick         { from_uid, network_name, kicked_uid, reason, signature }
NetworkSync         { from_uid, network_name, members, topic, round_id, signature }
```

### 认证/中继/保活
```
AuthChallenge  { from_uid, public_key_hex, nonce }
AuthResponse   { from_uid, public_key_hex, signature }
RelayRequest   { from_uid, to_uid, encrypted_payload }
RelayResponse  { from_uid, to_uid, encrypted_payload }
Ping / Pong    { ts }
ChannelMessage { channel, from_uid, text }
```

### TCP 帧格式
```
[4 bytes BE length] [JSON payload] [padding to 1024 bytes]
```

---

## 5. Web of Trust

### 信任级别
```
Never (-1) → Unknown (0) → Marginal (1) → Full (2) → Ultimate (3)
```

### DC-Net 权限映射
| 级别 | 权限 |
|------|------|
| Never | 完全排除 |
| Unknown | 只能接收 |
| Marginal | 可发言 |
| Full | 发言 + 中继 |
| Ultimate | 管理员/Leader |

### 信任计算
```
BFS 从自己的密钥出发，沿签名图遍历:
- 直接签名 → Full
- 1 个 Full 签名者签名 → Full
- 2 个 Marginal 签名者签名 → Full
- 1 个 Marginal 签名者 → Marginal
- 无签名 → Unknown
```

---

## 6. 传输层

### 可插拔传输
- **Direct**: 直连 TCP (默认)
- **Tor**: SOCKS5 代理 (127.0.0.1:9050)
- **Obfs4**: obfs4 桥接 + Tor
- **WebTunnel**: WebTunnel 桥接

### TCP 连接模型 (P2P)
```
每个节点:
  - 监听 TCP 端口 (默认 9000)
  - per-connection writer task (tokio::spawn)
  - per-connection reader task (tokio::spawn)
  - mpsc channel: CLI → 网络任务
  - UDP LAN 发现 (端口 9901, 30s 间隔)
```

---

## 7. 相关源文件

| 文件 | 功能 |
|------|------|
| `src/dcnet/mod.rs` | DC-Net 核心类型 + XOR |
| `src/dcnet/round.rs` | 轮次状态机 |
| `src/dcnet/round_network.rs` | 分布式轮次协调 (TCP) |
| `src/dcnet/group.rs` | 群组管理 |
| `src/dcnet/shuffle.rs` | 可验证洗牌 + Blame |
| `src/dcnet/reputation.rs` | 信誉评分 |
| `src/dcnet/f2f.rs` | F2F 信任网桥 |
| `src/dcnet/network.rs` | DcNetwork 群组抽象 |
| `src/pgp/mod.rs` | 信任级别 + PGP 身份 |
| `src/pgp/web_of_trust.rs` | Web of Trust (BFS) |
| `src/net/tcp.rs` | TCP 帧 + PeerMessage |
| `src/net/connection_manager.rs` | P2P 连接池 |
| `src/net/transport.rs` | 可插拔传输层 |
| `src/ratchet.rs` | Double Ratchet E2E |
| `src/crypto.rs` | AES-256-GCM |
| `src/storage.rs` | WAL 持久化 |
