# Chrono-shift v0.0.8.3 通信协议文档

## 分层

```text
应用层:  DC-Net 轮次消息 (DcRoundStart/Share/Result/Sync) + 中继 + 保活
   ↓
会话层: X25519 临时 DH 握手 + Ed25519 身份验签 → AES-256-GCM 帧
   ↓
传输层: TCP (IPv6 双栈, IPv4 回退)
```

## 1. 会话握手 (net/session.rs)

```text
发起方 → AuthChallenge { from_uid, public_key_hex, eph_pub_hex, nonce,
                          signature = Sign(eph_pub || nonce) }
接收方 → AuthResponse { from_uid, public_key_hex, eph_pub_hex,
                         signature = Sign(chal_eph || resp_eph || nonce) }
会话密钥 = HKDF(X25519(eph_sec_i, eph_pub_r), salt = 排序后的双公钥)
方向密钥 = HKDF(session, "chrono-dir-a"/"chrono-dir-b")  ← 防反射
帧格式   = [4字节长度][AES-256-GCM(nonce || 8字节序号 || 明文)]  ← 防重放
```

- 已知密钥节点: 验签失败即拒绝连接（防冒充）；
- 未知节点: 加密但不认证，密钥 TOFU 记录供后续消息验签；
- 握手明文帧超时 10s，数据帧读空闲 90s、写 15s 超时断开。

## 2. DC-Net 轮次 (round_engine.rs + round_network.rs)

```text
1. Leader 广播 DcRoundStart { channel, round_id, leader_id, participants,
   deadline_secs, payload_len }
2. 每个参与者计算份额 (边密钥 PSK 派生, HKDF) 并回传 DcRoundShare
   { channel, round_id, peer_uid, xored_payload, signature }
   —— 份额签名 = Ed25519(channel || round_id || share)
3. Leader 收集 (成员校验/去重/长度校验) → XOR 提取
4. Leader 广播 DcRoundResult { extracted_message, leader_signature }
```

- 消息帧 = [4字节长度][SHA-256 校验和][消息][零填充]——提取必须通过校验和，
  碰撞/损坏结果被丢弃；
- round_id 单一单调计数器，只接受恰好 +1（防脑裂注入）；
- 参与者断线重连：RoundSyncRequest/Response 仅交换承诺哈希，不泄露份额；
- 每轮允许一个参与者嵌入消息（多发送者碰撞由校验和检测并丢弃）。

## 3. 中继 (relay.rs)

```text
RelayRequest { from_uid, to_uid, origin_key_hex, nonce, timestamp,
               hops_left, signature, encrypted_payload }
签名 = Ed25519(域分隔 || from || to || nonce || timestamp || payload)
        (hops_left 不参与签名, 中继可递减)
```

- 准入：每发送者单调 nonce（防重放）、±60s 时间窗（防过期注入）、
  每窗口限速（防放大）；
- 验签密钥：直连消息用会话握手固定密钥；转来消息用自携带密钥 + TOFU 固定；
- 转发：目标直连 → 直发；否则查 RelayRouter 路径；hops_left 归零丢弃（防环）。

## 4. 身份与信任 (pgp/)

- PgpIdentity = { user_id, public_key_hex, fingerprint, created }；
- TrustSignature 域分离签名，入库必验签；
- 信任 = worklist 定点：min(签名者信任, 签名级别)，1 Full→Full、
  2 Marginal→Full，与查询顺序无关；缓存失效即清空。
