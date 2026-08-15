# Git 历史清理 + v8.1 合流操作手册

> 生成日期: 2026-08-15 · 状态: ✅ 已执行（用户决策：历史全部抹去，仅保留单一 v0.0.8.2 初始提交（后续开发至 v0.0.8.3））

## 执行结果（2026-08-15）

- 合流：v8.1 daemon 架构 + P0-P4 安全移植（真 X25519 会话、边密钥份额、
  WoT 定点信任、中继加固、WAL 接线、连接生命周期），142/142 测试、clippy 0。
- 历史重置：单一初始提交 8af1113 + 标签 v0.0.8.2；.git 从 357MB → 648KB。
- 敏感清理：data/（真实私钥）、target/、commits.txt、旧 tests/ 脚本、
  .claude/settings.local.json、QQ 邮箱历史、个人情感提交信息 —— 全部消失。
- 备份：chrono-backup-pre-clean.bundle（373MB，含完整旧历史，.gitignore 已忽略；
  确认推送成功后可以删除）。

## 0. 现状（已勘察核实）

- 本地 main = b27371b (v7.6)；远端 origin/main = e58cc3a (v8.1)，15 个提交，
  已在本机 fetch 成功（`git pull` 的 fetch 阶段已完成，merge 被本地未提交改动挡住）。
- 本会话的 P0-P4 路线图工作已安全提交到分支 `local/roadmap-p0-p4`（6afbe11）。
- 全量备份 bundle：`chrono-backup-pre-clean.bundle`（373MB，含全部提交与引用），
  任何一步出错都可以 `git clone chrono-backup-pre-clean.bundle restored/` 恢复。
- 沙箱无法访问远端（无 SSH agent / 私有仓库）：fetch/push 需在用户本机执行。

## 1. 紧急问题（已确认）

| # | 问题 | 证据 |
|---|------|------|
| 1 | **真实私钥入库**：data/keys/identity.json 被提交进 origin/main 历史 | ls-tree 确认 |
| 2 | 会话密钥 = HKDF(双方公钥)，公开可算（假加密） | handshake.rs:120-121 |
| 3 | 数据路径仍是明文 JSON（握手未接线） | connection_manager.rs:289 from_json |
| 4 | DC-Net 份额 SHA-256(公开信息)，匿名性数学上失效 | round_network.rs:151 |
| 5 | 165 个提交使用 QQ 邮箱；84 个提交信息含个人情感内容 | git log 统计 |
| 6 | target/ 等 356MB 构建产物仍在历史中 | pack 大小 |

## 2. v8.1 已自行修复（与我 P0-P4 重叠，合流时跳过）

- WoT 验签入库（web_of_trust.rs）
- identity 0600 权限
- WAL checkpoint tmp+rename
- 审计 CRIT-1~6、IPv6、协议过滤、Web 控制台、daemon 化（v8.0/v8.1 新功能）

## 3. 合流计划：以 v8.1 为基线，移植我这边 v8.1 缺失的修复

待移植（v8.1 缺失）：
1. session.rs 真 X25519 临时 DH + 方向密钥 + 防重放 → 替换 handshake.rs 的
   公钥派生密钥，并接入 connection_manager 数据路径（消除明文 JSON）；
2. 边密钥 EdgeKey + derive_pair_share + compute_xor_share_secure → 替换
   round_engine 使用的公开份额（P2 核心）；
3. round_driver.rs mesh 轮次（末位消息份额 + 冲突平局决胜）——与 v8.1 的
   RoundEngine（leader 收集模式）二选一或融合【决策点】；
4. WoT 定点信任计算（v8.1 仍是顺序相关的 bfs_trust）；
5. 中继加固全套（签名/nonce/过期/限速/TOFU/防环/转发）；
6. REPL 嵌套锁死锁修复、/nick bridge uid 同步、/connect 重试与入站队列接线、
   连接生命周期（有界队列/超时/清理）；
7. 关机自死锁修复（pump 自持发送端）；ratchet 决策文档。

## 4. 历史清理步骤（在最终合流历史上执行）

工具：git-filter-repo 未安装且沙箱无网络；本机可用 pip 安装，
或使用内置 filter-branch（较慢但零依赖）。以下给出两种命令。

### 4.1 删除文件路径（所有历史）

```bash
# filter-repo (推荐, 本机先: pip install git-filter-repo)
git filter-repo --invert-paths \
  --path client/security/rust_core/target \
  --path client/security/target \
  --path data \
  --path commits.txt \
  --path client/vendor \
  --path security_report_20260504_234142.txt \
  --path security_report_20260504_H4142.json \
  --path .claude/settings.local.json \
  --path client/security/Cargo.lock \
  --path tests/
```

### 4.2 作者邮箱重写（mailmap 或 --mailmap）

1403679822@qq.com → <待用户确认的 proton.me 地址>

### 4.3 提交信息清洗（--replace-message / msg-filter）

含 'Александра' / '我喜欢' / 表白 等字样的 84 条提交信息 → 中性文本
（如 'chore: 清理历史提交信息'）。注意：内容只改信息不改代码，
提交哈希会变（这是预期的）。

### 4.4 校验

```bash
git log --all --format='%ae' | sort -u   # 只剩目标邮箱
git log --all --format='%s' | grep -ciE 'Александра|表白'   # 应为 0
git ls-tree -r HEAD --name-only | grep -E 'data/|target/'    # 应为空
git count-objects -vH    # pack 应远小于 356MB
git gc --prune=now --aggressive
```

## 5. 双远端推送（用户本机执行）

```bash
# 先推 GitHub 私有仓库（force：历史已被重写）
git remote set-url origin git@github.com:fantuanmtf/Chrono-shift.git
git push --force --tags origin main

# 再推 Codeberg（同一份清理后的历史）
git remote add codeberg git@codeberg.org:haiyanfurry-mtf/Chrono-shift.git
git push --force --tags codeberg main
```

注意：若其他机器还有旧克隆，重写后它们必须重新 clone（不要再 pull）。

## 6. 需要你确认的决策清单

1. 合流方向：以 v8.1 为基线移植 P0-P4 修复？（推荐）
2. 轮次协议：v8.1 RoundEngine（leader 收集）与 mesh RoundDriver 二选一或融合？
3. 替换邮箱：proton.me 完整地址（用于 mailmap 重写 165 个提交）？
4. 84 条个人信息提交：改写为中性信息（推荐）还是其他处理？
5. Codeberg 仓库地址：git@codeberg.org:haiyanfurry-mtf/Chrono-shift.git 对吗？
6. data/ 与 tests/ 旧脚本：整段从历史删除（推荐，data 含真实私钥）？
7. 清理范围确认后，是否由我在本会话执行 filter 重写（无网络依赖），
   推送由你在本机完成？
