# Parental Control (grant-based, v2)

> 本文档解释 v2 起的家长控制模型——**按需授权**取代固定时间表。设计动因
> 见 [phase6-parental-control.md](phase6-parental-control.md)（历史版本，已停用 schedule 部分）。

---

## 1. 模型一句话

每台儿童设备声明两类 blocklist，每次域名请求按下面这张表判断：

| 设备类别 | 域名命中 hard 类 | 域名命中 grantable 类 + 无有效授权 | 域名命中 grantable 类 + 有有效授权 | 其它 |
| --- | --- | --- | --- | --- |
| Adult | 允许 | 允许 | 允许 | 允许 |
| Child | **封锁**（grant 也无法解锁） | **封锁** | 允许 | 允许 |
| Unknown | 由 `[parental].default_policy` 决定 | 同 | 同 | 同 |

> 全局黑名单和全局类别（`[parental].global_categories`）在最前面拦截，对所有设备生效。

---

## 2. 数据存哪里

```
┌──────────────────────────────────────────────────────────────────┐
│                        config/                                    │
├──────────────────────────────────────────────────────────────────┤
│  homeguard.toml          ← 基础设施 + 设备首启动种子                │
│  rules.list, rules/      ← 路由规则（与家长控制无关）              │
│  blocklists/             ← 文件型，按 category 组织                │
│      categories/         │                                         │
│        porn.list         ├─ 一行一个域名，# 注释                   │
│        games.list        │                                         │
│        social.list       │                                         │
│                          │                                         │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│             SQLite: /var/lib/homeguard/config.db                  │
├──────────────────────────────────────────────────────────────────┤
│  devices                                                          │
│    id, name, ip, mac, device_type                                 │
│                                                                   │
│  device_blocklists                  ← 设备 ⇄ 类别 + 模式           │
│    device_id, category, mode (hard | grantable)                   │
│                                                                   │
│  grants                              ← 本次改造的主角                │
│    id, device_id, category,                                       │
│    granted_at, expires_at, revoked_at, note                       │
└──────────────────────────────────────────────────────────────────┘
```

- **blocklist 文件内容**改一改就生效（restart 服务即可加载）。
- **devices / device_blocklists** 第一次启动从 `homeguard.toml [devices.*]`
  seed 进 DB，之后 SQL 改动是权威。
- **grants** 全程靠 SQL 操作，没有 TOML 镜像。

---

## 3. 家长操作 cookbook

预设 alias 让命令更短（追加进 `~/.zshrc`）：

```bash
export HG_DB=/var/lib/homeguard/config.db
alias hg-sql='sudo sqlite3 -header -column $HG_DB'

# 开 1 小时游戏
hg-grant() {
  sudo sqlite3 $HG_DB "INSERT INTO grants (device_id, category, expires_at, note)
    VALUES ('$1', '$2', datetime('now', '+$3'), $(printf %q "${4:-}"));"
}
# usage: hg-grant child_ipad games '1 hour' "homework done"
```

直接 SQL（不用 alias）：

```bash
DB=/var/lib/homeguard/config.db

# === 发授权 ===
# 开 1 小时游戏
sqlite3 $DB "INSERT INTO grants (device_id, category, expires_at)
             VALUES ('child_ipad', 'games', datetime('now', '+1 hour'));"

# 开 30 分钟社交，并写备注
sqlite3 $DB "INSERT INTO grants (device_id, category, expires_at, note)
             VALUES ('child_ipad', 'social', datetime('now', '+30 minutes'),
                     'after dinner break');"

# === 查看 ===
# 当前生效的所有授权
sqlite3 -header -column $DB "SELECT id, device_id, category,
       datetime(granted_at, 'localtime') AS granted,
       datetime(expires_at, 'localtime') AS expires
   FROM grants
   WHERE revoked_at IS NULL AND expires_at > datetime('now')
   ORDER BY expires_at;"

# 历史审计（最近 20 条，含已过期/已撤销）
sqlite3 -header -column $DB "SELECT id, device_id, category,
       datetime(granted_at, 'localtime') AS granted,
       datetime(expires_at, 'localtime') AS expires,
       datetime(revoked_at, 'localtime') AS revoked,
       note
   FROM grants ORDER BY granted_at DESC LIMIT 20;"

# === 撤销 ===
# 立刻收回 grant #42
sqlite3 $DB "UPDATE grants SET revoked_at = datetime('now') WHERE id = 42;"

# 收回某设备的所有有效授权
sqlite3 $DB "UPDATE grants SET revoked_at = datetime('now')
             WHERE device_id = 'child_ipad'
               AND revoked_at IS NULL
               AND expires_at > datetime('now');"
```

### 时间窗语法

`expires_at` 接受任何 SQLite [datetime modifier](https://www.sqlite.org/lang_datefunc.html#modifiers)：

| 写法 | 含义 |
| --- | --- |
| `datetime('now', '+1 hour')` | 1 小时后 |
| `datetime('now', '+90 minutes')` | 1 小时 30 分后 |
| `datetime('now', '+1 day')` | 24 小时后 |
| `datetime('now', '+1 day', 'start of day')` | 到今天结束（午夜） |
| `'2026-05-17 22:00:00'` | UTC 字面量 |
| `datetime('2026-05-17 22:00', 'utc')` | 显式 UTC |

**所有时间一律 UTC** 存（SQLite 默认）；上面查询里 `datetime(..., 'localtime')`
是为了显示成本地时间，不影响存储。

---

## 4. 生效延迟（5 秒）

HomeGuard 在内存缓存生效中的授权，每 5 秒从 SQLite 刷新一次（[src/control/grant.rs](../src/control/grant.rs)）。
所以：

- 你 INSERT 的 grant **最长等 5 秒**孩子设备就能访问。
- 你 UPDATE 设 `revoked_at` 或者授权自然过期，**最长 5 秒**会重新封锁。
- 同一 (device, category) 重复发 grant 时取**最晚的 expires_at**，可以叠加延长。

不需要重启服务、不需要发信号、不需要 reload。

---

## 5. 设备管理（v2 之后）

首次启动会把 `[devices.*]` seed 进 DB；之后 TOML 改动**被忽略**（日志会 warn）。改动用 SQL：

```bash
DB=/var/lib/homeguard/config.db

# 加新设备
sqlite3 $DB "INSERT INTO devices (id, name, ip, mac, device_type)
             VALUES ('kid2_ipad', 'Kid 2 iPad', '192.168.0.51',
                     'BB:CC:DD:EE:FF:00', 'child');"

# 给设备加 hard 类
sqlite3 $DB "INSERT INTO device_blocklists (device_id, category, mode)
             VALUES ('kid2_ipad', 'porn', 'hard'),
                    ('kid2_ipad', 'violence', 'hard');"

# 给设备加 grantable 类
sqlite3 $DB "INSERT INTO device_blocklists (device_id, category, mode)
             VALUES ('kid2_ipad', 'games', 'grantable'),
                    ('kid2_ipad', 'social', 'grantable');"

# 把某 category 从 grantable 改成 hard（升级管控）
sqlite3 $DB "INSERT INTO device_blocklists (device_id, category, mode)
             VALUES ('child_ipad', 'social', 'hard')
             ON CONFLICT(device_id, category) DO UPDATE SET mode = 'hard';"

# 移除设备（连带 device_blocklists + grants 级联删除）
sqlite3 $DB "DELETE FROM devices WHERE id = 'kid2_ipad';"

# 改 IP（DHCP 保留地址换了的话）
sqlite3 $DB "UPDATE devices SET ip = '192.168.0.55',
                                updated_at = datetime('now')
             WHERE id = 'child_ipad';"
```

设备改完后需要**重启服务**让 `DeviceManager` 重新加载（grants 是热加载的，但设备列表只在启动时读一次）：

```bash
sudo launchctl kickstart -k system/com.homeguard
```

---

## 6. Blocklist 文件的语法

`config/blocklists/categories/<name>.list`，一行一条，`#` 注释：

```text
# games.list — domains the kid can't reach without an active grant
*.steam.com
*.epicgames.com
.roblox.com
fortnite.com
```

格式：

- 纯文本，UTF-8
- `*.domain.com` / `.domain.com` 都解读为 suffix 匹配（含子域名）
- 没有前缀 = 精确匹配
- 空行 + `#` 开头的注释行被跳过

Blocklist 文件改动后**重启服务**生效。

---

## 7. 故障排查

### "我发了 grant 但孩子说还是访问不了"

```bash
# 1. 确认 grant 真的写进去了
sqlite3 -header -column $HG_DB \
  "SELECT * FROM grants WHERE device_id='child_ipad' ORDER BY granted_at DESC LIMIT 5;"

# 2. 确认 device_id 对得上孩子设备的 IP
sqlite3 -header -column $HG_DB \
  "SELECT id, name, ip FROM devices;"
# 然后在孩子设备上看真实 IP，比对

# 3. 等 5 秒后再试（缓存刷新窗口）
sleep 6

# 4. 确认目标域名确实在 grantable 类别下，而不是 hard 类别（hard 永远拦）
sqlite3 -header -column $HG_DB \
  "SELECT * FROM device_blocklists WHERE device_id='child_ipad';"
# 看 mode 列，'hard' 的 grant 没用

# 5. 看 homeguard 日志
sudo tail -f /var/log/homeguard/homeguard.log
# DNS 阶段会看到 'Active grant unblocks ...' 或 'grantable:games'
```

### "孩子设备完全没被识别（按 unknown 处理了）"

```bash
# DHCP 是不是给了别的 IP？
# 在孩子设备上看当前 IP，再比对：
sqlite3 $HG_DB "SELECT id, ip FROM devices WHERE id='child_ipad';"
# 不一致的话 UPDATE 或者把孩子设备的 DHCP 保留 IP 改回来
```

### "想清空所有过期 grant 让 DB 不要膨胀"

定期清理脚本（cron）：

```bash
# 删除 30 天前的 revoked 或 expired 行
sqlite3 $HG_DB \
  "DELETE FROM grants
   WHERE (revoked_at IS NOT NULL AND revoked_at < datetime('now', '-30 days'))
      OR (expires_at < datetime('now', '-30 days'));"
```

不删也无害——`grants` 表上有 partial index 只覆盖 active 行，hot path 查询不会变慢。

---

## 8. 与之前 schedule 模型的对照

| 之前（v1）                  | 现在（v2）                       |
| --------------------------- | -------------------------------- |
| `[schedules.school_hours]` 固定窗口 | 无（schedule 模型已移除）       |
| `device.schedules = [...]`         | 无                                |
| `device.extra_blocklists = [...]`  | `hard_blocklists` + `grantable_blocklists` 二分 |
| 窗口 == "封锁时间"                  | grant == "解锁时间窗"             |
| 改窗口要编辑 TOML + restart        | 发 grant 用 SQL，5 秒生效         |

`[schedules.*]` 配置项写在 `homeguard.toml` 里现在会被忽略；旧 `extra_blocklists`
会被当成 grantable 处理并打 warn（首次启动 seed 时）。
