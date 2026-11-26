# bs_unlock —— 自有卡密桥接（源码版）

替代 `com.bspath.core`（`bs_unlock.dylib`）的注入层，只用你自己的服务器做判定。

## 能力对照

| 能力 | 他那份 dylib | 这份源码 |
|---|---|---|
| 注入方式 | filter plist + TweakInject | 相同（`Executables` 匹配，不查 bundle id） |
| 授权投放 | dlsym 写 `g_agent_auth_state` / `g_agent_auth_valid_time` | 相同（已验证符号可见） |
| 卡槽写回 | 接管 `bs_card.txt` | 相同（每 tick 回写，抗 Agent 启动清零） |
| 判定来源 | 他服务器 `/hb` + `/api/client/login` | 你服务器 `/hb`（`code` / `expire` / `bindcard`） |
| 显示兜底 | 二进制改 5 处 + 运行时改 text | 可选，按 `vt_off` / `st_off` 打 `ret`，默认关闭 |
| 网络劫持 | interpose `connect` / `getaddrinfo` + fishhook | **不做**（不需要伪造连接，直接走你自己的 host） |
| 自动点击 / 看门狗 | `BSAutosvcHelper` + 自愈 | 未做（需要再加） |

关键差异：他必须劫持 `connect` 把 Agent 的私有通道伪装成“连接成功”，因为它没有真正的密钥应答。
你这边不需要——Agent 就算 `recv rep key failed` 超时，授权由 dlsym 直接写入，不看那条通道。

## 编译

```bat
set THEOS=C:\theos
make clean
make
```

产物：`.theos/obj/arm64e/bs_unlock.dylib`

签名（复用原包的 entitlements 最省事）：

```bat
ldid -S bs_unlock.ent.plist .theos\obj\arm64e\bs_unlock.dylib
```

## 安装

把 `bs_unlock.dylib` + `bs_unlock.plist` 放进手机 `/usr/lib/TweakInject/`，然后：

```sh
kill -9 $(lsof -n -P | grep BetaScree | awk '{print $2}' | sort -u)
uiopen --path /private/var/containers/Bundle/Application/.jbroot-8EEE3F01A712CE25/Applications/BetaScreenTYMDESUJCX8T.app
```

> 注意：如果原 `bs_unlock.dylib` 还在，会同时注入两份，必须先把他的删掉/改名。

## 配置（`/var/mobile/Media/bs_pull.conf`）

```ini
host=192.168.1.18      # 你的服务器
port=38471
prj=sjz
tick=60                # 心跳周期（秒）
devid=2105b41f0bb3916bca7a82aa78969d90
cardval=SNAILxxxxxxxx  # 兜底卡（服务器没回 bindcard 时用）
vt_off=0               # 可选：getter 偏移（十六进制），0=不打补丁
st_off=0
```

日志：`/var/mobile/Media/bs_bridge.log`

## 服务器契约（`/hb`）

```json
{
  "ok": true, "code": 0, "expire": 1827241100,
  "bindcard": "SNAILFMNRT54UM4P5HX266A3RLGT",
  "devid": "2105b41f...", "prj": "sjz", "prj_ver": "030201"
}
```

`code` 语义（与现有判定链一致）：

| code | 含义 | 插件行为 |
|---|---|---|
| 0 | 授权有效 | 写卡槽 + `auth=1` + 写入期 |
| 3 | 已过期 | 写卡槽（保留时间给中控显示）+ `auth=0` |
| 401 / 其他 | 拒绝 | `auth=0` |

## 回滚

```sh
rm -f /usr/lib/TweakInject/bs_unlock.dylib /usr/lib/TweakInject/bs_unlock.plist
cp /var/mobile/Media/bs_pull.conf.bak_zos /var/mobile/Media/bs_pull.conf
kill -9 $(lsof -n -P | grep BetaScree | awk '{print $2}' | sort -u)
uiopen --path /private/var/containers/Bundle/Application/.jbroot-8EEE3F01A712CE25/Applications/BetaScreenTYMDESUJCX8T.app
```

## 已知边界

- 符号如果哪天被 strip，`dlsym` 拿不到，就只能靠 `vt_off` / `st_off` 偏移打补丁。偏移要随 Agent 版本更新。
- 到期是**秒精度**，中控那列显示的分钟可能和卡里的整数差 1 分钟，属正常。
- 这份不碰 `beta.so` 下载/解密——那部分照旧走 `/ver` + `/key` + `/script/beta.so`，Agent 自己完成。
