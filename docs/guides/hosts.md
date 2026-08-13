# 按名访问（MagicDNS-lite）

`hextet hosts` 把配置里的 **peer 名**映射到 overlay IPv6 地址，输出一行行标准 hosts
记录，让你 `ping nas` / `ssh nas` 就能访问对端，而不必背 `fdxx:...` 地址。

这是 Tailscale「MagicDNS」的 lite 版：**不做真 DNS 解析器**，只生成静态 hosts 行
（交给系统 `/etc/hosts` 或你自己的脚本去用）。

## 用法

```console
$ hextet hosts [-c <config>] [--out <path>]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-c` / `--config` | `hextet.toml` | 配置文件路径 |
| `--out <path>` | （stdout） | 写到文件（临时文件 → fsync → rename 的原子替换，权限 0644）；缺省打印到 stdout |

输出每行格式（字段之间两个空格）：

```
<overlay_ipv6>  <peer名>  <peer名>.hextet
```

例：

```
fd12:3456:78:abcd::2  nas  nas.hextet
fd12:3456:78:abcd::3  lab  lab.hextet
```

每个 peer 除了 `<peer名>` 还有一个 `<peer名>.hextet` 别名，指向同一个 overlay 地址，
方便一眼看出「这是 hextet 生成的主机名」。

## 名字是怎么被改写的（净化规则）

peer 名可能带大写、空格、下划线甚至别的字符，不能直接进 hosts。hextet 把它净化为
合法主机名（只保留 `[a-z0-9-]`），按顺序执行：

1. 全部转小写；
2. 只保留 `a-z`、`0-9`，其余字符一律映射成 `-`；
3. 连续多个 `-` 折叠成一个；
4. 去掉首尾的 `-`。

净化之后还有三条策略：

- **空名字 → 跳过**：净化为空的 peer 不生成 hosts 行，并往 stderr 打一条 warn；
- **超过 63 字符 → 截断**：截到 63 个字符（再 trim 掉尾部的 `-`）；
- **撞名 → 确定性加后缀**：两个 peer 净化后同名时，后面的依次加 `-2`、`-3` 后缀，
  绝不静默覆盖。

例：

| 原始 peer 名 | 净化结果 |
|---|---|
| `My NAS` | `my-nas` |
| `UPPER_case.123` | `upper-case-123` |
| `a--b` | `a-b` |
| `-foo-` | `foo` |
| `___` | （空，跳过） |

撞名示例：`My NAS`、`My_NAS`、`my-nas` 三个 peer 会依次得到
`my-nas`、`my-nas-2`、`my-nas-3`。

这些跳过/截断/撞名的 warn **都写到 stderr**，stdout 只输出干净的 hosts 行——这样
`sudo tee -a /etc/hosts` 直接吃 stdout 也不会把日志写进系统 hosts 文件。

## 示例

打印到屏幕：

```console
$ hextet hosts -c hextet.toml
fd12:3456:78:abcd::2  nas  nas.hextet
```

写到文件（原子替换，0644）：

```console
$ hextet hosts -c hextet.toml --out /tmp/hextet.hosts
```

追加进系统 hosts（stdout 是纯 hosts 行，可以直接重定向）：

```console
$ sudo sh -c 'hextet hosts -c /etc/hextet/hextet.toml >> /etc/hosts'
# 或
$ hextet hosts -c /etc/hextet/hextet.toml | sudo tee -a /etc/hosts
```

## 诚实的边界

- **只映射 peer 名，不含本机**：`hextet hosts` 只输出 `[[peers]]` 里的对端；本节点
  自己的「名 → overlay 地址」不在此列（需要从身份推导本机地址，尚未实现，没有
  `--self` 之类的标志）。要 ping 自己，用 `hextet inspect` 看本机 overlay 地址。
- **是静态 hosts，不是真 DNS 解析器**：它只做一次性文本生成。新增/改名 peer 之后要
  重新跑一次；不会自动更新、不做通配符、不解析子网。
- **IPv6-only**：hextet 配置里本就没有 IPv4，hosts 行只有 IPv6 地址，没有任何 IPv4
  兼容处理。
- **子网路由不在这里**：hosts 只给每个 peer 的 overlay `/128` 地址；要让 peer 背后
  的子网可达，见 [site-to-site](site-to-site.md)。

## 参考

- 查看连接状态与 HTTP 状态服务：`docs/guides/status.md`
- 子网路由：`docs/guides/site-to-site.md`
- 实现计划：`docs/superpowers/plans/2026-08-12-m6-windows-and-release.md`（切片 A）
