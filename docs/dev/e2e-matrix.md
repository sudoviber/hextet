# E2E 真机验收矩阵

记录 `docs/guides/quickstart.md` 在真实公网 IPv6 双端上的手动验收结果（补充 CI
netns E2E——netns 模拟的是本地 veth"公网"，无法覆盖真实 ISP/光猫/防火墙路径）。

| 日期 | 场景 | 结果 |
|---|---|---|

CI 的 netns 场景（static / dynamic / doctor）不进本表——本表只记录**真实**
公网 IPv6 双端的手动验收。M2 起需要额外手动验证的项：真实家宽 PPPoE 重拨
（或手动 `ip -6 addr` 换址）后 `hextet status` 在 5s 内恢复 connected。
