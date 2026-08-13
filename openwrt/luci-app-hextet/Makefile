# luci-app-hextet —— hextet 的 LuCI 最小骨架
#
# 只做「状态/概览」：一个菜单项 + 一个只读视图（显示 uci 里的 enabled/config_file/
# verbose）+ 一条 rpcd ACL（允许 LuCI 读 hextet 的 uci 配置）。
# 它不驱动 daemon、也不编辑 hextet.toml——那是 M5 内嵌 Web UI 的事（见 spec §8）。
# 不依赖任何前端构建工具链，就是一个静态 JS 视图。

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-hextet
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=Apache-2.0

LUCI_TITLE:=hextet — IPv6-only serverless mesh VPN
LUCI_DEPENDS:=+hextet
LUCI_PKGARCH:=all

# luci.mk 提供 LuCI 应用的构建/安装（自动装 htdocs/、root/ 等目录）。
# 默认假设 luci feed 已 checkout 到 $(TOPDIR)/feeds/luci。若布局不同，
# 改成指向 luci 的 luci.mk（同 feed 内通常是 `include ../../luci.mk`）。
include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
