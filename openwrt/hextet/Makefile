# hextet — IPv6-only serverless mesh VPN (OpenWrt package)
#
# 这只是打包层：真正的 Rust 编译在 OpenWrt 构建主机上用它的交叉工具链完成，
# 产物是 crates/cli 的 `hextet` 二进制（`hextet daemon` 由 procd 拉起）。
#
# 本 Makefile 遵循 OpenWrt rust 包惯例（openwrt/packages 的 lang/rust/rust-package.mk）：
#   - PKG_BUILD_DEPENDS:=rust/host   —— 依赖 rust host 工具链（含 cargo）
#   - rust-package.mk 提供 CARGO_VARS（内含 CARGO_HOME / RUSTFLAGS / 交叉 linker），
#     以及 RUSTC_TARGET_ARCH（如 aarch64-unknown-linux-musl），cargo 据此交叉编译。
#
# 在 macOS 上无法用真实 OpenWrt SDK 构建，以下对 rust-package.mk 的变量名与
# `src-link` 的 feed 布局做了假设并在注释里标明——见 openwrt/README.md 的「未验证」。

include $(TOPDIR)/rules.mk

PKG_NAME:=hextet
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT OR Apache-2.0
PKG_LICENSE_FILES:=LICENSE-MIT LICENSE-APACHE
PKG_MAINTAINER:=hextet developers

# cargo 交叉编译需要 rust host 包（提供 cargo 与目标 std）。
PKG_BUILD_DEPENDS:=rust/host

# 用标准 Install 阶段：Build/Install 把二进制暂存到 PKG_INSTALL_DIR，
# Package/hextet/install 再从这里拷贝进包目录。
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

# OpenWrt 的 Rust 辅助（定义 CARGO_HOME / CARGO_VARS / RUSTC_TARGET_ARCH / RUSTFLAGS 等，
# 并把 cargo 的交叉 target 与 $(TARGET_CC) linker 接好）。
# 默认假设官方 packages feed 已 checkout 到 $(TOPDIR)/feeds/packages（`./scripts/feeds
# install -a` 之后的常规布局）。若你的 feed 布局不同，把下面这行改成指向 rust 包的
# rust-package.mk（同 feed 内通常是 `include ../rust/rust-package.mk`）。
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

# 源码根目录：本仓库根（含 Cargo.toml / Cargo.lock / crates/ / LICENSE-*）。
# 当 feed 用 `src-link openwrt <repo>/openwrt` 指向本仓库的 openwrt/ 目录时，
# $(CURDIR) 是 <repo>/openwrt/hextet，因此 ../.. 即仓库根。若你把 hextet/ 单独
# 拷贝出去打包，改为一个绝对路径或让 CI 传入。
HEXTET_SRC:=$(CURDIR)/../..

define Package/hextet
  SECTION:=net
  CATEGORY:=Network
  TITLE:=hextet — IPv6-only serverless mesh VPN
  URL:=https://github.com/sudoviber/hextet
  # kmod-wireguard：内核数据面；libc/libgcc/libssp：Rust 静态链接之外的运行时三元组。
  # 数据面走 netlink（纯 Rust），无其他原生依赖（无 openssl/ring，见 Cargo.lock）。
  DEPENDS:=+kmod-wireguard +libc +libgcc +libssp
endef

define Package/hextet/description
  IPv6-only serverless mesh VPN. Data plane is kernel WireGuard (netlink control),
  service is managed by procd + uci. This package ships the hextet daemon binary,
  a procd init script, uci defaults and an example hextet.toml.
endef

# 复制源码到 PKG_BUILD_DIR（本地源，不下载 tarball）。
define Build/Prepare
	$(call Build/Prepare/Default)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(HEXTET_SRC)/Cargo.toml $(PKG_BUILD_DIR)/
	$(CP) $(HEXTET_SRC)/Cargo.lock $(PKG_BUILD_DIR)/
	$(CP) $(HEXTET_SRC)/rust-toolchain.toml $(PKG_BUILD_DIR)/
	$(CP) -r $(HEXTET_SRC)/crates $(PKG_BUILD_DIR)/
	$(CP) $(HEXTET_SRC)/LICENSE-MIT $(PKG_BUILD_DIR)/
	$(CP) $(HEXTET_SRC)/LICENSE-APACHE $(PKG_BUILD_DIR)/
endef

# 用 OpenWrt rust 包的交叉环境编译 hextet 二进制。
# CARGO_VARS 内含 CARGO_HOME / RUSTFLAGS / 交叉 target 的 linker 设置，
# RUSTC_TARGET_ARCH 是 cargo 的 target triple（如 aarch64-unknown-linux-musl）。
# --locked：只用 Cargo.lock 锁定的版本；--release：发布构建；--bin hextet：只出二进制。
define Build/Compile
	( cd $(PKG_BUILD_DIR) && \
	  $(CARGO_VARS) \
	  cargo build --release --locked --target $(RUSTC_TARGET_ARCH) --bin hextet )
endef

# 把 cargo 产物暂存进 PKG_INSTALL_DIR，供 Package/hextet/install 拷贝。
define Build/Install
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)/release/hextet \
		$(PKG_INSTALL_DIR)/usr/sbin/hextet
endef

# 安装二进制 + conffiles（uci 默认值 + init 脚本）+ 示例配置。
define Package/hextet/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config $(1)/etc/hextet
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hextet $(1)/usr/sbin/hextet
	$(INSTALL_BIN) ./files/hextet.init $(1)/etc/init.d/hextet
	$(INSTALL_DATA) ./files/hextet.conf $(1)/etc/config/hextet
	$(INSTALL_DATA) ./files/hextet.toml.example $(1)/etc/hextet/hextet.toml.example
endef

define Package/hextet/conffiles
/etc/config/hextet
/etc/init.d/hextet
endef

$(eval $(call BuildPackage,hextet))
