'use strict';
'require uci';
'require view';

/*
 * hextet 状态/概览视图（最小骨架）
 *
 * 只读：从 uci 读 /etc/config/hextet 的 enabled / config_file / verbose 三项，
 * 展示在页面上。不修改配置、不驱动 daemon。依赖极轻：仅 uci + view，无构建工具链。
 */

return view.extend({
	load: function () {
		return uci.load('hextet');
	},

	render: function () {
		var enabled = uci.get('hextet', 'hextet', 'enabled') || '0';
		var config_file = uci.get('hextet', 'hextet', 'config_file') || '/etc/hextet/hextet.toml';
		var verbose = uci.get('hextet', 'hextet', 'verbose') || '0';

		return E('div', { 'class': 'cbi-section' }, [
			E('h2', _('hextet')),
			E('div', { 'class': 'cbi-section-descr' },
				_('IPv6-only serverless mesh VPN. This page only reads the service settings; the node itself is configured in hextet.toml.')),
			E('table', { 'class': 'cbi-section-table' }, [
				E('tr', { 'class': 'cbi-section-table-row' }, [
					E('td', { 'class': 'cbi-value-title' }, _('Enabled')),
					E('td', enabled === '1' ? _('yes') : _('no'))
				]),
				E('tr', { 'class': 'cbi-section-table-row' }, [
					E('td', { 'class': 'cbi-value-title' }, _('Config file')),
					E('td', config_file)
				]),
				E('tr', { 'class': 'cbi-section-table-row' }, [
					E('td', { 'class': 'cbi-value-title' }, _('Verbose logging')),
					E('td', verbose === '1' ? _('yes') : _('no'))
				])
			])
		]);
	}
});
