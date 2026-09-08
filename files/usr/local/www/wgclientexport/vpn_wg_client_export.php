<?php
/*
 * vpn_wg_client_export.php
 *
 * Copyright (c) 2026 WireGuard Client Export contributors
 * Licensed under the Apache License, Version 2.0.
 */

require_once('guiconfig.inc');
require_once('/usr/local/pkg/wgclientexport/bootstrap.inc');

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

function wgclientexport_page_csv($value): string {
	return implode(', ', wgclientexport_normalize_list($value));
}

function wgclientexport_page_tunnel_options(array $tunnels): array {
	$options = array();
	foreach ($tunnels as $tunnel) {
		$name = (string) ($tunnel['name'] ?? '');
		if ($name === '') {
			continue;
		}
		$description = trim((string) ($tunnel['description'] ?? ''));
		$options[$name] = $description === '' ? $name : "{$name} — {$description}";
	}
	return $options;
}

function wgclientexport_page_suggestion_context(): array {
	$local_networks = array();
	$interfaces = function_exists('config_get_path')
		? (array) config_get_path('interfaces', array()) : array();
	foreach ($interfaces as $name => $interface) {
		$name = (string) $name;
		if ($name === 'wan' || !is_array($interface)) {
			continue;
		}
		$device = function_exists('get_real_interface')
			? (string) get_real_interface($name) : (string) ($interface['if'] ?? '');
		if (str_starts_with($device, 'tun_wg')) {
			continue;
		}
		$address = function_exists('get_interface_ip') ? (string) get_interface_ip($name) : '';
		$prefix = function_exists('get_interface_subnet') ? (string) get_interface_subnet($name) : '';
		$network = wgclientexport_normalize_ipv4_cidr("{$address}/{$prefix}");
		if ($network !== null) {
			$local_networks[] = $network;
		}
	}

	return array(
		'dns_servers' => function_exists('config_get_path')
			? config_get_path('system/dnsserver', array()) : array(),
		'ddns_records' => function_exists('config_get_path')
			? config_get_path('dyndnses/dyndns', array()) : array(),
		'wan_ipv4' => function_exists('get_interface_ip')
			? (string) get_interface_ip('wan') : '',
		'local_networks' => $local_networks,
	);
}

$input_errors = array();
$save_success = false;
$one_time_result = null;
$readiness = wgclientexport_bootstrap();
$tunnels = wgclientexport_list_tunnels();
$tunnel_options = wgclientexport_page_tunnel_options($tunnels);
$requested_tunnel = (string) ($_POST['tunnel_id'] ?? $_POST['tunnel'] ?? $_GET['tun'] ?? '');
$selected_tunnel = array_key_exists($requested_tunnel, $tunnel_options)
	? $requested_tunnel : (string) array_key_first($tunnel_options);

$action = (string) ($_POST['wgce_action'] ?? '');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'save_settings') {
	$save = wgclientexport_save_settings($_POST);
	$input_errors = (array) ($save['input_errors'] ?? array());
	$save_success = empty($input_errors) && !empty($save['saved']);
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'provision') {
	$provision = wgclientexport_provision($_POST);
	$input_errors = (array) ($provision['input_errors'] ?? array());
	if (empty($input_errors) && is_array($provision['result'] ?? null)) {
		$one_time_result = $provision['result'];
	}
}

$stored = $selected_tunnel === '' ? null : wgclientexport_get_tunnel_settings($selected_tunnel);
$selected_info = null;
foreach ($tunnels as $tunnel) {
	if (($tunnel['name'] ?? '') === $selected_tunnel) {
		$selected_info = $tunnel;
		break;
	}
}
$suggestions_applied = !is_array($stored);
$suggestion_context = $suggestions_applied
	? wgclientexport_page_suggestion_context() : array();
$settings_values = wgclientexport_settings_for_ui(
	$selected_info ?? array('name' => $selected_tunnel),
	$suggestion_context,
	$stored
);
if ($action === 'save_settings' && !empty($input_errors)) {
	$settings_values = array_merge($settings_values, $_POST);
	$suggestions_applied = false;
}

$pgtitle = array(gettext('VPN'), gettext('WireGuard Client Export'));
$shortcut_section = 'wireguard';
include('head.inc');

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($save_success) {
	print_info_box(gettext('WireGuard Client Export settings were saved.'), 'success');
}
if (empty($readiness['ready'])) {
	$messages = array_map(
		static fn($message) => htmlspecialchars((string) $message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
		(array) ($readiness['input_errors'] ?? array())
	);
	print_info_box(implode('<br />', $messages), 'warning');
}
if (empty($tunnel_options)) {
	print_info_box(
		gettext('No compatible WireGuard tunnel is available. Create and enable a tunnel first.'),
		'warning'
	);
	include('foot.inc');
	exit;
}
if ($suggestions_applied) {
	print_info_box(gettext(
		'Suggested values were detected from pfSense. Review the public endpoint, then save the settings.'
	), 'info');
	if (trim((string) ($settings_values['endpoint_host'] ?? '')) === '') {
		print_info_box(gettext(
			'A public endpoint could not be detected. Enter a public hostname or IPv4 address.'
		), 'warning');
	}
}

$settings_submit = new Form_Button(
	'wgce_save_settings', gettext('Save settings'), null, 'fa-save'
);
$settings_submit->addClass('btn-primary');
$settings_form = new Form($settings_submit);
$settings_form->setAttribute('id', 'wgce_settings_form');
$settings_form->addGlobal(new Form_Input(
	'wgce_action', null, 'hidden', 'save_settings', array('id' => 'wgce_settings_action')
));
$settings_section = new Form_Section(gettext('Tunnel client-export settings'));
$settings_section->addInput(new Form_Select(
	'tunnel_id', gettext('Tunnel'), $selected_tunnel, $tunnel_options
))->setHelp(gettext('Settings are stored separately for each official WireGuard tunnel.'));
$settings_section->addInput(new Form_Checkbox(
	'enabled', gettext('Client generation'), gettext('Enable for this tunnel'),
	($settings_values['enabled'] ?? 'no') === 'yes'
));
$settings_section->addInput(new Form_Input(
	'client_pool_ipv4', gettext('IPv4 client pool'), 'text',
	(string) ($settings_values['client_pool_ipv4'] ?? ''), array('placeholder' => '10.66.66.0/24')
))->setHelp(gettext('Explicit pool used to allocate one unique /32 address per client.'));
$settings_section->addInput(new Form_Input(
	'endpoint_host', gettext('Public endpoint'), 'text',
	(string) ($settings_values['endpoint_host'] ?? ''), array('placeholder' => 'vpn.example.com')
));
$settings_section->addInput(new Form_Input(
	'endpoint_port', gettext('Endpoint port'), 'number',
	(string) ($settings_values['endpoint_port'] ?? '51820'), array('min' => 1, 'max' => 65535)
));
$settings_section->addInput(new Form_Input(
	'dns_ipv4', gettext('DNS resolvers'), 'text',
	wgclientexport_page_csv($settings_values['dns_ipv4'] ?? array()), array('placeholder' => '10.66.66.1, 1.1.1.1')
))->setHelp(gettext('Optional comma-separated IPv4 addresses.'));
$settings_section->addInput(new Form_Input(
	'local_routes_ipv4', gettext('Local-network routes'), 'text',
	wgclientexport_page_csv($settings_values['local_routes_ipv4'] ?? array()),
	array('placeholder' => '10.66.66.0/24, 192.168.1.0/24')
))->setHelp(gettext('Routes emitted by the Local networks profile.'));
$settings_section->addInput(new Form_Input(
	'reservations_ipv4', gettext('Reserved client addresses'), 'text',
	wgclientexport_page_csv($settings_values['reservations_ipv4'] ?? array()),
	array('placeholder' => '10.66.66.10, 10.66.66.20')
));
$settings_section->addInput(new Form_Input(
	'persistent_keepalive', gettext('Default persistent keepalive'), 'number',
	(string) ($settings_values['persistent_keepalive'] ?? '25'), array('min' => 0, 'max' => 65535)
))->setHelp(gettext('Use 0 to omit PersistentKeepalive from generated configurations.'));
$settings_form->add($settings_section);
print($settings_form);

$provision_values = $action === 'provision' ? $_POST : array();
$default_routing_profile = empty(wgclientexport_normalize_list(
	$stored['local_routes_ipv4'] ?? array()
)) ? 'full' : 'local';
$client_name = (string) ($provision_values['client_name'] ?? '');
$generation_available = !empty($readiness['ready'])
	&& ($stored['enabled'] ?? 'no') === 'yes';
$client_submit = new Form_Button(
	'wgce_generate_client', gettext('Generate client'), null, 'fa-plus'
);
$client_submit->addClass('btn-primary');
if (!$generation_available || trim($client_name) === '') {
	$client_submit->setDisabled();
}
$client_form = new Form($client_submit);
$client_form->setAttribute('id', 'wgce_client_form');
$client_form->addGlobal(new Form_Input(
	'wgce_action', null, 'hidden', 'provision', array('id' => 'wgce_provision_action')
));
$client_section = new Form_Section(gettext('Generate a remote-access client'));
$client_section->addInput(new Form_Select(
	'tunnel', gettext('Tunnel'), $selected_tunnel, array($selected_tunnel => $tunnel_options[$selected_tunnel])
));
$client_section->addInput(new Form_Input(
	'client_name', gettext('Client name'), 'text', $client_name,
	array('maxlength' => 64, 'placeholder' => 'iphone-personal',
		'aria-label' => gettext('Client name'), 'required' => true)
));
$client_section->addInput(new Form_Select(
	'routing_profile', gettext('Traffic'),
	(string) ($provision_values['routing_profile'] ?? $default_routing_profile),
	array('local' => gettext('Local networks only'), 'full' => gettext('All Internet traffic'),
		'custom' => gettext('Custom networks'))
));
$client_section->addInput(new Form_Checkbox(
	'show_advanced', gettext('Advanced options'), gettext('Show per-client overrides'), false
));
$client_form->add($client_section);
$advanced_section = new Form_Section(gettext('Advanced client options'));
$advanced_section->addClass('wgce-advanced-options');
$advanced_section->addInput(new Form_Input(
	'client_address', gettext('Client address'), 'text',
	(string) ($provision_values['client_address'] ?? ''), array('placeholder' => gettext('Automatic'))
));
$advanced_section->addInput(new Form_Input(
	'dns_ipv4', gettext('DNS override'), 'text',
	(string) ($provision_values['dns_ipv4'] ?? wgclientexport_page_csv($stored['dns_ipv4'] ?? array())),
	array('id' => 'wgce_client_dns_ipv4')
));
$advanced_section->addInput(new Form_Input(
	'persistent_keepalive', gettext('Persistent keepalive'), 'number',
	(string) ($provision_values['persistent_keepalive'] ?? $stored['persistent_keepalive'] ?? '25'),
	array('id' => 'wgce_client_persistent_keepalive', 'min' => 0, 'max' => 65535)
));
$advanced_section->addInput(new Form_Input(
	'custom_routes_ipv4', gettext('Custom networks'), 'text',
	(string) ($provision_values['custom_routes_ipv4'] ?? ''),
	array('placeholder' => '192.168.1.0/24, 10.0.0.0/8')
))->setHelp(gettext('Required only when Traffic is set to Custom networks.'));
$client_form->add($advanced_section);
print($client_form);

if (is_array($one_time_result)):
	$configuration = (string) ($one_time_result['configuration'] ?? '');
	$filename = (string) ($one_time_result['filename'] ?? 'wireguard-client.conf');
?>
<section id="wgce-result" class="panel panel-success" aria-labelledby="wgce-result-title">
	<div class="panel-heading"><h2 id="wgce-result-title" class="panel-title"><?=gettext('Client created')?></h2></div>
	<div class="panel-body">
		<p><strong><?=htmlspecialchars((string) $one_time_result['client_name'])?></strong> —
			<?=htmlspecialchars((string) $one_time_result['address'])?></p>
		<div class="alert alert-warning"><?=gettext('This configuration is shown only once. Its private key cannot be recovered from pfSense.')?></div>
		<div id="wgce-qrcode" style="width: 280px; height: 280px; margin-bottom: 1rem" aria-label="<?=gettext('WireGuard configuration QR code')?>"></div>
		<p id="wgce-action-status" class="help-block" role="status" aria-live="polite"></p>
		<textarea id="wgce-configuration" class="form-control" rows="12" readonly><?=htmlspecialchars($configuration, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></textarea>
		<br />
		<button type="button" id="wgce-copy" class="btn btn-default"><i class="fa fa-copy"></i> <?=gettext('Copy configuration')?></button>
		<button type="button" id="wgce-download" class="btn btn-primary"><i class="fa fa-download"></i> <?=gettext('Download .conf')?></button>
		<a class="btn btn-default" href="/wg/vpn_wg_peers.php"><?=gettext('Open WireGuard peers')?></a>
	</div>
</section>
<script src="/wgclientexport/js/qrcode.js"></script>
<script>
'use strict';
(function () {
	var field = document.getElementById('wgce-configuration');
	var configuration = field.value;
	var filename = <?=json_encode($filename, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)?>;
	var status = document.getElementById('wgce-action-status');
	function announce(message, failed) {
		status.textContent = message;
		status.className = failed ? 'help-block text-danger' : 'help-block text-success';
	}
	function fallbackCopy(field) {
		field.focus();
		field.select();
		try {
			var copied = document.execCommand('copy');
			announce(copied
				? <?=json_encode(gettext('Configuration copied.'))?>
				: <?=json_encode(gettext('Copy was blocked. Select the configuration and copy it manually.'))?>,
				!copied);
		} catch (error) {
			announce(<?=json_encode(gettext('Copy was blocked. Select the configuration and copy it manually.'))?>, true);
		}
	}
	document.getElementById('wgce-copy').addEventListener('click', function () {
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(configuration).then(function () {
				announce(<?=json_encode(gettext('Configuration copied.'))?>, false);
			}).catch(function () {
				fallbackCopy(field);
			});
		} else {
			fallbackCopy(field);
		}
	});
	document.getElementById('wgce-download').addEventListener('click', function () {
		var url = URL.createObjectURL(new Blob([configuration], {type: 'text/plain;charset=utf-8'}));
		var link = document.createElement('a');
		link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove();
		window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
		announce(<?=json_encode(gettext('Configuration download started.'))?>, false);
	});
	try {
		if (typeof QRCode !== 'function') {
			throw new Error('QR library unavailable');
		}
		new QRCode(document.getElementById('wgce-qrcode'), {
			text: configuration, width: 280, height: 280, correctLevel: QRCode.CorrectLevel.M
		});
	} catch (error) {
		document.getElementById('wgce-qrcode').textContent =
			<?=json_encode(gettext('QR code unavailable. Use Copy configuration or Download .conf.'))?>;
	}
}());
</script>
<?php
	unset($configuration, $filename, $one_time_result);
endif;
?>
<script>
'use strict';
events.push(function () {
	var generationAvailable = <?=json_encode($generation_available)?>;
	function updateAdvancedOptions() {
		var visible = $('#show_advanced').prop('checked') || $('#routing_profile').val() === 'custom';
		$('.wgce-advanced-options').toggle(visible);
		$('#custom_routes_ipv4').closest('.form-group').toggle($('#routing_profile').val() === 'custom');
	}
	function updateGenerateButton() {
		$('#wgce_generate_client').prop(
			'disabled', !generationAvailable || $.trim($('#client_name').val()) === ''
		);
	}
	$('#show_advanced, #routing_profile').on('change', updateAdvancedOptions);
	$('#client_name').on('input', updateGenerateButton);
	$('#tunnel_id').on('change', function () {
		window.location.href = '/wgclientexport/vpn_wg_client_export.php?tun=' + encodeURIComponent(this.value);
	});
	updateAdvancedOptions();
	updateGenerateButton();
});
</script>
<?php include('foot.inc'); ?>
