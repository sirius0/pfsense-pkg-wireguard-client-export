<?php
/*
 * wgclientexport.priv.inc
 *
 * Copyright (c) 2026 WireGuard Client Export contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

global $priv_list;

$priv_list['page-vpn-wireguard-client-export'] = array();
$priv_list['page-vpn-wireguard-client-export']['name'] =
	'WebCfg - VPN: WireGuard Client Export';
$priv_list['page-vpn-wireguard-client-export']['descr'] =
	'Allow access to the WireGuard Client Export page.';
$priv_list['page-vpn-wireguard-client-export']['match'] = array();
$priv_list['page-vpn-wireguard-client-export']['match'][] =
	'wgclientexport/vpn_wg_client_export.php*';

?>
