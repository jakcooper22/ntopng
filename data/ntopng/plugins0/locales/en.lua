-- Persistent Data
local multiRefObjects = {

} -- multiRefObjects
local obj1 = {
	["active_monitoring"] = {
		["24h"] = "24H Availability";
		["cont_icmp"] = "Continuous ICMPv4";
		["cont_icmp6"] = "Continuous ICMPv6";
	};
	["remote_to_remote"] = {
		["title"] = "Remote to Remote Hosts";
		["description"] = "Trigger alerts for remote client hosts on remote-to-remote flows. Only works for the builtin alert recipient.";
	};
	["pool_quota_exceeded"] = {
		["title"] = "Quota Exceeded";
		["description"] = "Trigger an alert when a time/traffic quota is exceeded.";
	};
	["unexpected_ntp"] = {
		["unexpected_ntp_description"] = "Trigger an alert when not allowed NTP server is detected";
		["alert_unexpected_ntp_title"] = "Unexpected NTP server found";
		["title"] = "Allowed NTP servers";
		["unexpected_ntp_title"] = "Unexpected NTP server";
		["status_unexpected_ntp_description"] = "Unexpected NTP server found: %{server}";
		["description"] = "Comma separated values of NTP servers IPs. Example: 173.194.76.109,52.97.232.242";
	};
	["new_api_demo"] = {
		["my_manifest_title"] = "My Manifest Title";
		["alert_host_new_api_demo_description"] = "%{host}: one_param = %{one_param} another_param = %{another_param}";
	};
	["ip_reassignment"] = {
		["title"] = "IP Reassignment";
		["description"] = "Trigger alerts when an IP address, previously seen with a MAC address, is now seen with another MAC address. This alert might indicate an ARP spoof attempt. Only works for the builtin alert recipient.";
	};
	["no_if_activity"] = {
		["status_no_activity_description"] = "No activity reported on network interface.";
		["alert_no_activity_title"] = "No activity on interface";
		["no_if_activity_title"] = "No activity on interface";
		["no_if_activity_description"] = "Trigger an alert when no activity from an interface is detected";
	};
	["unexpected_new_device"] = {
		["alert_unexpected_new_device_title"] = "Unexpected Device Connected";
		["unexpected_new_device_title"] = "Unexpected Device Connected";
		["status_unexpected_new_device_description"] = "Unexpected MAC address device <a href=\"%{host_url}\">%{mac_address}</a> connected to the network.";
		["unexpected_new_device_description"] = "Trigger an alert first time an unexpected (i.e. not part of the allowed MAC addresses list) device connects to the network.";
		["title"] = "Allowed MAC Addresses";
		["status_unexpected_new_device_description_pro"] = "Unexpected MAC address device <a href=\"%{host_url}\">%{mac_address}</a> connected to the network. SNMP Device <a href=\"%{ip_url}\">%{ip}</a> on Port <a href=\"%{port_url}\">%{port}</a> <span class='badge badge-secondary'>%{interface_name}</span>";
		["description"] = "Comma separated values of allowed MAC Addresses. Example: FF:FF:FF:FF:FF:FF";
	};
	["host_log_collector"] = {
		["description"] = "Collect syslog logs from hosts and trigger alerts according to the configured severity level (0 for min verbosity, 7 for max)";
		["title"] = "Host Log";
	};
	["unexpected_dhcp"] = {
		["alert_unexpected_dhcp_title"] = "Unexpected DHCP found";
		["unexpected_dhcp_title"] = "Unexpected DHCP";
		["status_unexpected_dhcp_description"] = "Unexpected DHCP server found: %{server}";
		["title"] = "Allowed DHCP";
		["description"] = "Comma separated values of allowed DHCP IPs. Example: 192.168.1.1";
		["unexpected_dhcp_description"] = "Trigger an alert when not allowed DHCP server is detected";
	};
	["pool_connection_disconnection"] = {
		["title"] = "Host Pool Connection/Disconnection";
		["description"] = "Trigger an alert when a host pool connects to - or disconnects from - the network.";
	};
	["unexpected_dns"] = {
		["alert_unexpected_dns_title"] = "Unexpected DNS found";
		["status_unexpected_dns_description"] = "Unexpected DNS server found: %{server}";
		["description"] = "Comma separated values of allowed DNS IPs. Example: 8.8.8.8,8.8.4.4,1.1.1.1";
		["title"] = "Allowed DNS";
		["unexpected_dns_title"] = "Unexpected DNS";
		["unexpected_dns_description"] = "Trigger an alert when not allowed DNS server is detected";
	};
	["discord_alert_endpoint"] = {
		["webhook_description"] = "Instructions:<ul><li>Open the Discord channel you want to receive ntopng notifications from.<li>From the channel menu, select Edit channel (or click on the wheel icon). <li>Click on Webhooks menu item.<li>Click the Create Webhook button and fill in the name of the bot that will post the messages (note that you can set it on the ntopng recipients page)<li>Note the URL from the WebHook URL field to be copied in the field above. <li>Click the Save button.</ul>";
		["message_sender"] = "Nickname of the discord message sender (optional). ";
		["username"] = "Username";
		["discord_send_error"] = "Error sending message to Discord.";
		["url"] = "WebHook URL";
		["validation"] = {
			["invalid_username"] = "Invalid Discord username.";
			["invalid_url"] = "Invalid Discord Webhook URL. See https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks.";
			["empty_url"] = "Discord Webook URL cannot be empty.";
		};
	};
	["low_goodput"] = {
		["title"] = "Low Goodput";
		["description"] = "Trigger alerts when flow goodput is too low (&lt;= 60%)";
	};
	["suricata_collector"] = {
		["title"] = "Suricata";
		["statistics"] = "Suricata Statistics";
		["description"] = "Collect alerts and metadata from Suricata";
	};
	["shell_alert_endpoint"] = {
		["shell_script"] = "Script PATH";
		["shell_options"] = "Options";
		["shell_send_error"] = "Error while trying to run the script.";
		["shell_description"] = {
			["option_description"] = "Instructions<ul><li>Insert here the options you want to pass to the script</ul>";
			["path_description"] = "Note:<ul><li>The script must be stored in \"/usr/share/ntopng/scripts/shell/\"<li>The script options alert.* are expanded at runtime with the alert values</lu>";
		};
		["validation"] = {
			["empty_path"] = "Shell script path cannot be empty.";
			["invalid_path"] = "Invalid shell script path. The script must be stored in \"/usr/share/ntopng/scripts/shell/\" and end with .sh.";
			["invalid_script"] = "Invalid script. Script not secure.";
		};
	};
	["syslog_alert_endpoint"] = {
		["port"] = "Port";
		["host"] = "Host";
		["validation"] = {
			["invalid_host"] = "Invalid Syslog host.";
			["invalid_port"] = "Invalid Syslog port.";
		};
		["text"] = "Text";
		["content"] = "Content";
		["protocol"] = "Protocol";
		["alert_format"] = "Format";
		["description"] = "Host, Port and Protocol should be specified for remote syslog servers only.";
	};
	["zero_tcp_window"] = {
		["zero_tcp_window_description"] = "Trigger an alert when a flow TCP window is zero";
		["zero_tcp_window_title"] = "Zero TCP Window";
		["alert_zero_tcp_window_description"] = "Reported TCP Zero Window";
		["status_zero_tcp_window_description"] = "Reported TCP Zero Window";
		["alert_zero_tcp_window_title"] = "TCP Zero Window";
		["status_zero_tcp_window_description_c2s"] = "Reported client TCP zero window";
		["status_zero_tcp_window_description_s2c"] = "Reported server TCP zero window ";
	};
	["telegram_alert_endpoint"] = {
		["telegram_channel"] = "Channel Id";
		["telegram_token"] = "Token";
		["webhook_description"] = {
			["channel_id_description"] = "Instructions if you want to use the bot in a group:<ul><li>Add to your group the bot you created<li>Add to your group @getidsbot<li>Copy here the id the @getidsbot gave to you</ul>Instructions if you want to use the bot in a chat:<ul><li>Start a new conversation with @getidsbot<li>Copy here the id the @getidsbot gave to you</ul>";
			["token_description"] = "Instructions:<ul><li>Start a new chat with @BotFather<li>Type and send '/newbot'<li>Give a name to your bot<li>Give a username to your bot<li>Copy here the token the @BotFather gave to you</ul>";
		};
		["telegram_send_error"] = "Error sending message to Telegram.";
		["validation"] = {
			["invalid_channel_name"] = "Invalid Telegram Channel Name.";
			["invalid_token"] = "Invalid Telegram Token.";
		};
	};
	["unexpected_smtp"] = {
		["unexpected_smtp_title"] = "Unexpected SMTP server";
		["status_unexpected_smtp_description"] = "Unexpected SMTP server found: %{server}";
		["unexpected_smtp_description"] = "Trigger an alert when not allowed SMTP server is detected";
		["title"] = "Allowed SMTP servers";
		["alert_unexpected_smtp_title"] = "Unexpected SMTP server found";
		["description"] = "Comma separated values of SMTP servers IPs. Example: 173.194.76.109,52.97.232.242";
	};
}
return obj1
