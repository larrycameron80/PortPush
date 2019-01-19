# Validates a port value.
function validatePort {
	param( [int]$Port )
	
	If ( [int]$Port -lt 1 -OR [int]$Port -gt 65535 ) {
		Write-Error -Message "Invalid Port Specified." -Category InvalidArgument -ErrorAction Stop
	}
}

# Validates an IP value.
function validateIP {
	param( [string]$IP )
	
	$error.clear()
	
	try { 
		[ipaddress]$IP | Out-Null 
	}
	
	catch {
		Write-Error -Message "Invalid IP Address Specified." -Category InvalidArgument -ErrorAction Stop
	}
}
	
# Deletes a specified rule from the port proxy ruleset
function deleteRule {
	param( [int]$lPort, [string]$listenIP )
	
	if ( ! $listenIP ) {
		Write-Error -Message "No Listen IP specified. A listening IP address must be specified when deleting a rule." -Category InvalidArgument -ErrorAction Stop
	}
	
	elseif ( ! $lPort ) {
		Write-Error -Message "No Listen Port specified. A listening port must be specified when deleting a rule." -Category InvalidArgument -ErrorAction Stop
	}
	
	else {
		validateIP -IP $listenIP
		validatePort -Port $lPort
		
		try {
			# Gets the associated rule from the firewall rule list.
			$rule = Get-NetFirewallRule -DisplayName WindowsMedia | Get-NetFirewallPortFilter | Where-Object LocalPort -eq $lPort | Select -ExpandProperty CreationClassName 
			$delrule = $rule.split("|")[3]
		}
		
		catch {
			Write-Error -Message "Unable to locate associated rule. Please verify your specified IP and Port." -Category InvalidArgument -ErrorAction Stop
		}
		
		netsh interface portproxy delete v4tov4 listenport=$lPort listenaddress=$listenIP
		Remove-NetFirewallRule -Name $delrule
		
		$socketString = $listenIP + ":" + $lPort
		Write-Host "$socketString rule has been successfully removed."
		Write-Host " "
	}
}

# Deletes ALL rules that have been created by the PortPush utility (ONLY rules made by PortPush)
function flushRules {
	param( [string]$listenIP )
	
	if ( ! $listenIP ) {
		Write-Error -Message "No Listen IP specified. A listening IP address must be specified to flush all associated rules." -Category InvalidArgument -ErrorAction Stop
	}
	
	else {
		validateIP -IP $listenIP
		$rules = Get-NetFirewallRule -DisplayName WindowsMedia | Select -ExpandProperty Name
		
		Foreach ( $rule in $rules ) {
			$listenport = Get-NetFirewallRule -Name $rule | Get-NetFirewallPortFilter | Select -ExpandProperty LocalPort
			netsh interface portproxy delete v4tov4 listenport=$listenport listenaddress=$listenIP >null 2>&1
			Remove-NetFirewallRule -Name $rule
		}
	
	Write-Host " "
	Write-Host "All Rules have been successfully flushed."
	Write-Host " "
	
	}
}

# Adds a new PortPush rule.
function addRule {
	param( [int]$lPort, [int]$tPort, [string]$listenIP, [string]$targetIP )
	
	if ( ! $lPort ) {
		Write-Error -Message "No Listening Port specified. A listening port must be specified." -Category InvalidArgument -ErrorAction Stop
	}
	
	elseif ( ! $tPort ) {
		Write-Error -Message "No Target Port specified. A target port must be specified." -Category InvalidArgument -ErrorAction Stop
	}
	
	elseif ( ! $listenIP ) {
		Write-Error -Message "No Listening IP specified. A listening IP must be specified." -Category InvalidArgument -ErrorAction Stop
	}
	
	elseif ( ! $targetIP ) {
		Write-Error -Message "No Target IP specified. A target IP must be specified." -Category InvalidArgument -ErrorAction Stop
	}
	
	else {
		validatePort -Port $lPort
		validatePort -Port $tPort
		validateIP -IP $listenIP
		validateIP -IP $targetIP
		
		$error.clear()
		
		try {
			netsh advfirewall firewall add rule name=WindowsMedia dir=in protocol=TCP localport=$lPort action=allow | Out-Null
		}
		
		catch {
			Write-Error -Message "Unable to create firewall rule. Are you running as administrator?" -Category ProtocolError -ErrorAction Stop
		}
		
		try {
			netsh interface portproxy add v4tov4 listenport=$lPort listenaddress=$listenIP connectport=$tPort connectaddress=$targetIP
		}
		
		catch {
			Write-Error -Message "Unable to create forwarding rule. Are you running as administrator?" -Category ProtocolError -ErrorAction Stop
		}
		
		$listenSocket = $listenIP + ":" + $lPort
		$targetSocket = $targetIP + ":" + $tPort
		Write-Host " $listenSocket => $targetSocket rule has been added."
		Write-Host " "
	}
}

# This is the function users should be calling. Sub-functions can be called directly, but it is not encouraged.
function winPortPush {
	param( [switch]$list, [switch]$flush, [switch]$delete, [int]$lPort, [int]$tPort, [string]$listenIP, [string]$targetIP )
	
	if ( $list ) {
		listRules
	}
	
	elseif ( $flush ) {
		flushRules -listenIP $listenIP
	}
	
	elseif ( $delete ) {
		deleteRule -listenIP $listenIP -lPort $lPort
	}
	
	else {
		addRule -lPort $lPort -listenIP $listenIP -tPort $tPort -targetIP $targetIP
	}
}