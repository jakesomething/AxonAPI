#
# Powershell script to pull indicators from Alien Vault Opensource Threat Exchange(OTX) and export to CSVs for importing into Arcsight or other SIEM.
# Written by Wylie Bayes 02/23/2018
#
# Updated by github.com/jakehsomething 12/29/2022
# Change log: Removed alien, fixed move to archive (if folder doesn't exist it didn't archive), changed the output to be data that wasn't in previous instance (whitelist)
#             Include headers in export, removed data points not useful 
#
#
# Define Main Function, set variables to Null, and then define as arrays. 
function Get-OTXData {
	Clear-Host
	$otxkey = ""
	# Define export location.
	$exports = "C:\Exports\"
	$whitelists = "C:\Exports\archive"
	# How old are indicators allowed to be in days
	$daysold = "30"
	$FileHashesEPO = $null
	$FileHashes = $null
	$hostnames = $null
	$IPV4s = $null
	$IPV6s = $null
	$Emails = $null
	$URLs = $null
	$counts = $null
	$total = $null
	$hostnames = @()
	$IPV4s = @()
	$IPV6s = @()
	$URLs = @()
	$FileHashes = @()
	$Emails = @()
	$counts = @()
	;""
	;""
	
	# Define our Error preference.
	$ErrorActionPreference = "SilentlyContinue"
	# Archive previous days export into the archive folder.
	$archive = get-childitem "$exports\*.csv" -Exclude "$exports\Total_Numbers.csv"
	$archivePath = "$exports\archive\"
	if ($null -ne $archive){
		if(!(Test-Path $archivePath -PathType Container)){
			New-Item -ItemType Directory -Force -Path $archivePath
	   }
		Move-Item $archive "$archivePath" -Force
		write-host "Archived previous CSVs into the archive folder" -foregroundcolor "Green"
	} else {
		write-host "No previous CSV's to archive. Continuing" -foregroundcolor "Yellow"
	}

	# Pull in White Lists for Exclusions
	$IPv4WL = Import-CSV "$whitelists\IPv4s.csv" 
	$DomainOrHostnameWL = Import-CSV "$whitelists\DomainOrHostnames.csv" 
	$EmailWL = Import-CSV "$whitelists\Emails.csv" 
	$FileHashWL = Import-CSV "$whitelists\FileHashes.csv" 
	$URLWL = Import-CSV "$whitelists\URLs.csv"
	# Define a bit of regex for later
	$regex = "[^a-zA-Z]"
	# Define first page to begin.
	$next = "https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=10&page=1"
	do {
		write-progress "Pulling & sorting all OTX indicators. Processing page: $page"
		$indicators = invoke-webrequest -URI $next -UseBasicParsing -Headers @{"X-OTX-API-KEY"="$otxkey"} -UseDefaultCredentials
		# Convert JSON data received into powershell object.
		$data = $indicators.Content | ConvertFrom-Json
		# Populate the next page into $next variable.
		$next = $data.next
		$page = $next.split("&")[1].split("=")[1]
		#
		$filtered = $data.Results | Where-Object {$null -ne $_.References}
		if ($filtered){
			foreach ($item in $filtered){
				$name = $null
				$name = $item.Name -replace $regex
				$LastModified = get-date $item.Modified
				if ($LastModified -gt (get-date).AddDays("-$daysold")){
					foreach ($indicator in $Item.Indicators) {
						# Gather Domain and Subdomain Names Indicators
						if ($indicator.Type -eq "hostname" -or $indicator.type -eq "domain" -and $indicator.indicator -notin $DomainOrHostnameWL.DomainOrHostName){
							if ($item.References -like "*http*") {
								$hostnames += new-object PSObject -Property @{"Hostname"="$($indicator.Indicator)"; "Name"="$($name)"; "Reference"="$($item.References)"} | Select Hostname,Name,Reference
							}
						}
						# Gather All IPV4 Indicators
						if ($indicator.Type -eq "IPv4" -and $indicator.indicator -notin $IPv4WL."IPv4 Address"){
							if ($item.References -like "*http*"){
								$IPV4s += new-object PSObject -Property @{"IPv4 Address"="$($indicator.Indicator)"; "Name"="$($name)"; "Reference"="$($item.References)"} | Select "IPv4 Address",Name,Reference
							}
						}
						# Gather All IPV6 Indicators
						if ($indicator.Type -eq "IPv6"){
							if ($item.References -like "*http*"){
								$IPV6s += new-object PSObject -Property @{"IPv6 Address"="$($indicator.Indicator)"; "Name"="$($name)"; "Reference"="$($item.References)"} | Select "IPv6 Address",Name,Reference
							}
						}
						# Gather All URL Indicators
						if ($indicator.Type -eq "URL" -and $indicator.indicator -notin $URLWL.URL){
							if ($item.References -like "*http*"){
								$URLs += new-object PSObject -Property @{"URL"="$($indicator.indicator)"; "Name"="$($name)"; "Reference"="$($item.References)"} | Select URL,Name,Reference
							}
						}
						# Gather all File Hash Indicators
						if ($indicator.Type -eq "FileHash-MD5" -or $indicator.Type -eq "FileHash-SHA1" -or $indicator.Type -eq "Filehash-SHA256" -and $indicator.indicator -notin $FileHashWL.FileHash){
							if ($item.References -like "*http*"){
								if ($null -ne $item.References -and $item.References -like "*http*"){
								$FileHashes += new-object PSObject -Property @{"FileHash"="$($indicator.Indicator)"; "Name"="$($name)"; "Reference"="$($item.References)"} | Select FileHash,Name,Reference
								}
							}
						}
						# Gather all Email Indicators
						if ($indicator.Type -eq "email" -and $indicator.indicator -notin $EmailWL."Email Address"){
							if ($item.References -like "*http*"){
								$Emails += new-object PSObject -Property @{"Email"="$($indicator.Indicator)"; "Name"="$($name)"; "Reference"="$($item.References)"} | Select Email,Name,Reference
							}
						}
					}
				}
			}
		}
	} while ($next -ne $null)
	# Export all indicators to CSVs if data exists in each object.

	write-progress "Exporting all OTX indicators to CSV."
	if ($hostnames){
		$hostnames | ConvertTo-Csv -NoTypeInformation | Set-Content "$($exports)Hostnames.csv"
	}
	if ($IPV4s) {
		$IPV4s | ConvertTo-Csv -NoTypeInformation | Set-Content "$($exports)IPV4s.csv"
	}
	if ($IPV6s) {
		$IPV6s | ConvertTo-Csv -NoTypeInformation | Set-Content "$($exports)IPV6s.csv"
	}
	if ($URLs) {
		$URLs | ConvertTo-Csv -NoTypeInformation | Set-Content "$($exports)URLs.csv"
	}
	if ($FileHashes) {
		$FileHashes | ConvertTo-Csv -NoTypeInformation | Set-Content "$($exports)FileHashes.csv"
	}
	if ($Emails){
		$Emails | ConvertTo-Csv -NoTypeInformation | Set-Content "$($exports)Emails.csv"
	}

	# Total up the indicators and create a CSV just for number tracking.
	$total = $hostnames.count + $IPv4s.count + $URLs.count + $FileHashesEPO.count + $Emails.count
	$counts = new-object PSObject -Property @{"Hostnames"="$($hostnames.count)"; "IPv4s"="$($IPv4s.count)"; "URLs"="$($URLs.Count)"; "FileHashes"="$($FileHashes.count)"; "Emails"="$($Emails.Count)"; "Total"="$($total)"} | Select Hostnames,IPv4s,URLs,FileHashes,Emails,Total
	$counts | Export-csv "$($exports)Total_Numbers.csv" -NoTypeInformation -Append
	
}

Get-OTXData