#
# Powershell script to pull indicators from Alien Vault Opensource Threat Exchange(OTX) and export to CSVs for importing into Arcsight or other SIEM.
# Written by Wylie Bayes 02/23/2018
#
# Define Main Function, set variables to Null, and then define as arrays. 
function Get-OTXData {
	Clear-Host
	$otxkey = ""
	# Define export location.
	$exports = "C:\Exports\"
		# How old are indicators allowed to be in days
	$daysold = "30"
	#
	$IPV4s = $null
	
	$CVEs = $null
	$counts = $null
	$total = $null
	$IPV4s = @()
	$CVEs = @()
	$counts = @()
	;""
	;""
	;""
	# Define our Error preference.
	$ErrorActionPreference = "SilentlyContinue"
	# Archive previous days export into the archive folder.
	$archive = get-childitem "$exports\*.csv"
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
		# Define a bit of regex for later
	$regex = "[^a-zA-Z]"
	# Define first page to begin.
	$next = "https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=10&page=1"
	do {
		write-progress "Pulling all OTX indicators and exporting to CSVs. Processing page: $page"
		$indicators = invoke-webrequest -URI $next -UseBasicParsing -Headers @{"X-OTX-API-KEY"="$otxkey"} -UseDefaultCredentials
		# Convert JSON data received into powershell object.
		$data = $indicators.Content | ConvertFrom-Json
		# Populate the next page into $next variable.
		$next = $data.next
		$page = $next.split("&")[1].split("=")[1]
		#
		$filtered = $data.Results | where {$null -ne $_.References}
		if ($filtered){
			foreach ($item in $filtered){
				$name = $null
				$name = $item.Name -replace $regex
				$LastModified = get-date $item.Modified
				if ($LastModified -gt (get-date).AddDays("-$daysold")){
					foreach ($indicator in $Item.Indicators) {

						# Gather All IPV4 Indicators
						if ($indicator.Type -eq "IPv4" -and $indicator.indicator -notin $IPv4WL."IPv4 Address"){
							if ($item.References -like "*http*"){
								$IPV4s += new-object PSObject -Property @{"IPv4 Address"="$($indicator.Indicator)"; "Name"="$($name)"; "Reference"="$($item.References)"} | Select "IPv4 Address",Name,Reference
							}
						}
						if ($indicator.Type -eq "CVE" -and $indicator.indicator -notin $CVEWL.CVE){
							if ($item.References -like "*http*"){
								$CVEs += new-object PSObject -Property @{"CVE"="$($indicator.Indicator)"; "Name"="$($name)"; "Reference"="$($item.References)"} | Select CVE,Name,Reference
							}
						}
					}
				}
			}
		}
	} while ($null -ne $next)
	# Export all indicators to CSVs if data exists in each object.
	if ($IPV4s) {
		$IPV4s | ConvertTo-Csv -NoTypeInformation | Select -Skip 1 | Set-Content "$($exports)IPV4s.csv"
	}
	if ($CVEs){
		$CVEs | ConvertTo-Csv -NoTypeInformation | select -Skip 1 | Set-Content "$($exports)CVEs.csv"
	}
	# Total up the indicators and create a CSV just for number tracking.
	$total = $IPv4s.count + $CVEs.count
	$counts = new-object PSObject -Property @{"IPv4s"="$($IPv4s.count)"; "CVEs"="$($CVEs.count)"; "Total"="$($total)"} | Select IPv4s,CVEs,Total
	$counts | Export-csv "$($exports)Total_Numbers.csv" -NoTypeInformation -Append
	# Open exports folder and complete the operation.
}

Get-OTXData