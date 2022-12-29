#
# Powershell script to push indicators from CSV into LogRhythm Axon lists. This is configured to append IPs to a list.
# Written by github.com/jakesomething 12-29-2022
#

$api_key = ""
$tenant_id = ""
$list_id = ""
$FilePath = '/Exports/IPV4s.csv'

#Configure headers
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "multipart/form-data")
$headers.Add("Authorization", $api_key)

#Setup file to be uplaoded
$multipartContent = [System.Net.Http.MultipartFormDataContent]::new()
$multipartFile = $FilePath
$FileStream = [System.IO.FileStream]::new($multipartFile, [System.IO.FileMode]::Open)
$fileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
$fileHeader.Name = "file"
$fileHeader.FileName = $FilePath
$fileContent = [System.Net.Http.StreamContent]::new($FileStream)
$fileContent.Headers.ContentDisposition = $fileHeader
$multipartContent.Add($fileContent)

$body = $multipartContent

#Send CSV to Axon
$response = Invoke-RestMethod "https://api.na01.prod.boreas.cloud/list-svc/v1/tenants/$tenant_id/list-definitions/$list_id/list-items/import?headersNotIncluded=false" -Method 'PUT' -Headers $headers -Body $body
$response | ConvertTo-Json