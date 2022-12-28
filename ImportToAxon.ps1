$api_key = ""
$tenant_id = ""
$list_id = ""

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "multipart/form-data")
$headers.Add("Authorization", $api_key)

$multipartContent = [System.Net.Http.MultipartFormDataContent]::new()
$multipartFile = '/C:/Exports/IPV4s.csv'
$FileStream = [System.IO.FileStream]::new($multipartFile, [System.IO.FileMode]::Open)
$fileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
$fileHeader.Name = "file"
$fileHeader.FileName = "/C:/Exports/IPV4s.csv"
$fileContent = [System.Net.Http.StreamContent]::new($FileStream)
$fileContent.Headers.ContentDisposition = $fileHeader
$multipartContent.Add($fileContent)

$body = $multipartContent

$response = Invoke-RestMethod 'https://api.na01.prod.boreas.cloud/list-svc/v1/tenants/' + $tenant_id + '/list-definitions/' + $list_id + '/list-items/import?headersNotIncluded=false' -Method 'POST' -Headers $headers -Body $body
$response | ConvertTo-Json