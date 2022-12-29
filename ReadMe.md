# LogRhythm Axon Import script for AlienVault OTX
## Overview
This project is to demonstrate the ease of importing data from a free intel feed into the LogRhythm Axon platform using publically available APIs.  This version will sort out new data to append to the Axon lists, other approaches could be taken to replace the list in the future.

## Requirements
* PowerShell 7 or newer
* OTX Account https://otx.alienvault.com/
* LogRhythm Axon API credentials
* LogRhythm Axon List ID

## Usage
1. Update both scripts with necessary OTX key, API key and List ID
2. Run the OTXDataGathere.ps1 script to download threat IP data (default download location is C:\Export)
3. Run the ImportToAxon.ps1 script to upload list to LogRhythm Axon
