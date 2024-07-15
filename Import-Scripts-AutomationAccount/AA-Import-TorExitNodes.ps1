#Requires -Module "SentinelTIUploadToolkit"

Import-Module -Name "SentinelTIUploadToolkit"

##############################################################################################################
# Define variables for TI API Upload
##############################################################################################################
$workspaceId = ""

##############################################################################################################
# TOR Exit Nodes
##############################################################################################################
$url = "https://check.torproject.org/torbulkexitlist"
$response = Get-IOCIPRawContent -Url $url

##############################################################################################################
# TOR Exit Nodes Threat-Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'TORExitNodes'
$ValidDays = 1
$Name = 'TORExitNodes'
$Description = 'TOR Exit Nodes AA'
$Confidence = 100
$TLP = 'white'
$IOCType = "IPv4"
$Labels = '["Tor", "indicator","botnet"]'
$ExternalReferenceSourceName = 'website'
$ExternalReferenceDescription = 'Tor Exit Nodes'
$ExternalReferenceUrl = 'https://metrics.torproject.org/collector.html#type-tordnsel'

$StixJsonOutPut = ConvertTo-STIXJson -Data $response `
                                  -SourceSystem $SourceSystem `
                                  -ValidDays $ValidDays `
                                  -Name $Name `
                                  -Description $Description `
                                  -Confidence $Confidence `
                                  -Labels $Labels `
                                  -TLP $TLP `
                                  -ExternalReferenceSourceName $ExternalReferenceSourceName `
                                  -ExternalReferenceDescription $ExternalReferenceDescription `
                                  -ExternalReferenceUrl $ExternalReferenceUrl `
                                  -StixPattern $IOCType

#####################################################################################################
# Sentinel Upload
#####################################################################################################
Write-Output "Starting TI Import from $SourceSystem"
Import-ThreatIntelligenceIndicators_MI -WorkspaceId $workspaceId -Indicators $StixJsonOutPut
