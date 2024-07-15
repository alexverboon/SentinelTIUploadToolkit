$modulePath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'src\SentinelTIUploadToolkit.psm1'
Import-Module -Name "$modulePath" -Force

##############################################################################################################
# Define variables for TI API Upload
##############################################################################################################
$AppId = ''
$AppSecret = ''
$TenantName = "demo.OnMicrosoft.com"
$workspaceId = ""

##############################################################################################################
# TOR Exit Nodes
##############################################################################################################
$url = "https://check.torproject.org/torbulkexitlist"
$response = Get-IOCIPRawContent -Url $url


##############################################################################################################
# DigitalSide Threat-Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'TORExitNodes'
$ValidDays = 1
$Name = 'TORExitNodes'
$Description = 'TOR Exit Nodes'
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
Import-ThreatIntelligenceIndicators -AppId $AppId -AppSecret $AppSecret -TenantName $TenantName -WorkspaceId $workspaceId -Indicators $StixJsonOutPut
