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
# Tor All Nodes - https://www.dan.me.uk/tornodes
##############################################################################################################
$url = "https://www.dan.me.uk/torlist/?full"
$response = Get-IOCIPRawContent -Url $url


##############################################################################################################
# TOR ALL Nodes Threat-Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'TORAllNodes'
$ValidDays = 1
$Name = 'TORAllNodes'
$Description = 'TOR All Nodes'
$Confidence = 100
$TLP = 'white'
$IOCType = "IPv4"
$Labels = '["Tor", "indicator","botnet"]'
$ExternalReferenceSourceName = 'website'
$ExternalReferenceDescription = 'Tor All Nodes - www.dan.me.uk'
$ExternalReferenceUrl = 'https://www.dan.me.uk/tornodes'

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
