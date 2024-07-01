Import-Module -Name "$psScriptRoot\src\SentinelTIUploadToolkit.psm1" -Force

##############################################################################################################
# Define variables for TI API Upload
##############################################################################################################
$AppId = ''
$AppSecret = ''
$TenantName = "demo.OnMicrosoft.com"
$workspaceId = ""

##############################################################################################################
# Blocklist.de - Bots
##############################################################################################################
$url = "https://lists.blocklist.de/lists/bots.txt"
$response = Get-IOCIPContent -Url $url


##############################################################################################################
# DigitalSide Threat-Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'Blocklistde'
$ValidDays = 1
$Name = 'Bllocklistde'
$Description = 'Blocklist.de - Bots'
$Confidence = 85
$TLP = 'white'
$IOCType = "IPv4"
$Labels = '["malicious", "indicator","botnet"]'
$ExternalReferenceSourceName = 'website'
$ExternalReferenceDescription = 'Blocklist.de - Bots'
$ExternalReferenceUrl = 'https://www.blocklist.de/en/index.html'

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
