Import-Module -Name "$psScriptRoot\src\SentinelTIUploadToolkit.psm1" -Force

##############################################################################################################
# Define variables for TI API Upload
##############################################################################################################
$AppId = ''
$AppSecret = ''
$TenantName = "demo.OnMicrosoft.com"
$workspaceId = ""

##############################################################################################################
# Open Phish
##############################################################################################################
$url = "https://openphish.com/feed.txt"
$response = Get-IOCUrlContent -Url $url

##############################################################################################################
# OpenPhish Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'OpenPhish'
$ValidDays = 1
$Name = 'OpenPhish'
$Description = 'OpenPhish'
$Confidence = 85
$TLP = 'white'
$IOCType = "Url"
$Labels = '["malicious", "indicator"]'
$ExternalReferenceSourceName = 'OpenPhish'
$ExternalReferenceDescription = 'OpenPhish'
$ExternalReferenceUrl = 'https://openphish.com/feed.txt'

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
