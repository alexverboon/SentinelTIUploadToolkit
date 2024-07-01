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
# DigitalSide Threat-Intel domain
##############################################################################################################
$url = "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"
$response = Get-IOCDomainNamesContent -Url $url

##############################################################################################################
# DigitalSide Threat-Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'DigitalSide'
$ValidDays = 1
$Name = 'DIGITALSIDE.IT'
$Description = 'DigitalSide Threat-Intel'
$Confidence = 85
$TLP = 'white'
$IOCType = "Domain"
$Labels = '["malicious", "indicator","malware"]'
$ExternalReferenceSourceName = 'website'
$ExternalReferenceDescription = 'DigitalSide Threat-Intel Repository'
$ExternalReferenceUrl = 'https://osint.digitalside.it'

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



##############################################################################################################
# DigitalSide Threat-Intel Url
##############################################################################################################
$url = "https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt"
$response = Get-IOCUrlContent -Url $url

##############################################################################################################
# DigitalSide Threat-Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'DigitalSide'
$ValidDays = 1
$Name = 'DIGITALSIDE.IT'
$Description = 'DigitalSide Threat-Intel'
$Confidence = 85
$TLP = 'white'
$IOCType = "Url"
$Labels = '["malicious", "indicator","malware"]'
$ExternalReferenceSourceName = 'website'
$ExternalReferenceDescription = 'DigitalSide Threat-Intel Repository'
$ExternalReferenceUrl = 'https://osint.digitalside.it'

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


##############################################################################################################
# DigitalSide Threat-Intel Url
##############################################################################################################
$url = "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"
$response = Get-IOCIPContent -Url $url

##############################################################################################################
# DigitalSide Threat-Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'DigitalSide'
$ValidDays = 1
$Name = 'DIGITALSIDE.IT'
$Description = 'DigitalSide Threat-Intel'
$Confidence = 85
$TLP = 'white'
$IOCType = "IPv4"
$Labels = '["malicious", "indicator","malware"]'
$ExternalReferenceSourceName = 'website'
$ExternalReferenceDescription = 'DigitalSide Threat-Intel Repository'
$ExternalReferenceUrl = 'https://osint.digitalside.it'

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
