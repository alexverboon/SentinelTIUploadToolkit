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
# Get Cloud Intel IP Addresses
##############################################################################################################
$ApiKey = 'key{democloudintel}'
$Email = 'democloudintel@himanshuanand.com'
$Date = '06-03-2024'  
$response = Get-IOCCloudIntel -ApiKey $ApiKey -Email $Email -Date $Date
##############################################################################################################
# Cloud Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'CloudIntel'
$ValidDays = 30
$Name = 'CloudIntel'
$Description = 'CloudIntel ' + $Date
$Confidence = 85
$TLP = 'white'
$IOCType = "IPv4"
$Labels = '["malicious", "indicator"]'
$ExternalReferenceSourceName = 'GitHub'
$ExternalReferenceDescription = 'CloudIntel repository'
$ExternalReferenceUrl = 'https://github.com/unknownhad/CloudIntel'

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
