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
# abuse.ch SSLBL Botnet C2 IP Blacklist (IPs only)    
##############################################################################################################
$url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
$response = Get-IOCIPContent -Url $url

##############################################################################################################
# abuse.ch SSLBL Botnet C2 IP Blacklist (IPs only) Threat-Intel Sentinel TI Upload variables
##############################################################################################################
$SourceSystem = 'AbuseSSLBL'
$ValidDays = 1
$Name = 'Abuse.ch'
$Description = 'abuse.ch SSLBL Botnet C2 IP Blacklist (IPs only)'
$Confidence = 85
$TLP = 'white'
$IOCType = "IPv4"
$Labels = '["malicious", "indicator","Botnet","C2"]'
$ExternalReferenceSourceName = 'website'
$ExternalReferenceDescription = 'abuse.ch SSLBL Botnet C2 IP Blacklist (IPs only)'
$ExternalReferenceUrl = 'https://sslbl.abuse.ch/'

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
