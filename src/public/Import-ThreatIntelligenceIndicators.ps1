    <#
    .SYNOPSIS
    Import threat intelligence indicators to Microsoft Sentinel using the Threat Intelligence upload API.

    .DESCRIPTION
    This function imports threat intelligence indicators to Azure Sentinel using client credentials for authentication and authorization.

    .PARAMETER AppId
    The Application (Client) ID used for authentication.

    .PARAMETER AppSecret
    The Application (Client) Secret used for authentication.

    .PARAMETER TenantName
    The name of the Azure AD tenant where the application is registered.

    .PARAMETER WorkspaceId
    The ID of the Azure Sentinel workspace where indicators will be uploaded.

    .PARAMETER Indicators
    STIX JSON content containing the threat intelligence indicators to upload.

    .EXAMPLE
    $AppId = '50ba0ff6-6g2f-4896-8f88-f63d0a61b04e'
    $AppSecret = ''
    $TenantName = "demo.OnMicrosoft.com"
    $workspaceId = "81547333-052d-420c-bb06-edc426462c22"

    Import-ThreatIntelligenceIndicators -AppId $AppId -AppSecret $AppSecret -TenantName $TenantName -WorkspaceId $workspaceId -Indicators $StixJsonOutPut

    Uploads threat intelligence indicators stored in $jsonOutput to the Azure Sentinel workspace specified by WorkspaceId.

    .LINK
    https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api
    https://learn.microsoft.com/en-us/azure/sentinel/upload-indicators-api

    #>
    function Import-ThreatIntelligenceIndicators {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppId,

        [Parameter(Mandatory = $true)]
        [string]$AppSecret,

        [Parameter(Mandatory = $true)]
        [string]$TenantName,

        [Parameter(Mandatory = $true)]
        [string]$WorkspaceId,

        [Parameter(Mandatory = $true)]
        $Indicators
    )

    #The scope of the authentication request. Typically, this is "https://management.azure.com/.default" for Azure resources.
    $Scope = "https://management.azure.com/.default"
    # Construct token endpoint URL
    $Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token"

    # Create body for authentication request
    $Body = @{
        client_id     = $AppId
        client_secret = $AppSecret
        scope         = $Scope
        grant_type    = 'client_credentials'
    }

    $PostSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method      = 'POST'
        Body        = $Body
        Uri         = $Url
    }

    # Request the access token
    $TokenRequest = Invoke-RestMethod @PostSplat

    # Create headers for API request
    $Header = @{
        Authorization = "$($TokenRequest.token_type) $($TokenRequest.access_token)"
    }

    # Construct Threat Intelligence upload API endpoint URL
    #$Uri = "https://sentinelus.azure-api.net/$WorkspaceId/threatintelligence:upload-indicators?api-version=2022-07-01" #deprecated
    $Uri = "https://sentinelus.azure-api.net/$WorkspaceId/threatintelligenceindicators:upload?api-version=2022-07-01"


    try {
        # Convert JSON string to PowerShell object
        $jsonObject = ConvertFrom-Json $Indicators
        # Splitting into batches of 100 entries
        $batchSize = 100
        $batchNumber = 1
        $batchedObjects = @()

        for ($i = 0; $i -lt $jsonObject.value.Count; $i += $batchSize) {
            $batch = $jsonObject.value[$i..($i + $batchSize - 1)]
            $batchedObject = @{
                sourcesystem = $jsonObject.sourcesystem
                value = $batch
            }
            $batchedObjects += $batchedObject

            # For demonstration, outputting the batch number and its count
            Write-Output "Batch $batchNumber has $($batch.Count) entries"
            $batchNumber++
        }

        # Output the batched objects (you can further process or display as needed)
        $bCount=1
        foreach ($batchedObject in $batchedObjects) {
            $batch = ConvertTo-Json $batchedObject -Depth 10  # Adjust Depth based on object complexity
            Write-Output "Batch $bCount of $($batchedObjects.Count) batches"

            do {
                try {
                    # Upload indicators to Azure Sentinel
                    $Results = Invoke-RestMethod -Uri $Uri -Headers $Header -Body $batch -Method POST -ContentType "application/json"

                    # Output the results as JSON
                    $Results | ConvertTo-Json

                    # Check if status code is 429 (Too Many Requests)
                    if ($Results.StatusCode -eq 429) {
                        # Parse the error message to get the retry time
                        $ErrorMessage = ConvertFrom-Json $Results.Content
                        if ($ErrorMessage.message -match 'Try again in (\d+) seconds') {
                            $RetryAfter = [int]$matches[1]
                            Write-Output "Received 429 status code. Waiting for $RetryAfter seconds before retrying..."
                            Start-Sleep -Seconds $RetryAfter
                        } else {
                            Write-Error "Unexpected error message format: $($ErrorMessage.message)"
                        }
                    }
                }
                catch {
                    Write-Error "Error uploading indicators: $_"
                }
            } while ($Results.StatusCode -eq 429)
        $bCount++
        }
    }
    catch {
        Write-Error "Error processing indicators: $_"
    }
}

