
    <#
    .SYNOPSIS
    Imports threat intelligence indicators to Azure Sentinel using the Threat Intelligence upload API.

    .DESCRIPTION
    This function Imports threat intelligence indicators to Azure Sentinel using a System Managed Identity for authentication and authorization.
    
    .PARAMETER WorkspaceId
    The ID of the Azure Sentinel workspace where indicators will be uploaded.

    .PARAMETER Indicators
    STIX JSON content containing the threat intelligence indicators to upload.

    .EXAMPLE
    Import-ThreatIntelligenceIndicators_MI -WorkspaceId $workspaceId -Indicators $StixJsonOutPut

    Imports threat intelligence indicators stored in $jsonOutput to the Azure Sentinel workspace specified by WorkspaceId.

    .LINK
    https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api
    https://learn.microsoft.com/en-us/azure/sentinel/upload-indicators-api

    #>
    function Import-ThreatIntelligenceIndicators_MI {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceId,

        [Parameter(Mandatory = $true)]
        $Indicators
    )

    # Ensure you do not inherit an AzContext in your runbook
    Disable-AzContextAutosave -Scope Process
    # Connect to Azure with system-assigned managed identity
    Connect-AzAccount -Identity | Out-Null

        $resource= "?resource=https://management.azure.com/" 
        $url = $env:IDENTITY_ENDPOINT + $resource 
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
        $Headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
        $Headers.Add("Metadata", "True") 
        $accessToken = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $Headers
        Write-Output $accessToken.access_token

        $ApiHeaders = @{
            Authorization = "$($accessToken.token_type) $($accessToken.access_token)"
         }


    # Construct Threat Intelligence upload API endpoint URL
    $Uri = "https://sentinelus.azure-api.net/$WorkspaceId/threatintelligence:upload-indicators?api-version=2022-07-01"

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
                    $Results = Invoke-RestMethod -Uri $Uri -Headers $ApiHeaders -Body $batch -Method POST -ContentType "application/json"

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

