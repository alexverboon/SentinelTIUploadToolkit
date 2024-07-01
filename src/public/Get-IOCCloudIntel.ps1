<#
.Synopsis

    Retrieves malicious IP information from the CloudIntel API based on the specified date.

.DESCRIPTION

    This function makes a GET request to the CloudIntel API to fetch malicious IP information for a specific date.
    It requires an API key and email address for authentication.

.PARAMETER ApiKey

    The API key required for authentication with the CloudIntel API.

.PARAMETER Email

    The email address associated with the API key.

.PARAMETER Date

    The date for which malicious IP information is to be retrieved (format: MM-DD-YYYY).

.EXAMPLE

    Get-IOCCloudIntel -ApiKey 'key{democloudintel}' -Email 'democloudintel@himanshuanand.com' -Date '02-02-2024'
    Retrieves malicious IP information for the date '02-02-2024' using the specified API key and email.

.LINK
    https://github.com/unknownhad/CloudIntel
    https://api.cloudintel.info/

.NOTES
    Author: Alex Verboon
    Date: 30.06.2024
#>
    function Get-IOCCloudIntel {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$Email,

        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    $ApiUrl = 'https://api.cloudintel.info/v1/maliciousip'
    $Headers = @{
        'x-api-key' = $ApiKey
        'x-email' = $Email
    }
    $requestUrl = "$apiUrl" + "?date=$date"
    try {
        $Response = Invoke-RestMethod -Uri $RequestUrl -Method Get -Headers $Headers
        return $Response
    }
    catch {
        Write-Error "Failed to retrieve data from API. $_"
    }
    }




