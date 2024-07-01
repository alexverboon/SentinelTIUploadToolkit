    <#
    .SYNOPSIS
    Retrieves URLs from a specified URL and returns them as PowerShell objects.

    .DESCRIPTION
    Retrieves the content from a specified URL and extracts URLs, returning each URL as a PowerShell object with a 'Url' attribute.

    .PARAMETER Url
    The URL of the text file or web resource to retrieve content from.

    .EXAMPLE
   Get-IOCUrlContent -Url "https://example.com/urls.txt"

    Retrieves URLs from the specified URL and returns them as PowerShell objects.
    #>
    function Get-IOCUrlContent {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    try {
        # Retrieve content from the URL
        $response = Invoke-WebRequest -Uri $Url -ErrorAction Stop

        # Check if the request was successful (status code 200)
        if ($response.StatusCode -eq 200) {
            # Initialize an array to store URL objects
            $urlObjects = @()

            # Split the content into lines and process each line
            $contentLines = $response.Content -split "`r?`n"
            foreach ($line in $contentLines) {
                # Match URLs using regex (simplified pattern)
                $urlMatches = [regex]::Matches($line, 'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
                foreach ($match in $urlMatches) {
                    # Create a PSObject with Url attribute
                    $urlObject = [PSCustomObject]@{
                        Url = $match.Value 
                    }
                    # Add the URL object to the array
                    $urlObjects += $urlObject
                }
            }

            # Output the array of URL objects
            Write-Output $urlObjects
        } else {
            Write-Error "Failed to retrieve content. Status code: $($response.StatusCode)"
        }
    } catch {
        Write-Error "Error retrieving content from $Url`: $_"
    }
}

