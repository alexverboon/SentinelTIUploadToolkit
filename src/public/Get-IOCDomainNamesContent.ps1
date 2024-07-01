    <#
    .SYNOPSIS
    Retrieves domain names from a specified URL and returns them as PowerShell objects.

    .DESCRIPTION
    Retrieves the content from a specified URL and extracts domain names, returning each domain name as a PowerShell object with a 'DomainName' attribute.

    .PARAMETER Url
    The URL of the text file or web resource to retrieve content from.

    .EXAMPLE
    Get-DomainNames -Url "https://example.com/domain-names.txt"

    Retrieves domain names from the specified URL and returns them as PowerShell objects.
    #>
    function Get-IOCDomainNamesContent {
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
            # Initialize an array to store domain name objects
            $domainObjects = @()

            # Split the content into lines and process each line
            $contentLines = $response.Content -split "`r?`n"
            foreach ($line in $contentLines) {
                # Match domain names using regex (simplified pattern)
                $domainMatches = [regex]::Matches($line, '(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?')
                foreach ($match in $domainMatches) {
                    # Create a PSObject with DomainName attribute
                    
                    $domainObject = [PSCustomObject]@{
                        DomainName = $match.Value
                    }
                    # Add the domain object to the array
                    $domainObjects += $domainObject
                }
            }

            # Output the array of domain name objects
            Write-Output $domainObjects
        } else {
            Write-Error "Failed to retrieve content. Status code: $($response.StatusCode)"
        }
    } catch {
        Write-Error "Error retrieving content from $Url`: $_"
    }
    }


