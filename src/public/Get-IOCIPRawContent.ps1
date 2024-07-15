
    <#
    .SYNOPSIS
    Retrieves IP addresses from a specified URL and returns them as PowerShell objects.

    .DESCRIPTION
    Retrieves the content from a specified URL and extracts IP addresses, returning each IP address as a PowerShell object with an 'IP' attribute.

    .PARAMETER Url
    The URL of the text file or web resource to retrieve content from.

    .EXAMPLE
    Get-IOCIPRawContent -Url "https://check.torproject.org/torbulkexitlist"

    Retrieves IP addresses from the specified URL and returns them as PowerShell objects.
    #>
    function Get-IOCIPRawContent {
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
            # Initialize an array to store IP objects
            $ipObjects = @()

            # Split the content into lines and process each line
            $contentLines = $response.RawContent -split "`r?`n"
            foreach ($line in $contentLines) {
                # Match IP addresses using regex
                $ipMatches = [regex]::Matches($line, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
                foreach ($match in $ipMatches) {
                    # Create a PSObject with IP attribute
                    $ipObject = [PSCustomObject]@{
                        IP = $match.Value
                    }
                    # Add the IP object to the array
                    $ipObjects += $ipObject
                }
            }

            # Output the array of IP objects
            Write-Output $ipObjects
        } else {
            Write-Error "Failed to retrieve content. Status code: $($response.StatusCode)"
        }
    } catch {
        Write-Error "Error retrieving content from $Url`: $_"
    }
    }