 <#
    .SYNOPSIS
    Converts a collection of IOCs (Indicators of Compromise) into STIX JSON format.

    .DESCRIPTION
    Converts a collection of IOCs (Indicators of Compromise) into STIX (Structured Threat Information eXpression) JSON format, based on specified parameters.

    .PARAMETER Input
    Array of objects containing IOCs to be converted.

    .PARAMETER SourceSystem
    Name of the source system or tool generating the STIX JSON.

    .PARAMETER ValidDays
    Number of days the IOC should remain valid from the current date.

    .PARAMETER Name
    Name of the indicator.

    .PARAMETER Description
    Description of the indicator.

    .PARAMETER Confidence
    Confidence level in the validity of the indicator.

    .PARAMETER Labels
    Array of labels associated with the indicator.

    .PARAMETER TLP
    Traffic Light Protocol (TLP) level of the indicator. Valid values are "White", "green", "amber", or "red".

    .PARAMETER StixPattern
    STIX pattern type for the indicator. Valid values are "IPv4", "IPv6", "Domain", "Url", "email", "filemd5", or "filename".

    .PARAMETER ExternalReferenceSourceName
    Source name of the external reference for the indicator.

    .PARAMETER ExternalReferenceDescription
    Description of the external reference for the indicator.

    .PARAMETER ExternalReferenceUrl
    URL of the external reference for the indicator.

    .EXAMPLE
    ConvertTo-STIXJson -Response $response -SourceSystem "SUNDAY" -ValidDays 30 -Name "TIDEMO2" -Description "Indicator of malicious activity" -Confidence "High" -Labels @("malicious", "phishing") -TLP "green" -StixPattern "IPv4" -ExternalReferenceSourceName "Example Source" -ExternalReferenceDescription "Description of the reference" -ExternalReferenceUrl "https://example.com"

    Converts an array of IP addresses stored in $response into STIX JSON format with the specified parameters.
    #>
    function ConvertTo-STIXJson {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data,

        [Parameter(Mandatory = $true)]
        [string]$SourceSystem,

        [Parameter(Mandatory = $true)]
        [int]$ValidDays,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Confidence,

        [Parameter(Mandatory = $true)]
        [array]$Labels,

        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "White",  
            "green",  
            "amber",  
            "red"   
        )]
        [string]$TLP,

        [Parameter(Mandatory = $true)]
        [Validateset(
            "IPv4",
            "IPv6",
            "Domain",
            "Url",
            "email",
            "filemd5",
            "filename"
        )]
        [string]$StixPattern,

        [Parameter(Mandatory = $true)]
        [string]$ExternalReferenceSourceName,

        [Parameter(Mandatory = $true)]
        [string]$ExternalReferenceDescription,

        [Parameter(Mandatory = $true)]
        [string]$ExternalReferenceUrl
    )

 # Map TLP levels to corresponding marking definitions
    switch ($TLP.ToLower()) {
        "white" {
            $tlpmarking = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
        }
        "green" {
            $tlpmarking = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
        }
        "amber" {
            $tlpmarking = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        }
        "red" {
            $tlpmarking = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
        }
        default {
            throw "Unsupported TLP level: $TLP"
        }
    }

        switch ($StixPattern.ToLower()) {
        "IPv4" {
            $StixPatternstring = "ipv4-addr:value ="
        }
        "IPv6" {
            $StixPatternstring = "ipv6-addr:value ="
        }
        "Domain" {
            $StixPatternstring = "domain-name:value ="
        }
        "Url" {
            $StixPatternstring = "url:value ="
        }
        "email" {
            $StixPatternstring = "email-addr:value ="
        }
        "filemd5" {
            $StixPatternstring = "file:hashes.MD5"
        }
        "filename"{
            $StixPatternstring = "file:name ="
        }

                default {
            throw "Unsupported Stix Pattern: $StixPattern"
        }
    }

    # Initialize an empty array to store JSON strings
    $jsonStrings = @()

    foreach ($item in $Data) {
        
        switch ($StixPattern.ToLower()) {
        "IPv4" {
                    $IocValue = $item.IP 
        }
        "IPv6" {
                    $IocValue = $item.IP 
        }
        "Domain" {
                    $IocValue = $item.DomainName 
        }
        "Url" {
                    $IocValue = $item.Url 
        }
        "email" {
                    $IocValue = $item.email 
        }
        "filemd5" {
                    $IocValue = $item.md5 
        }
        "filename"{
                    $IocValue = $item.filename 
        }
                default {
            throw "Unsupported Stix Pattern: $StixPattern"
        }}
       
        #$IocValue = $item.IP 

        $currentDateTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffffffZ"
        $validDateTime = (Get-Date).AddDays($ValidDays) 
        $validDateTime = $validDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
        $pattern = "[$StixPatternstring '$IocValue']"
        $identifier = (New-Guid).Guid
        $id = "indicator--$identifier"

        $jsonObject = @"
        {
            "created": "$currentDateTime",
            "id": "$id",
            "modified": "$currentDateTime",
            "pattern": "$pattern",
            "pattern_type": "stix",
            "spec_version": "2.1",
            "type": "indicator",
            "name": "$Name",
            "description": "$Description",
            "valid_from": "$currentDateTime",
            "valid_until": "$validDateTime",
            "confidence": "$Confidence",
            "labels": $Labels,
            "object_marking_refs": [
                "$tlpmarking"
            ],
            "external_references": [
                {
                    "source_name": "$ExternalReferenceSourceName",
                    "description": "$ExternalReferenceDescription",
                    "url": "$ExternalReferenceUrl"
                }
            ]
        }
"@

        $jsonStrings += $jsonObject
    }
    $jsonArray = @"
{
  "sourcesystem": "$SourceSystem",
  "indicators": [
    $($jsonStrings -join ",`n")
  ]
}
"@
return $jsonArray
}