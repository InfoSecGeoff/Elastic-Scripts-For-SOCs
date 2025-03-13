<#
.SYNOPSIS
Retrieves Elastic Cloud billing information in the form of several reports

.PARAMETER CloudApiKey
This API key is generated via the Elastic Cloud console. It is totally different from the Elasticsearch API keys managed in Kibana.

.PARAMETER OrgID
OrgID values can be retrieved from the Deployments page in Elastic Cloud

.PARAMETER ReportType
Options are Overview, Charts, Deployments, and ItemizedCosts

.EXAMPLE 
.\ElasticCloudBillingReport.ps1 -CloudApiKey "<your cloud API key>" -OrgId "<your org ID>" -ReportType "Deployments"

.EXAMPLE 
.\ElasticCloudBillingReport.ps1 -CloudApiKey "<your cloud API key>" -OrgId "<your org ID>" -FromDate "2025-01-22T02:00:00Z" -ToDate "2025-01-25T00:00:00Z" -ReportType "Deployments"
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$CloudApiKey,
    
    [Parameter(Mandatory=$true)]
    [string]$OrgId,
    
    [Parameter(Mandatory=$false)]
    [string]$FromDate = (Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0).ToString("yyyy-MM-ddTHH:mm:ssZ"),
    
    [Parameter(Mandatory=$false)]
    [string]$ToDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ"),
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Overview", "Charts", "Deployments", "ItemizedCosts")]
    [string]$ReportType = "Overview"
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{
    "Authorization" = "ApiKey $CloudApiKey"
    "Content-Type" = "application/json"
}
$baseUrl = "https://api.elastic-cloud.com/api/v1"

function Invoke-ElasticCloudApi {
    param (
        [string]$Endpoint,
        [hashtable]$QueryParams = @{}
    )
    
    $url = "$baseUrl$Endpoint"
    
    if ($QueryParams.Count -gt 0) {
        $queryString = $QueryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" } | Join-String -Separator "&"
        $url = "$url`?$queryString"
    }
    
    Write-Verbose "Making request to: $url"
    
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        return $response
    }
    catch {
        Write-Error "Error calling Elastic Cloud API: $_"
        if ($_.ErrorDetails.Message) {
            Write-Error "Details: $($_.ErrorDetails.Message)"
        }
        throw
    }
}

$queryParams = @{
    "from" = $FromDate
    "to" = $ToDate
}

switch ($ReportType) {
    "Overview" {
        Write-Host "Retrieving cost overview for organization $OrgId" -ForegroundColor Cyan
        $endpoint = "/billing/costs/$OrgId"
        $result = Invoke-ElasticCloudApi -Endpoint $endpoint -QueryParams $queryParams
        
        Write-Host "`nCost Overview Summary:" -ForegroundColor Green
        Write-Host "Total Cost: $($result.costs.total)"
        Write-Host "Trial Costs: $($result.trials)"
        Write-Host "Hourly Rate: $($result.hourly_rate)"
        
        if ($result.balance) {
            Write-Host "`nBalance Information:" -ForegroundColor Green
            Write-Host "Available Balance: $($result.balance.available)"
            Write-Host "Remaining Balance: $($result.balance.remaining)"
        }
        
        return $result
    }
    
    "Charts" {
        Write-Host "Retrieving cost charts for organization $OrgId" -ForegroundColor Cyan
        $endpoint = "/billing/costs/$OrgId/charts"
        $queryParams["bucketing_strategy"] = "daily"
        $result = Invoke-ElasticCloudApi -Endpoint $endpoint -QueryParams $queryParams
        return $result
    }
    
    "Deployments" {
        Write-Host "Retrieving deployment costs for organization $OrgId" -ForegroundColor Cyan
        $endpoint = "/billing/costs/$OrgId/deployments"
        $result = Invoke-ElasticCloudApi -Endpoint $endpoint -QueryParams $queryParams
        
        Write-Host "`nDeployment Costs Summary:" -ForegroundColor Green
        Write-Host "Total Cost: $($result.total_cost)"
        Write-Host "`nDeployment Breakdown:" -ForegroundColor Green

        foreach ($deployment in $result.deployments) {
            Write-Host "  - Deployment: $($deployment.deployment_name) ($($deployment.deployment_id))"
            Write-Host "    Total Cost: $($deployment.costs.total)"
            Write-Host "    Hourly Rate: $($deployment.hourly_rate)"
            Write-Host "    Period: $($deployment.period.start) to $($deployment.period.end)"
            Write-Host ""
        }
        return $result
    }
    
    "ItemizedCosts" {
        Write-Host "Retrieving itemized costs for organization $OrgId" -ForegroundColor Cyan
        $endpoint = "/billing/costs/$OrgId/items"
        $result = Invoke-ElasticCloudApi -Endpoint $endpoint -QueryParams $queryParams
        
        Write-Host "`nItemized Costs Summary:" -ForegroundColor Green
        Write-Host "Total Cost: $($result.costs.total)"
        
        if ($result.resources -and $result.resources.Count -gt 0) {
            Write-Host "`nResource Breakdown:" -ForegroundColor Green
            foreach ($resource in $result.resources) {
                Write-Host "  - $($resource.name) ($($resource.kind))"
                Write-Host "    Hours: $($resource.hours)"
                Write-Host "    Instance Count: $($resource.instance_count)"
                Write-Host "    Price: $($resource.price) ($($resource.price_per_hour)/hour)"
                Write-Host ""
            }
        }
        
        return $result
    }
}
