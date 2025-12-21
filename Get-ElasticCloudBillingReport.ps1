<#
.SYNOPSIS
    Generates detailed HTML billing reports from the Elastic Cloud Billing API.

.DESCRIPTION
    This script connects to the Elastic Cloud Billing API to retrieve and analyze cost data
    for an organization. It generates a comprehensive HTML report with interactive charts,
    deployment breakdowns, and cost analysis over a specified time period.
    
    The report includes:
    - Total cost and daily averages
    - Cost trend visualizations (line, pie, and bar charts)
    - Per-deployment cost breakdowns
    - Cost breakdown by type (compute, storage, data transfer)
    - Itemized costs for each deployment
    
    Requirements:
    - Valid Elastic Cloud API key with Billing Admin role
    - Organization ID from Elastic Cloud Console
    - Internet connectivity to api.elastic-cloud.com
    - PowerShell 5.1 or later

.PARAMETER CloudApiKey
    Your Elastic Cloud API key. Must have 'Billing admin' role assigned.
    Find or create API keys at: https://cloud.elastic.co/deployment-features/keys

.PARAMETER OrganizationId
    Your Elastic Cloud Organization ID. Find this in the Elastic Cloud Console:
    Avatar menu (top right) > Organization > Copy Organization ID

.PARAMETER OutputPath
    Directory path where the HTML report will be saved. Defaults to current directory.
    Script will create the directory if it doesn't exist.

.PARAMETER DaysBack
    Number of days of billing history to analyze (1-365). Default is 30 days.
    Recommend: 
    - hour granularity: max 7 days
    - day granularity: 7-90 days
    - week granularity: 14-180 days
    - month granularity: 60+ days

.PARAMETER CostGranularity
    Data aggregation level for cost trends. Valid values: hour, day, week, month
    Default is "day". Choose based on your analysis period:
    - hour: detailed view for short periods (max 7 days recommended)
    - day: standard daily analysis (most common)
    - week: weekly trends for longer periods
    - month: monthly view for annual analysis

.EXAMPLE
    .\ElasticBillingReport.ps1 -CloudApiKey "abc123..." -OrganizationId "12345"
    
    Generates a 30-day billing report with daily granularity in the current directory.

.EXAMPLE
    .\ElasticBillingReport.ps1 -CloudApiKey "abc123..." -OrganizationId "12345" -DaysBack 7 -CostGranularity "hour"
    
    Generates a 7-day report with hourly cost breakdown for detailed recent analysis.

.EXAMPLE
    .\ElasticBillingReport.ps1 -CloudApiKey "abc123..." -OrganizationId "12345" -OutputPath "C:\Reports\Elastic" -DaysBack 90 -CostGranularity "week"
    
    Generates a 90-day report with weekly granularity and saves to specified directory.

.NOTES
     Author     : Geoff Tankersley
    Version    : 1.3
    
    API Endpoints Used:
    - /api/v1/billing/costs/{org_id}
    - /api/v1/billing/costs/{org_id}/deployments
    - /api/v1/billing/costs/{org_id}/deployments/{deployment_id}/items
    - /api/v1/billing/costs/{org_id}/charts
    
    Troubleshooting:
    - 401 errors: Verify API key is correct and hasn't expired
    - 403 errors: Ensure API key has 'Billing admin' role
    - 404 errors: Verify Organization ID is correct
    - Connection errors: Check firewall allows HTTPS to api.elastic-cloud.com
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$CloudApiKey,
    
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$OrganizationId,
    
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if (!(Test-Path $_ -PathType Container)) {
            if (!(Test-Path (Split-Path $_ -Parent))) {
                throw "Parent directory does not exist: $(Split-Path $_ -Parent)"
            }
        }
        return $true
    })]
    [string]$OutputPath = ".\",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("hour", "day", "week", "month")]
    [string]$CostGranularity = "day"
)

$script:version = "1.3"

function Test-InputParameters {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [string]$OrgId,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysBack,
        
        [Parameter(Mandatory=$true)]
        [string]$Granularity
    )
    
    $errors = @()
    
    if ($ApiKey.Length -lt 10) {
        $errors += "API Key appears to be too short. Please verify your Elastic Cloud API key."
    }
    
    if ($OrgId -notmatch '^[a-zA-Z0-9]+$' -or $OrgId.Length -lt 5) {
        $errors += "Organization ID appears to be invalid. It should be alphanumeric and at least 5 characters long."
    }
    
    $outputDir = if (Test-Path $OutputPath -PathType Container) { $OutputPath } else { Split-Path $OutputPath -Parent }
    if (!(Test-Path $outputDir)) {
        try {
            New-Item -ItemType Directory -Path $outputDir -Force -ErrorAction Stop | Out-Null
            Write-Log "Created output directory: $outputDir" -Level "INFO"
        }
        catch {
            $errors += "Cannot create output directory: $outputDir. Error: $($_.Exception.Message)"
        }
    }
    
    try {
        $testFile = Join-Path $OutputPath "test_$(Get-Random).tmp"
        "test" | Out-File -FilePath $testFile -ErrorAction Stop
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        $errors += "No write permission to output directory: $OutputPath"
    }
    
    switch ($Granularity) {
        "hour" {
            if ($DaysBack -gt 7) {
                $errors += "When using 'hour' granularity, DaysBack should not exceed 7 days to avoid too much data"
            }
        }
        "week" {
            if ($DaysBack -lt 14) {
                $errors += "When using 'week' granularity, DaysBack should be at least 14 days"
            }
        }
        "month" {
            if ($DaysBack -lt 60) {
                $errors += "When using 'month' granularity, DaysBack should be at least 60 days"
            }
        }
    }
    
    try {
        $testConnection = Test-NetConnection -ComputerName "api.elastic-cloud.com" -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue
        if (!$testConnection) {
            $errors += "Cannot reach api.elastic-cloud.com. Please check your internet connection."
        }
    }
    catch {
        Write-Log "Warning: Could not test internet connectivity" -Level "DEBUG"
    }
    
    return $errors
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "ERROR", "DEBUG", "SUCCESS", "WARNING")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        "INFO" = "White"
        "ERROR" = "Red"
        "DEBUG" = "Gray"
        "SUCCESS" = "Green"
        "WARNING" = "Yellow"
    }
    
    Write-Host "${timestamp}: ${Message}" -ForegroundColor $colors[$Level]
}

function Invoke-BillingApi {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Endpoint,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BillingApiKey,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$QueryParams = @{}
    )
    
    if (!$Endpoint.StartsWith("/api/")) {
        throw "Invalid endpoint format. Must start with '/api/'"
    }
    
    $essApi = "api.elastic-cloud.com"
    $url = "https://$essApi$Endpoint"
    
    if ($QueryParams.Count -gt 0) {
        $validParams = @()
        foreach ($param in $QueryParams.GetEnumerator()) {
            if ($param.Value -and $param.Value.ToString().Trim() -ne "") {
                $validParams += "$($param.Key)=$([System.Web.HttpUtility]::UrlEncode($param.Value))"
            }
        }
        if ($validParams.Count -gt 0) {
            $url += "?" + ($validParams -join "&")
        }
    }
    
    Write-Log "Calling: $url" -Level "DEBUG"
    
    try {
        $headers = @{
            "Authorization" = "ApiKey $BillingApiKey"
            "Accept" = "application/json"
            "User-Agent" = "ElasticBillingReporter/1.3"
        }
        
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop -TimeoutSec 30
        Write-Log "API call successful" -Level "DEBUG"
        return $response
    }
    catch [System.Net.WebException] {
        $statusCode = $_.Exception.Response.StatusCode
        $statusDescription = $_.Exception.Response.StatusDescription
        
        switch ($statusCode) {
            401 { Write-Log "Authentication failed. Please verify your API key." -Level "ERROR" }
            403 { Write-Log "Access forbidden. Your API key may not have billing permissions." -Level "ERROR" }
            404 { Write-Log "API endpoint not found: $Endpoint" -Level "ERROR" }
            429 { Write-Log "Rate limit exceeded. Please wait and try again." -Level "ERROR" }
            default { Write-Log "HTTP Error $statusCode`: $statusDescription" -Level "ERROR" }
        }
        return $null
    }
    catch {
        Write-Log "Error calling billing API: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Test-OrganizationAccess {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrganizationId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BillingApiKey
    )
    
    Write-Log "Testing access to organization: $OrganizationId" -Level "INFO"
    
    $response = Invoke-BillingApi -Endpoint "/api/v1/billing/costs/$OrganizationId" -BillingApiKey $BillingApiKey -QueryParams @{
        "from" = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ")
        "to" = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        "granularity" = "day"
    }
    
    if ($null -eq $response) {
        Write-Log "Cannot access organization $OrganizationId with provided API key" -Level "ERROR"
        return $false
    }
    
    Write-Log "Successfully verified access to organization: $OrganizationId" -Level "SUCCESS"
    return $true
}

function Get-OrganizationCosts {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrganizationId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BillingApiKey,
        
        [Parameter(Mandatory=$false)]
        [string]$From,
        
        [Parameter(Mandatory=$false)]
        [string]$To,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("hour", "day", "week", "month")]
        [string]$Granularity = "day"
    )
    
    Write-Log "Getting organization costs with granularity: $Granularity..." -Level "INFO"
    
    $endpoint = "/api/v1/billing/costs/$OrganizationId"
    $queryParams = @{
        "granularity" = $Granularity
    }
    
    if ($From -and $From.Trim() -ne "") { $queryParams["from"] = $From }
    if ($To -and $To.Trim() -ne "") { $queryParams["to"] = $To }
    
    $response = Invoke-BillingApi -Endpoint $endpoint -BillingApiKey $BillingApiKey -QueryParams $queryParams
    
    if ($null -eq $response) {
        Write-Log "Failed to get organization costs" -Level "ERROR"
        return $null
    }
    
    $costCount = if ($response.costs) { $response.costs.Count } else { 0 }
    Write-Log "Retrieved organization costs data with $costCount data points" -Level "SUCCESS"
    return $response
}

function Get-DeploymentsCosts {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrganizationId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BillingApiKey,
        
        [Parameter(Mandatory=$false)]
        [string]$From,
        
        [Parameter(Mandatory=$false)]
        [string]$To
    )
    
    Write-Log "Getting deployments costs..." -Level "INFO"
    
    $endpoint = "/api/v1/billing/costs/$OrganizationId/deployments"
    $queryParams = @{}
    
    if ($From -and $From.Trim() -ne "") { $queryParams["from"] = $From }
    if ($To -and $To.Trim() -ne "") { $queryParams["to"] = $To }
    
    $response = Invoke-BillingApi -Endpoint $endpoint -BillingApiKey $BillingApiKey -QueryParams $queryParams
    
    if ($null -eq $response) {
        Write-Log "Failed to get deployments costs" -Level "ERROR"
        return $null
    }
    
    $deploymentCount = if ($response.deployments) { $response.deployments.Count } else { 0 }
    Write-Log "Retrieved deployments costs for $deploymentCount deployments" -Level "SUCCESS"
    return $response
}

function Get-DeploymentItemizedCosts {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrganizationId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DeploymentId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BillingApiKey,
        
        [Parameter(Mandatory=$false)]
        [string]$From,
        
        [Parameter(Mandatory=$false)]
        [string]$To
    )
    
    Write-Log "Getting itemized costs for deployment: $DeploymentId" -Level "DEBUG"
    
    $endpoint = "/api/v1/billing/costs/$OrganizationId/deployments/$DeploymentId/items"
    $queryParams = @{}
    
    if ($From -and $From.Trim() -ne "") { $queryParams["from"] = $From }
    if ($To -and $To.Trim() -ne "") { $queryParams["to"] = $To }
    
    $response = Invoke-BillingApi -Endpoint $endpoint -BillingApiKey $BillingApiKey -QueryParams $queryParams
    
    if ($null -eq $response) {
        Write-Log "Failed to get itemized costs for deployment $DeploymentId" -Level "WARNING"
        return $null
    }
    
    return $response
}

function Get-BillingCharts {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrganizationId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BillingApiKey,
        
        [Parameter(Mandatory=$false)]
        [string]$From,
        
        [Parameter(Mandatory=$false)]
        [string]$To
    )
    
    Write-Log "Getting billing charts data..." -Level "INFO"
    
    $endpoint = "/api/v1/billing/costs/$OrganizationId/charts"
    $queryParams = @{}
    
    if ($From -and $From.Trim() -ne "") { $queryParams["from"] = $From }
    if ($To -and $To.Trim() -ne "") { $queryParams["to"] = $To }
    
    $response = Invoke-BillingApi -Endpoint $endpoint -BillingApiKey $BillingApiKey -QueryParams $queryParams
    
    if ($null -eq $response) {
        Write-Log "Failed to get billing charts (this endpoint may not be available)" -Level "WARNING"
        return $null
    }
    
    Write-Log "Retrieved billing charts data" -Level "SUCCESS"
    return $response
}

function ConvertTo-ChartData {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$ChartType,
        
        [Parameter(Mandatory=$true)]
        [string]$ChartId
    )
    
    switch ($ChartType) {
        "line" {
            $labels = @()
            $values = @()
            
            foreach ($item in $Data) {
                if ($item.timestamp) {
                    $labels += ($item.timestamp -replace 'T.*', '')
                } else {
                    $labels += "Unknown"
                }
                
                if ($item.total -ne $null) {
                    $values += [math]::Round([double]$item.total, 2)
                } else {
                    $values += 0
                }
            }
            
            $labelsJS = ($labels | ForEach-Object { "'$_'" }) -join ","
            $valuesJS = $values -join ","
            
            return @"
{
    type: 'line',
    data: {
        labels: [$labelsJS],
        datasets: [{
            label: 'Daily Cost (USD)',
            data: [$valuesJS],
            borderColor: 'rgb(59, 130, 246)',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            tension: 0.4
        }]
    },
    options: {
        responsive: true,
        plugins: {
            title: {
                display: true,
                text: 'Cost Trend Over Time'
            }
        },
        scales: {
            y: {
                beginAtZero: true,
                title: {
                    display: true,
                    text: 'Cost (USD)'
                }
            }
        }
    }
}
"@
        }
        "pie" {
            $labels = @()
            $values = @()
            
            foreach ($item in $Data) {
                $labels += $item.deployment_name -replace "'", "\'"
                
                if ($item.costs -and $item.costs.total -ne $null) {
                    $values += [math]::Round([double]$item.costs.total, 2)
                } else {
                    $values += 0
                }
            }
            
            $labelsJS = ($labels | ForEach-Object { "'$_'" }) -join ","
            $valuesJS = $values -join ","
            
            return @"
{
    type: 'pie',
    data: {
        labels: [$labelsJS],
        datasets: [{
            data: [$valuesJS],
            backgroundColor: [
                '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', 
                '#9966FF', '#FF9F40', '#8B5CF6', '#C9CBCF',
                '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'
            ]
        }]
    },
    options: {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
        title: {
            display: true,
            text: 'Cost Distribution by Deployment'
        },
        legend: {
            position: 'bottom',
            labels: {
                boxWidth: 12,
                font: {
                    size: 10
                }
            }
        }
    }
}
}
"@
        }
        "bar" {
            $labels = @()
            $values = @()
            
            foreach ($item in $Data) {
                $deploymentName = $item.deployment_name
                if ($deploymentName.Length -gt 20) {
                    $deploymentName = $deploymentName.Substring(0, 17) + "..."
                }
                $labels += $deploymentName -replace "'", "\'"
                
                if ($item.costs -and $item.costs.total -ne $null) {
                    $values += [math]::Round([double]$item.costs.total, 2)
                } else {
                    $values += 0
                }
            }
            
            $labelsJS = ($labels | ForEach-Object { "'$_'" }) -join ","
            $valuesJS = $values -join ","
            
            return @"
{
    type: 'bar',
    data: {
        labels: [$labelsJS],
        datasets: [{
            label: 'Cost (USD)',
            data: [$valuesJS],
            backgroundColor: 'rgba(59, 130, 246, 0.8)',
            borderColor: 'rgb(59, 130, 246)',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        plugins: {
            title: {
                display: true,
                text: 'Deployment Costs'
            }
        },
        scales: {
            y: {
                beginAtZero: true,
                title: {
                    display: true,
                    text: 'Cost (USD)'
                }
            },
            x: {
                ticks: {
                    maxRotation: 45,
                    minRotation: 45
                }
            }
        }
    }
}
"@
        }
    }
}

function Generate-HtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$BillingData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [string]$OrganizationId,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysBack
    )
    
    Write-Log "Generating HTML report..." -Level "INFO"
    
    $reportDate = Get-Date -Format "yyyy-MM-dd"
    $reportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $totalCost = 0
    $deploymentCount = 0
    $avgDailyCost = 0
    $dataPointCount = 0
    
    if ($BillingData.DeploymentsCosts -and $BillingData.DeploymentsCosts.deployments) {
        $deploymentCount = $BillingData.DeploymentsCosts.deployments.Count
        
        foreach ($deployment in $BillingData.DeploymentsCosts.deployments) {
            if ($deployment.costs -and $deployment.costs.total -ne $null) {
                $totalCost += [double]$deployment.costs.total
            }
        }
        
        $avgDailyCost = if ($DaysBack -gt 0) { 
            $totalCost / $DaysBack 
        } else { 0 }
    }
    
    if ($BillingData.OrgCosts -and $BillingData.OrgCosts.costs) {
        $dataPointCount = $BillingData.OrgCosts.costs.Count
    }
    
    $charts = @()
    
    if ($BillingData.OrgCosts -and $BillingData.OrgCosts.costs -and $BillingData.OrgCosts.costs.Count -gt 1) {
        $validCostData = $BillingData.OrgCosts.costs | Where-Object { 
            $_.total -ne $null -and $_.total -ne ""
        }
        
        if ($validCostData -and $validCostData.Count -gt 0) {
            $costTrendConfig = ConvertTo-ChartData -Data $validCostData -ChartType "line" -ChartId "costTrend"
            $charts += @{
                id = "costTrendChart"
                config = $costTrendConfig
            }
        }
    }
    
    if ($BillingData.DeploymentsCosts -and $BillingData.DeploymentsCosts.deployments) {
        $validDeployments = $BillingData.DeploymentsCosts.deployments | Where-Object {
            $_.deployment_name -and $_.deployment_name.ToString().Trim() -ne "" -and
            $_.costs -and $_.costs.total -ne $null -and [double]$_.costs.total -gt 0
        }
        
        if ($validDeployments -and $validDeployments.Count -gt 0) {
            $deploymentPieConfig = ConvertTo-ChartData -Data $validDeployments -ChartType "pie" -ChartId "deploymentPie"
            $charts += @{
                id = "deploymentPieChart"
                config = $deploymentPieConfig
            }
            
            $deploymentBarConfig = ConvertTo-ChartData -Data $validDeployments -ChartType "bar" -ChartId "deploymentBar"
            $charts += @{
                id = "deploymentBarChart"
                config = $deploymentBarConfig
            }
        }
    }

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elastic Cloud Billing Report - $reportDate</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .org-info {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            text-align: left;
        }
        
        .org-info strong {
            display: block;
            margin-bottom: 5px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px;
            padding: 40px;
            background: #f8fafc;
        }
        
        .summary-card {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }
        
        .summary-card .icon {
            font-size: 3rem;
            margin-bottom: 15px;
        }
        
        .summary-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #1e40af;
            margin-bottom: 10px;
        }
        
        .summary-card .label {
            font-size: 1rem;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 50px;
        }
        
        .section-title {
            font-size: 2rem;
            color: #1e40af;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #e2e8f0;
        }
        
        .chart-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }
        
        .chart-container {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            height: 400px;
            position: relative;
        }

        .chart-container canvas {
            max-width: 100%;
            max-height: 100%;
        }
        
        .table-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th {
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            color: white;
            padding: 20px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .table td {
            padding: 20px;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .table tr:hover {
            background: #f8fafc;
        }
        
        .cost-cell {
            font-weight: 600;
            color: #059669;
        }
        
        .deployment-name {
            font-weight: 600;
            color: #1e40af;
        }
        
        .footer {
            background: #f1f5f9;
            padding: 30px;
            text-align: center;
            color: #64748b;
            border-top: 1px solid #e2e8f0;
        }
        
        .no-data {
            text-align: center;
            padding: 60px;
            color: #64748b;
            font-style: italic;
        }
        
        @media (max-width: 768px) {
            .chart-grid {
                grid-template-columns: 1fr;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Elastic Cloud Billing Report</h1>
            <p>Generated on $reportTime</p>
            <div class="org-info">
                <strong>Organization ID:</strong> $OrganizationId
                <strong>Report Period:</strong> $DaysBack days
                <strong>Granularity:</strong> $CostGranularity
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="icon">💰</div>
                <div class="value">$([math]::Round($totalCost, 2))</div>
                <div class="label">Total Cost (USD)</div>
            </div>
            <div class="summary-card">
                <div class="icon">🚀</div>
                <div class="value">$deploymentCount</div>
                <div class="label">Active Deployments</div>
            </div>
            <div class="summary-card">
                <div class="icon">📊</div>
                <div class="value">$([math]::Round($avgDailyCost, 2))</div>
                <div class="label">Avg Daily Cost (USD)</div>
            </div>
            <div class="summary-card">
                <div class="icon">📅</div>
                <div class="value">$DaysBack</div>
                <div class="label">Days Analyzed</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2 class="section-title">📈 Cost Analysis</h2>
                <div class="chart-grid">
                    $(if ($charts.Count -gt 0) {
                        foreach ($chart in $charts) {
                            "<div class='chart-container'><canvas id='$($chart.id)'></canvas></div>"
                        }
                    } else {
                        "<div class='no-data'>No chart data available for the selected time period</div>"
                    })
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">🏗️ Deployment Details</h2>
                <div class="table-container">
                    $(if ($BillingData.DeploymentsCosts -and $BillingData.DeploymentsCosts.deployments) {
                        $validDeployments = $BillingData.DeploymentsCosts.deployments | Where-Object {
                            $_.deployment_name -and $_.deployment_name.ToString().Trim() -ne "" -and
                            $_.deployment_id -and $_.deployment_id.ToString().Trim() -ne ""
                        }
                        
                        if ($validDeployments) {
                            @"
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Deployment Name</th>
                                        <th>Deployment ID</th>
                                        <th>Total Cost (USD)</th>
                                        <th>Hourly Rate (USD)</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    $(foreach ($deployment in ($validDeployments | Sort-Object { if ($_.costs -and $_.costs.total) { [double]$_.costs.total } else { 0 } } -Descending)) {
                                        $costValue = if ($deployment.costs -and $deployment.costs.total -ne $null) {
                                            [math]::Round([double]$deployment.costs.total, 2)
                                        } else { "0.00" }
                                        
                                        $hourlyRate = if ($deployment.hourly_rate -ne $null) {
                                            [math]::Round([double]$deployment.hourly_rate, 4)
                                        } else { "0.00" }
                                        
                                        "<tr>
                                            <td class='deployment-name'>$([System.Web.HttpUtility]::HtmlEncode($deployment.deployment_name))</td>
                                            <td><code>$([System.Web.HttpUtility]::HtmlEncode($deployment.deployment_id))</code></td>
                                            <td class='cost-cell'>$costValue</td>
                                            <td class='cost-cell'>$hourlyRate</td>
                                        </tr>"
                                    })
                                </tbody>
                            </table>
"@
                        } else {
                            "<div class='no-data'>No valid deployment data available</div>"
                        }
                    } else {
                        "<div class='no-data'>No deployment data available</div>"
                    })
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">📋 Cost Breakdown by Type</h2>
                <div class="table-container">
                    $(if ($BillingData.OrgCosts -and $BillingData.OrgCosts.costs) {
                        $validCostEntries = $BillingData.OrgCosts.costs | Where-Object { 
                            $_.total -ne $null -and $_.dimensions
                        }
                        
                        if ($validCostEntries) {
                            $allDimensions = @{}
                            
                            foreach ($cost in $validCostEntries) {
                                foreach ($dimension in $cost.dimensions) {
                                    if ($allDimensions.ContainsKey($dimension.type)) {
                                        $allDimensions[$dimension.type] += [double]$dimension.cost
                                    } else {
                                        $allDimensions[$dimension.type] = [double]$dimension.cost
                                    }
                                }
                            }
                            
                            $totalAggregated = ($allDimensions.Values | Measure-Object -Sum).Sum
                            
                            @"
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Cost Type</th>
                                        <th>Amount (USD)</th>
                                        <th>Percentage</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    $(foreach ($dimensionType in ($allDimensions.Keys | Sort-Object { $allDimensions[$_] } -Descending)) {
                                        $cost = $allDimensions[$dimensionType]
                                        $percentage = if ($totalAggregated -gt 0) {
                                            [math]::Round(($cost / $totalAggregated) * 100, 1)
                                        } else { 0 }
                                        
                                        $typeLabel = switch ($dimensionType) {
                                            "capacity" { "Compute Capacity" }
                                            "data_in" { "Data Ingress" }
                                            "data_out" { "Data Egress" }
                                            "data_internode" { "Inter-node Transfer" }
                                            "storage_bytes" { "Storage (Bytes)" }
                                            "storage_api" { "Storage API Calls" }
                                            default { $dimensionType }
                                        }
                                        
                                        "<tr>
                                            <td>$typeLabel</td>
                                            <td class='cost-cell'>$([math]::Round($cost, 2))</td>
                                            <td>$percentage%</td>
                                        </tr>"
                                    })
                                </tbody>
                            </table>
"@
                        } else {
                            "<div class='no-data'>No valid cost breakdown data available</div>"
                        }
                    } else {
                        "<div class='no-data'>No cost breakdown data available</div>"
                    })
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Elastic Cloud Billing Report Generator v$script:version</p>
            <p>Organization: $OrganizationId | Report covers $DaysBack days of billing data</p>
        </div>
    </div>
    
    <script>
        $(if ($charts.Count -gt 0) {
            foreach ($chart in $charts) {
                @"
        
        const ctx$($chart.id) = document.getElementById('$($chart.id)').getContext('2d');
        new Chart(ctx$($chart.id), $($chart.config));
"@
            }
        })
    </script>
</body>
</html>
"@

    $fileName = "ElasticCloudBillingReport.html"
    $fullPath = Join-Path $OutputPath $fileName
    
    try {
        $htmlContent | Out-File -FilePath $fullPath -Encoding UTF8
        Write-Log "HTML report saved to: $fullPath" -Level "SUCCESS"
        return $fullPath
    }
    catch {
        Write-Log "Failed to save HTML report: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Start-BillingReport {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrgId,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [ValidateRange(1, 365)]
        [int]$DaysBack,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("hour", "day", "week", "month")]
        [string]$Granularity
    )
    
    Write-Log "Starting Elastic Cloud Billing Report Generator v$script:version" -Level "INFO"
    Write-Log "Parameters: OrgId=$OrgId, DaysBack=$DaysBack, Granularity=$Granularity, OutputPath=$OutputPath" -Level "INFO"
    
    Write-Log "Validating input parameters..." -Level "INFO"
    $validationErrors = Test-InputParameters -ApiKey $ApiKey -OrgId $OrgId -OutputPath $OutputPath -DaysBack $DaysBack -Granularity $Granularity
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "Input validation failed:" -Level "ERROR"
        foreach ($validationerror in $validationErrors) {
            Write-Log "  - $error" -Level "ERROR"
        }
        throw "Input validation failed. Please fix the errors above and try again."
    }
    
    Write-Log "Input validation passed" -Level "SUCCESS"
    
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Log "Created output directory: $OutputPath" -Level "INFO"
    }
    
    try {
        $toDate = Get-Date
        $fromDate = $toDate.AddDays(-$DaysBack)
        $fromStr = $fromDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $toStr = $toDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        Write-Log "Date range: $fromStr to $toStr" -Level "INFO"
        
        if ($fromDate -gt $toDate) {
            throw "Invalid date range: From date cannot be after To date"
        }
    }
    catch {
        Write-Log "Error calculating date range: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
    
    Write-Log "Testing access to organization: $OrgId" -Level "INFO"
    $hasAccess = Test-OrganizationAccess -OrganizationId $OrgId -BillingApiKey $ApiKey
    if (!$hasAccess) {
        throw "Cannot access organization $OrgId. Please verify your organization ID and API key permissions."
    }
    
    $billingData = @{}
    $dataCollectionErrors = @()
    
    try {
        Write-Log "Collecting organization cost data..." -Level "INFO"
        $billingData.OrgCosts = Get-OrganizationCosts -OrganizationId $OrgId -BillingApiKey $ApiKey -From $fromStr -To $toStr -Granularity $Granularity
        if (!$billingData.OrgCosts) {
            $dataCollectionErrors += "Failed to retrieve organization costs"
        } else {
            Write-Log "Organization costs retrieved successfully" -Level "SUCCESS"
        }
        
        Write-Log "Collecting deployment cost data..." -Level "INFO"
        $billingData.DeploymentsCosts = Get-DeploymentsCosts -OrganizationId $OrgId -BillingApiKey $ApiKey -From $fromStr -To $toStr
        if (!$billingData.DeploymentsCosts) {
            $dataCollectionErrors += "Failed to retrieve deployment costs"
        } else {
            Write-Log "Deployment costs retrieved successfully" -Level "SUCCESS"
        }
        
        Write-Log "Collecting billing charts data..." -Level "INFO"
        $billingData.Charts = Get-BillingCharts -OrganizationId $OrgId -BillingApiKey $ApiKey -From $fromStr -To $toStr
        
        if ($billingData.DeploymentsCosts -and $billingData.DeploymentsCosts.deployments) {
            Write-Log "Collecting itemized costs for deployments..." -Level "INFO"
            $billingData.ItemizedCosts = @{}
            $itemizedSuccessCount = 0
            
            foreach ($deployment in $billingData.DeploymentsCosts.deployments) {
                Write-Log "Getting itemized costs for: $($deployment.deployment_name)" -Level "DEBUG"
                $itemized = Get-DeploymentItemizedCosts -OrganizationId $OrgId -DeploymentId $deployment.deployment_id -BillingApiKey $ApiKey -From $fromStr -To $toStr
                if ($itemized) {
                    $billingData.ItemizedCosts[$deployment.deployment_id] = $itemized
                    $itemizedSuccessCount++
                }
            }
            
            Write-Log "Successfully retrieved itemized costs for $itemizedSuccessCount out of $($billingData.DeploymentsCosts.deployments.Count) deployments" -Level "INFO"
        }
    }
    catch {
        Write-Log "Critical error during data collection: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
    
    $hasUsableData = $billingData.OrgCosts -or $billingData.DeploymentsCosts
    if (!$hasUsableData) {
        throw "No usable billing data was retrieved. This could be due to API permissions, account type, or billing data availability."
    }
    
    if ($dataCollectionErrors.Count -gt 0) {
        Write-Log "Some data collection issues occurred (report will be generated with available data):" -Level "WARNING"
        foreach ($dataCollectionerror in $dataCollectionErrors) {
            if ($dataCollectionerror -and $dataCollectionerror.Trim() -ne "") {
                Write-Log "  - $error" -Level "WARNING"
            }
        }
    }
    
    Write-Log "Generating HTML report..." -Level "INFO"
    try {
        $reportPath = Generate-HtmlReport -BillingData $billingData -OutputPath $OutputPath -OrganizationId $OrgId -DaysBack $DaysBack
        
        if ($reportPath -and (Test-Path $reportPath)) {
            Write-Log "Report generation completed successfully!" -Level "SUCCESS"
            Write-Log "Report saved to: $reportPath" -Level "SUCCESS"
            
            $fileInfo = Get-Item $reportPath
            if ($fileInfo.Length -lt 1000) {
                Write-Log "Warning: Generated report file seems unusually small ($($fileInfo.Length) bytes)" -Level "WARNING"
            }
            
            Write-Log "Opening report in default browser..." -Level "INFO"
            try {
                Start-Process $reportPath
                Write-Log "Report opened successfully" -Level "SUCCESS"
            }
            catch {
                Write-Log "Could not open browser automatically. Please manually open: $reportPath" -Level "WARNING"
            }
            
            return $reportPath
        }
        else {
            throw "Report file was not created or is inaccessible"
        }
    }
    catch {
        Write-Log "Report generation failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

try {
    Write-Log "Initializing Elastic Cloud Billing Report Generator v$script:version" -Level "INFO"
    
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    
    if (-not $OrganizationId -or $OrganizationId.Trim() -eq "") {
        Write-Log "ERROR: Organization ID is required. You can find your Organization ID in the Elastic Cloud Console:" -Level "ERROR"
        Write-Log "1. Log in to https://cloud.elastic.co" -Level "INFO"
        Write-Log "2. Click on your avatar in the upper right corner" -Level "INFO"
        Write-Log "3. Select 'Organization'" -Level "INFO"
        Write-Log "4. Copy the Organization ID from the page" -Level "INFO"
        Write-Log " " -Level "INFO"
        Write-Log "Usage: .\ElasticBillingReport.ps1 -CloudApiKey 'your-api-key' -OrganizationId 'your-org-id'" -Level "INFO"
        exit 1
    }
    
    $reportPath = Start-BillingReport -ApiKey $CloudApiKey -OrgId $OrganizationId -OutputPath $OutputPath -DaysBack $DaysBack -Granularity $CostGranularity
    
    Write-Log "Script completed successfully!" -Level "SUCCESS"
    Write-Log "Report location: $reportPath" -Level "INFO"
}
catch {
    $errorMessage = if ($_.Exception.Message -and $_.Exception.Message.Trim() -ne "") { 
        $_.Exception.Message 
    } else { 
        "Unknown error occurred" 
    }
    Write-Log "Script execution failed: $errorMessage" -Level "ERROR"
    
    if ($_.ScriptStackTrace -and $_.ScriptStackTrace.Trim() -ne "") {
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "DEBUG"
    }
    
    if ($errorMessage -like "*organization*" -or $errorMessage -like "*403*" -or $errorMessage -like "*401*") {
        Write-Log " " -Level "INFO"
        Write-Log "Common solutions:" -Level "INFO"
        Write-Log "1. Verify your Organization ID is correct (found in Elastic Cloud Console > Organization)" -Level "INFO"
        Write-Log "2. Ensure your API key has 'Billing admin' role assigned" -Level "INFO"
        Write-Log "3. Check that your API key hasn't expired" -Level "INFO"
        Write-Log "4. Verify you're using the correct API key format (should be a long string)" -Level "INFO"
    }
    
    exit 1
}
