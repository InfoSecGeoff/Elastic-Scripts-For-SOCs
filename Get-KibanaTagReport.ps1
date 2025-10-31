<#
.SYNOPSIS
    Generates a comprehensive tag usage report with expandable asset listings

.DESCRIPTION
    Creates an interactive HTML report with:
    - Summary statistics cards
    - Usage analytics charts
    - Top 25 most used tags table
    - Complete sortable table of all tags
    - Expandable tag cards showing all assets
    - Search/filter functionality

.PARAMETER KibanaUrl
    The URL of your Kibana instance
    
.PARAMETER KibanaApiKey
    API key for authenticating with Kibana
    
.PARAMETER OutputPath
    Directory path for saving output files (default: current directory)
    
.PARAMETER OutputFormat
    Output format: HTML

.EXAMPLE
    .\Get-KibanaTagReport.ps1 `
        -KibanaUrl "https://your-kibana.com:5601" `
        -KibanaApiKey "your-api-key"

.NOTES
    Author: Geoff Tankersley
    Version: 2.0
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$KibanaUrl,
    
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$KibanaApiKey,
    
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if (!(Test-Path $_ -PathType Container)) {
            if (!(Test-Path (Split-Path $_ -Parent))) {
                throw "Parent directory does not exist: $(Split-Path $_ -Parent)"
            }
        }
        return $true
    })]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("JSON", "CSV", "HTML")]
    [string]$OutputFormat = "HTML"
)

$script:version = "2.0"

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

function Test-InputParameters {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KibanaUrl,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $errors = @()
    
    if ($KibanaUrl -notmatch '^https?://') {
        $errors += "Kibana URL must start with http:// or https://"
    }
    
    if ($ApiKey.Length -lt 10) {
        $errors += "API Key appears to be too short."
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
    
    return $errors
}

function Invoke-KibanaApi {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Endpoint,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$KibanaUrl,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKey
    )
    
    $url = "$($KibanaUrl.TrimEnd('/'))$Endpoint"
    
    Write-Log "Calling Kibana API: $url" -Level "DEBUG"
    
    try {
        $headers = @{
            "Authorization" = "ApiKey $ApiKey"
            "kbn-xsrf" = "true"
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET -TimeoutSec 30 -ErrorAction Stop
        Write-Log "API call successful" -Level "DEBUG"
        return $response
    }
    catch {
        Write-Log "Error calling Kibana API: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Get-AllTags {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KibanaUrl,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey
    )
    
    Write-Log "Retrieving all tags from Kibana..." -Level "INFO"
    
    $endpoint = "/api/saved_objects/_find?type=tag&per_page=10000"
    $response = Invoke-KibanaApi -Endpoint $endpoint -KibanaUrl $KibanaUrl -ApiKey $ApiKey
    
    if ($null -eq $response -or -not $response.saved_objects) {
        Write-Log "Failed to retrieve tags" -Level "ERROR"
        return @{}
    }
    
    Write-Log "Found $($response.saved_objects.Count) tags" -Level "SUCCESS"
    
    $tags = @{}
    foreach ($tagObj in $response.saved_objects) {
        $tags[$tagObj.id] = [PSCustomObject]@{
            Id = $tagObj.id
            Name = $tagObj.attributes.name
            Description = if ($tagObj.attributes.description) { $tagObj.attributes.description } else { "" }
            Color = if ($tagObj.attributes.color) { $tagObj.attributes.color } else { "#64748b" }
            UsageCount = 0
            UsedByTypes = @{}
            UsedByObjects = @()
        }
    }
    
    return $tags
}

function Get-TagUsageStatistics {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KibanaUrl,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Tags
    )
    
    Write-Log "Analyzing tag usage across all saved objects..." -Level "INFO"
    
    $objectTypes = @(
        "dashboard",
        "visualization", 
        "search",
        "lens",
        "map",
        "canvas-workpad",
        "index-pattern"
    )
    
    $totalObjectsScanned = 0
    
    foreach ($type in $objectTypes) {
        Write-Log "  Scanning $type objects..." -Level "DEBUG"
        
        $endpoint = "/api/saved_objects/_find?type=$type&per_page=10000"
        $response = Invoke-KibanaApi -Endpoint $endpoint -KibanaUrl $KibanaUrl -ApiKey $ApiKey
        
        if ($response -and $response.saved_objects) {
            $objectCount = $response.saved_objects.Count
            if ($objectCount -gt 0) {
                Write-Log "    Found $objectCount $type objects" -Level "DEBUG"
            }
            $totalObjectsScanned += $objectCount
            
            foreach ($obj in $response.saved_objects) {
                if ($obj.references) {
                    foreach ($ref in $obj.references) {
                        if ($ref.type -eq "tag" -and $Tags.ContainsKey($ref.id)) {
                            $Tags[$ref.id].UsageCount++
                            
                            if (-not $Tags[$ref.id].UsedByTypes.ContainsKey($type)) {
                                $Tags[$ref.id].UsedByTypes[$type] = 0
                            }
                            $Tags[$ref.id].UsedByTypes[$type]++
                            
                            $objTitle = if ($obj.attributes.title) { $obj.attributes.title } else { "Untitled" }
                            $Tags[$ref.id].UsedByObjects += [PSCustomObject]@{
                                Type = $type
                                Id = $obj.id
                                Title = $objTitle
                                UpdatedAt = if ($obj.updated_at) { $obj.updated_at } else { "" }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Write-Log "Scanned $totalObjectsScanned saved objects" -Level "SUCCESS"
    
    $usedTags = ($Tags.Values | Where-Object { $_.UsageCount -gt 0 }).Count
    $unusedTags = ($Tags.Values | Where-Object { $_.UsageCount -eq 0 }).Count
    $totalUsages = ($Tags.Values | Measure-Object -Property UsageCount -Sum).Sum
    
    return @{
        Tags = $Tags
        TotalTags = $Tags.Count
        UsedTags = $usedTags
        UnusedTags = $unusedTags
        TotalUsages = $totalUsages
        TotalObjectsScanned = $totalObjectsScanned
    }
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Statistics,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = "kibana_tag_usage_detailed_$timestamp.html"
    $fullPath = Join-Path $OutputPath $fileName
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $sortedTags = $Statistics.Tags.Values | Sort-Object -Property UsageCount -Descending
    
    function ConvertTo-SafeHtml {
        param([string]$Text)
        if ([string]::IsNullOrWhiteSpace($Text)) {
            return ""
        }
        return [System.Web.HttpUtility]::HtmlEncode($Text.Trim())
    }
    
    function ConvertTo-SafeJs {
        param([string]$Text)
        if ([string]::IsNullOrWhiteSpace($Text)) {
            return ""
        }
        return $Text.Trim() -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`r", '' -replace "`n", '\n'
    }
    
    # JS data for tags
    $tagsJsonArray = @()
    foreach ($tag in $sortedTags) {
        $assetsArray = @()
        foreach ($asset in ($tag.UsedByObjects | Sort-Object Type, Title)) {
            $assetsArray += @{
                type = ConvertTo-SafeJs $asset.Type
                title = ConvertTo-SafeJs $asset.Title
                id = ConvertTo-SafeJs $asset.Id
                updatedAt = ConvertTo-SafeJs $asset.UpdatedAt
            }
        }
        
        $usedByTypesObj = @{}
        foreach ($kvp in $tag.UsedByTypes.GetEnumerator()) {
            $usedByTypesObj[$kvp.Key] = $kvp.Value
        }
        
        $tagsJsonArray += @{
            id = ConvertTo-SafeJs $tag.Id
            name = ConvertTo-SafeJs $tag.Name
            description = ConvertTo-SafeJs $tag.Description
            color = ConvertTo-SafeJs $tag.Color
            usageCount = $tag.UsageCount
            usedByTypes = $usedByTypesObj
            assets = $assetsArray
        }
    }
    
    $tagsJson = $tagsJsonArray | ConvertTo-Json -Depth 10 -Compress
    
    # Top 10
    $top10Tags = $sortedTags | Where-Object { $_.UsageCount -gt 0 } | Select-Object -First 10
    
    if ($top10Tags -and $top10Tags.Count -gt 0) {
        $top10Labels = ($top10Tags | ForEach-Object { 
            $safeName = ConvertTo-SafeJs $_.Name
            "'$safeName'"
        }) -join ","
        $top10Values = ($top10Tags | ForEach-Object { $_.UsageCount }) -join ","
    } else {
        $top10Labels = ""
        $top10Values = ""
    }
    
    $usedCount = $Statistics.UsedTags
    $unusedCount = $Statistics.UnusedTags
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kibana Tag Usage Report - Detailed</title>
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
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #005571 0%, #009eb4 100%);
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
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
            transition: transform 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
        }
        
        .summary-card .icon {
            font-size: 3rem;
            margin-bottom: 15px;
        }
        
        .summary-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #005571;
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
            color: #005571;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #e2e8f0;
        }
        
        .search-bar {
            margin-bottom: 30px;
            position: sticky;
            top: 0;
            z-index: 100;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .search-input {
            width: 100%;
            padding: 15px 20px;
            font-size: 1.1rem;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            transition: border-color 0.3s;
        }
        
        .search-input:focus {
            outline: none;
            border-color: #009eb4;
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
        }
        
        .table-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow: hidden;
            max-height: 800px;
            overflow-y: auto;
            margin-bottom: 40px;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th {
            background: linear-gradient(135deg, #005571 0%, #009eb4 100%);
            color: white;
            padding: 20px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        .table td {
            padding: 20px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }
        
        .table tr:hover {
            background: #f8fafc;
        }
        
        .tag-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
            background: #009eb4;
            color: white;
            margin-right: 10px;
            white-space: nowrap;
        }
        
        .usage-count {
            font-weight: 700;
            font-size: 1.2rem;
            color: #005571;
        }
        
        .type-breakdown {
            color: #64748b;
            font-size: 0.9rem;
            margin-top: 5px;
        }
        
        .type-badge {
            display: inline-block;
            background: #e2e8f0;
            color: #475569;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.85rem;
            margin: 2px;
        }
        
        .tag-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .tag-card:hover {
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        
        .tag-header {
            padding: 25px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #f8fafc;
            transition: background 0.3s;
        }
        
        .tag-header:hover {
            background: #f1f5f9;
        }
        
        .tag-info {
            display: flex;
            align-items: center;
            flex: 1;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .tag-color {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            flex-shrink: 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .tag-name {
            font-size: 1.3rem;
            font-weight: 600;
            color: #1e293b;
        }
        
        .tag-count {
            background: #009eb4;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
        }
        
        .tag-types {
            color: #64748b;
            font-size: 0.9rem;
        }
        
        .expand-icon {
            font-size: 1.5rem;
            color: #64748b;
            transition: transform 0.3s;
            flex-shrink: 0;
        }
        
        .tag-card.expanded .expand-icon {
            transform: rotate(180deg);
        }
        
        .tag-details {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        
        .tag-card.expanded .tag-details {
            max-height: 3000px;
        }
        
        .tag-description {
            padding: 15px 25px;
            color: #64748b;
            font-style: italic;
            background: #fefce8;
            border-left: 4px solid #fbbf24;
        }
        
        .assets-list {
            padding: 25px;
        }
        
        .asset-type-group {
            margin-bottom: 25px;
        }
        
        .asset-type-header {
            font-weight: 600;
            color: #005571;
            font-size: 1.1rem;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }
        
        .asset-item {
            padding: 12px 15px;
            margin-bottom: 8px;
            background: #f8fafc;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
        }
        
        .asset-item:hover {
            background: #e2e8f0;
        }
        
        .asset-title {
            font-weight: 500;
            color: #1e293b;
            flex: 1;
            word-break: break-word;
        }
        
        .asset-id {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            color: #64748b;
            margin-left: 15px;
            flex-shrink: 0;
        }
        
        .no-results {
            text-align: center;
            padding: 60px;
            color: #64748b;
            font-size: 1.2rem;
        }
        
        .unused-tag {
            opacity: 0.5;
        }
        
        .footer {
            background: #f1f5f9;
            padding: 30px;
            text-align: center;
            color: #64748b;
            border-top: 1px solid #e2e8f0;
        }
        
        @media (max-width: 768px) {
            .chart-grid {
                grid-template-columns: 1fr;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏷️ Kibana Tag Usage Report - Detailed View</h1>
            <p>Generated on $reportDate</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="icon">🏷️</div>
                <div class="value">$($Statistics.TotalTags)</div>
                <div class="label">Total Tags</div>
            </div>
            <div class="summary-card">
                <div class="icon">✅</div>
                <div class="value">$($Statistics.UsedTags)</div>
                <div class="label">Tags In Use</div>
            </div>
            <div class="summary-card">
                <div class="icon">⚠️</div>
                <div class="value">$($Statistics.UnusedTags)</div>
                <div class="label">Unused Tags</div>
            </div>
            <div class="summary-card">
                <div class="icon">📊</div>
                <div class="value">$($Statistics.TotalUsages)</div>
                <div class="label">Total Tag Usages</div>
            </div>
            <div class="summary-card">
                <div class="icon">📁</div>
                <div class="value">$($Statistics.TotalObjectsScanned)</div>
                <div class="label">Objects Scanned</div>
            </div>
        </div>
        
        <div class="content">
"@

    if ($top10Tags -and $top10Tags.Count -gt 0) {
        $htmlContent += @"
            <div class="section">
                <h2 class="section-title">📈 Usage Analytics</h2>
                <div class="chart-grid">
                    <div class="chart-container">
                        <canvas id="topTagsChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="usageDistributionChart"></canvas>
                    </div>
                </div>
            </div>
"@
    }

    # Top 25
    $usedTags = $sortedTags | Where-Object { $_.UsageCount -gt 0 }
    if ($usedTags -and $usedTags.Count -gt 0) {
        $htmlContent += @"
            <div class="section">
                <h2 class="section-title">🏆 Top 25 Most Used Tags</h2>
                <div class="table-container">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Rank</th>
                                <th>Tag Name</th>
                                <th>Usage Count</th>
                                <th>Object Types</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
"@

        $rank = 1
        foreach ($tag in ($usedTags | Select-Object -First 25)) {
            $tagName = ConvertTo-SafeHtml $tag.Name
            
            $typeBreakdownParts = @()
            foreach ($kvp in ($tag.UsedByTypes.GetEnumerator() | Sort-Object Key)) {
                $typeBreakdownParts += "$(ConvertTo-SafeHtml $kvp.Key): $($kvp.Value)"
            }
            $typeBreakdown = $typeBreakdownParts -join ", "
            
            $description = ConvertTo-SafeHtml $tag.Description
            
            $htmlContent += @"
                            <tr>
                                <td><strong>#$rank</strong></td>
                                <td>
                                    <span class="tag-badge">$tagName</span>
                                </td>
                                <td class="usage-count">$($tag.UsageCount)</td>
                                <td class="type-breakdown">$typeBreakdown</td>
                                <td>$description</td>
                            </tr>
"@
            $rank++
        }

        $htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
    }

    # All tags
    $htmlContent += @"
            <div class="section">
                <h2 class="section-title">📋 All Tags (Sorted by Usage)</h2>
                <div class="table-container">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Tag Name</th>
                                <th>Usage Count</th>
                                <th>Object Types</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
"@

    foreach ($tag in $sortedTags) {
        $tagName = ConvertTo-SafeHtml $tag.Name
        $rowClass = if ($tag.UsageCount -eq 0) { "class='unused-tag'" } else { "" }
        
        $typeBreakdownHtml = ""
        if ($tag.UsedByTypes.Count -gt 0) {
            $badges = @()
            foreach ($kvp in ($tag.UsedByTypes.GetEnumerator() | Sort-Object Key)) {
                $typeName = ConvertTo-SafeHtml $kvp.Key
                $badges += "<span class='type-badge'>$typeName`: $($kvp.Value)</span>"
            }
            $typeBreakdownHtml = $badges -join " "
        } else {
            $typeBreakdownHtml = "<span style='color: #ef4444;'>Not used</span>"
        }
        
        $description = ConvertTo-SafeHtml $tag.Description
        
        $htmlContent += @"
                            <tr $rowClass>
                                <td>
                                    <span class="tag-badge">$tagName</span>
                                </td>
                                <td class="usage-count">$($tag.UsageCount)</td>
                                <td class="type-breakdown">$typeBreakdownHtml</td>
                                <td>$description</td>
                            </tr>
"@
    }

    $htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@

    # Expandable tag details
    $htmlContent += @"
            <div class="section">
                <h2 class="section-title">🔍 Tag Details & Assets (Click to Expand)</h2>
                
                <div class="search-bar">
                    <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search tags by name, description, or asset..." />
                </div>
                
                <div id="tagsContainer">
                    <!-- Tags will be rendered here by JavaScript -->
                </div>
                
                <div id="noResults" class="no-results" style="display: none;">
                    No tags found matching your search.
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Kibana Tag Usage Report Script v$script:version</p>
            <p>Click on any tag in the bottom section to expand and view all associated assets</p>
        </div>
    </div>
    
    <script>
        // Tag data
        const allTags = $tagsJson;
        
        // Escape HTML for display
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Render tags
        function renderTags(tags) {
            const container = document.getElementById('tagsContainer');
            const noResults = document.getElementById('noResults');
            
            if (tags.length === 0) {
                container.innerHTML = '';
                noResults.style.display = 'block';
                return;
            }
            
            noResults.style.display = 'none';
            
            const htmlParts = tags.map(tag => {
                const typeBreakdownBadges = Object.entries(tag.usedByTypes || {})
                    .map(([type, count]) => {
                        return '<span class="type-badge">' + escapeHtml(type) + ': ' + count + '</span>';
                    })
                    .join(' ');
                
                const assetsByType = {};
                (tag.assets || []).forEach(asset => {
                    if (!assetsByType[asset.type]) {
                        assetsByType[asset.type] = [];
                    }
                    assetsByType[asset.type].push(asset);
                });
                
                const assetsHtmlParts = Object.entries(assetsByType)
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([type, assets]) => {
                        const assetItems = assets
                            .sort((a, b) => a.title.localeCompare(b.title))
                            .map(asset => {
                                return '<div class="asset-item">' +
                                    '<span class="asset-title">' + escapeHtml(asset.title) + '</span>' +
                                    '<span class="asset-id">' + escapeHtml(asset.id) + '</span>' +
                                '</div>';
                            })
                            .join('');
                        
                        return '<div class="asset-type-group">' +
                            '<div class="asset-type-header">' + 
                            escapeHtml(type.charAt(0).toUpperCase() + type.slice(1)) + 
                            ' (' + assets.length + ')</div>' +
                            assetItems +
                        '</div>';
                    })
                    .join('');
                
                const descriptionHtml = tag.description ? 
                    '<div class="tag-description">' + escapeHtml(tag.description) + '</div>' : '';
                
                const assetsContentHtml = (tag.assets || []).length > 0 ? 
                    assetsHtmlParts : 
                    '<p style="color: #64748b; text-align: center; padding: 20px;">No assets tagged</p>';
                
                return '<div class="tag-card" data-tag-id="' + escapeHtml(tag.id) + '">' +
                    '<div class="tag-header" onclick="toggleTag(\'' + escapeHtml(tag.id) + '\')">' +
                        '<div class="tag-info">' +
                            '<div class="tag-color" style="background-color: ' + escapeHtml(tag.color) + ';"></div>' +
                            '<div class="tag-name">' + escapeHtml(tag.name) + '</div>' +
                            '<div class="tag-count">' + tag.usageCount + ' uses</div>' +
                            '<div class="tag-types">' + typeBreakdownBadges + '</div>' +
                        '</div>' +
                        '<div class="expand-icon">▼</div>' +
                    '</div>' +
                    descriptionHtml +
                    '<div class="tag-details">' +
                        '<div class="assets-list">' +
                            assetsContentHtml +
                        '</div>' +
                    '</div>' +
                '</div>';
            });
            
            container.innerHTML = htmlParts.join('');
        }
        
        // Toggle tag expansion
        function toggleTag(tagId) {
            const card = document.querySelector('[data-tag-id="' + tagId + '"]');
            if (card) {
                card.classList.toggle('expanded');
            }
        }
        
        // Search functionality
        function searchTags(query) {
            query = query.toLowerCase().trim();
            
            if (!query) {
                renderTags(allTags);
                return;
            }
            
            const filtered = allTags.filter(tag => {
                if (tag.name && tag.name.toLowerCase().includes(query)) return true;
                if (tag.description && tag.description.toLowerCase().includes(query)) return true;
                return (tag.assets || []).some(asset => 
                    asset.title && asset.title.toLowerCase().includes(query)
                );
            });
            
            renderTags(filtered);
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            renderTags(allTags);
            
            const searchInput = document.getElementById('searchInput');
            searchInput.addEventListener('input', (e) => {
                searchTags(e.target.value);
            });
        });
"@

    if ($top10Tags -and $top10Tags.Count -gt 0) {
        $htmlContent += @"
        
        // Charts
        Chart.defaults.color = '#64748b';
        Chart.defaults.borderColor = '#e2e8f0';
        
        const topTagsCtx = document.getElementById('topTagsChart').getContext('2d');
        new Chart(topTagsCtx, {
            type: 'bar',
            data: {
                labels: [$top10Labels],
                datasets: [{
                    label: 'Usage Count',
                    data: [$top10Values],
                    backgroundColor: 'rgba(0, 158, 180, 0.8)',
                    borderColor: 'rgb(0, 158, 180)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Top 10 Most Used Tags',
                        font: { size: 16 }
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
        
        const usageDistCtx = document.getElementById('usageDistributionChart').getContext('2d');
        new Chart(usageDistCtx, {
            type: 'doughnut',
            data: {
                labels: ['Tags In Use', 'Unused Tags'],
                datasets: [{
                    data: [$usedCount, $unusedCount],
                    backgroundColor: ['#22c55e', '#ef4444'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Tag Usage Distribution',
                        font: { size: 16 }
                    },
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
"@
    }

    $htmlContent += @"
    </script>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $fullPath -Encoding UTF8
    Write-Log "HTML report saved to: $fullPath" -Level "SUCCESS"
    
    try {
        Start-Process $fullPath
        Write-Log "Report opened in browser" -Level "SUCCESS"
    }
    catch {
        Write-Log "Could not open browser automatically. Please manually open: $fullPath" -Level "WARNING"
    }
    
    return $fullPath
}

function Start-TagUsageReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KibanaUrl,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputFormat
    )
    
    Write-Log "Starting Kibana Tag Usage Report v$script:version" -Level "INFO"
    Write-Log "Kibana URL: $KibanaUrl" -Level "INFO"
    Write-Log "Output Format: $OutputFormat" -Level "INFO"
    
    Write-Log "Validating input parameters..." -Level "INFO"
    $validationErrors = Test-InputParameters -KibanaUrl $KibanaUrl -ApiKey $ApiKey -OutputPath $OutputPath
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "Input validation failed:" -Level "ERROR"
        foreach ($validationerror in $validationErrors) {
            Write-Log "  - $validationerror" -Level "ERROR"
        }
        throw "Input validation failed."
    }
    
    Write-Log "Input validation passed" -Level "SUCCESS"
    
    # Get all tags
    $tags = Get-AllTags -KibanaUrl $KibanaUrl -ApiKey $ApiKey
    
    if ($tags.Count -eq 0) {
        Write-Log "No tags found in Kibana" -Level "WARNING"
        return
    }
    
    # Get usage statistics
    $statistics = Get-TagUsageStatistics -KibanaUrl $KibanaUrl -ApiKey $ApiKey -Tags $tags
    
    Write-Host "`nUsage Summary:" -ForegroundColor Cyan
    Write-Log "  Total Tags: $($statistics.TotalTags)" -Level "INFO"
    Write-Log "  Tags In Use: $($statistics.UsedTags)" -Level "SUCCESS"
    Write-Log "  Unused Tags: $($statistics.UnusedTags)" -Level "WARNING"
    Write-Log "  Total Tag Usages: $($statistics.TotalUsages)" -Level "INFO"
    Write-Host ""
    
    # Export HTML report
    $outputFile = Export-HtmlReport -Statistics $statistics -OutputPath $OutputPath
    
    Write-Log "Tag usage report completed successfully!" -Level "SUCCESS"
    
    if ($outputFile) {
        return $outputFile
    }
}

# Main
try {
    Write-Log "Initializing Kibana Tag Usage Report Script v$script:version" -Level "INFO"
    
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    
    $KibanaUrl = $KibanaUrl.TrimEnd('/')
    
    $result = Start-TagUsageReport `
        -KibanaUrl $KibanaUrl `
        -ApiKey $KibanaApiKey `
        -OutputPath $OutputPath `
        -OutputFormat $OutputFormat
    
    Write-Log "Script completed successfully!" -Level "SUCCESS"
    
    if ($result) {
        Write-Log "Output saved to: $result" -Level "INFO"
    }
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level "ERROR"
    
    if ($_.ScriptStackTrace) {
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "DEBUG"
    }
    
    exit 1
}
