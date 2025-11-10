<#
.SYNOPSIS
Retrieve all Fleet agent policies that have custom processors configured.

.DESCRIPTION
This script queries the Kibana Fleet API to retrieve all agent policies and identifies which ones
have custom processors configured at the package policy/input/stream level. This is useful for reviewing custom field accuracy across Fleet agent policies at scale.

.PARAMETER KibanaUrl
The URL of your Kibana instance

.PARAMETER ApiKey
Kibana API key for authentication

.PARAMETER ExportJson
Switch to export results as JSON file (optional)

.PARAMETER ExportHtml
Switch to export results as HTML report (optional)

.PARAMETER ExportCsv
Switch to export results as CSV file (optional)

.PARAMETER OutputPath
Output path for the report files

.EXAMPLE
.\Get-FleetAgentPoliciesWithProcessors.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key"

.EXAMPLE
.\Get-FleetAgentPoliciesWithProcessors.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -ExportJson -ExportHtml

.NOTES
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1 or later
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$KibanaUrl,
    
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportJson,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportHtml,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ""
)

$headers = @{
    "kbn-xsrf" = "reporting"
    "Authorization" = "ApiKey $ApiKey"
    "Content-Type" = "application/json"
}

$scriptDirectory = if ([string]::IsNullOrEmpty($OutputPath)) {
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        Get-Location
    } else {
        $PSScriptRoot
    }
} else {
    $OutputPath
}

if (-not (Test-Path -Path $scriptDirectory -PathType Container)) {
    Write-Host "Creating output directory: $scriptDirectory" -ForegroundColor Yellow
    New-Item -Path $scriptDirectory -ItemType Directory -Force | Out-Null
}

function Invoke-KibanaApi {
    param (
        [string]$Endpoint,
        [string]$Method = "GET",
        [string]$Body
    )
    
    $fullUrl = "$KibanaUrl$Endpoint"
    
    try {
        $response = Invoke-RestMethod -Uri $fullUrl -Method $Method -Headers $headers -Body $Body -ContentType "application/json"
        return $response
    }
    catch {
        Write-Host "Error calling $fullUrl : $_" -ForegroundColor Red
        return $null
    }
}

function Find-ProcessorsInObject {
    param (
        [Parameter(Mandatory = $false)]
        $Object,
        
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    $processors = @()
    
    if ($null -eq $Object) { 
        return $processors 
    }
    
    if ($Path -match 'processors$') {
        if ($Object -is [array]) {
            $arrayIndex = 0
            foreach ($proc in $Object) {
                if ($null -ne $proc) {
                    $processors += [PSCustomObject]@{
                        Location = "$Path[$arrayIndex]"
                        Processor = $proc
                        ProcessorJson = ($proc | ConvertTo-Json -Depth 10 -Compress)
                    }
                }
                $arrayIndex++
            }
            return $processors
        }
        elseif ($Object -is [string]) {
            $processors += [PSCustomObject]@{
                Location = $Path
                Processor = $Object
                ProcessorJson = $Object
            }
            return $processors
        }
        elseif ($Object -is [hashtable] -or $Object.GetType().Name -eq 'PSCustomObject') {
            $processors += [PSCustomObject]@{
                Location = $Path
                Processor = $Object
                ProcessorJson = ($Object | ConvertTo-Json -Depth 10 -Compress)
            }
            return $processors
        }
    }
    
    if ($Object -is [array]) {
        for ($i = 0; $i -lt $Object.Count; $i++) {
            if ($null -ne $Object[$i]) {
                $processors += Find-ProcessorsInObject -Object $Object[$i] -Path "$Path[$i]"
            }
        }
    }
    elseif ($Object -is [hashtable] -or $Object.GetType().Name -eq 'PSCustomObject') {
        $properties = if ($Object -is [hashtable]) { $Object.Keys } else { $Object.PSObject.Properties.Name }
        
        foreach ($prop in $properties) {
            $value = if ($Object -is [hashtable]) { $Object[$prop] } else { $Object.$prop }
            $newPath = if ([string]::IsNullOrEmpty($Path)) { $prop } else { "$Path.$prop" }
            
            if ($null -ne $value) {
                $processors += Find-ProcessorsInObject -Object $value -Path $newPath
            }
        }
    }
    
    return $processors
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   FLEET AGENT POLICIES - ADD_FIELDS PROCESSORS FINDER    ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Kibana URL: $KibanaUrl" -ForegroundColor White
if ($ExportJson -or $ExportHtml -or $ExportCsv) {
    Write-Host "  Export Formats: $((@() + $(if($ExportJson){'JSON'}) + $(if($ExportHtml){'HTML'}) + $(if($ExportCsv){'CSV'})) -join ', ')" -ForegroundColor White
    Write-Host "  Output Directory: $scriptDirectory" -ForegroundColor White
} else {
    Write-Host "  Export: None (console output only)" -ForegroundColor Gray
}

Write-Host "`n=== RETRIEVING AGENT POLICIES ===" -ForegroundColor Cyan

# Get agent policies
$page = 1
$perPage = 100
$allPolicies = @()

do {
    Write-Host "Fetching page $page..." -ForegroundColor Yellow
    $policiesResponse = Invoke-KibanaApi -Endpoint "/api/fleet/agent_policies?page=$page&perPage=$perPage&full=true"
    
    if (-not $policiesResponse) {
        Write-Host "No response from API" -ForegroundColor Red
        break
    }

    if (-not $policiesResponse.items) {
        Write-Host "Response does not contain 'items' property" -ForegroundColor Yellow
        Write-Host "Response properties: $(($policiesResponse.PSObject.Properties.Name) -join ', ')" -ForegroundColor Gray

        if ($policiesResponse.data) {
            Write-Host "Found 'data' property instead of 'items', using that..." -ForegroundColor Yellow
            $policiesResponse | Add-Member -NotePropertyName items -NotePropertyValue $policiesResponse.data -Force
        }
        elseif ($policiesResponse -is [array]) {
            Write-Host "Response is an array directly, using it as items..." -ForegroundColor Yellow
            $policiesResponse = @{ items = $policiesResponse; total = $policiesResponse.Count }
        }
        else {
            Write-Host "Unable to find policy data in response" -ForegroundColor Red
            break
        }
    }
    
    $allPolicies += $policiesResponse.items
    $total = if ($policiesResponse.total) { $policiesResponse.total } else { $policiesResponse.items.Count }
    $page++
    
    Write-Host "Retrieved $($allPolicies.Count) of $total policies" -ForegroundColor Green
    
} while ($allPolicies.Count -lt $total -and $policiesResponse.items.Count -gt 0)

Write-Host "`nTotal policies retrieved: $($allPolicies.Count)" -ForegroundColor Green

if ($allPolicies.Count -eq 0) {
    Write-Host "`nNo agent policies found!" -ForegroundColor Yellow
    exit 0
}

Write-Host "`n=== SEARCHING FOR ADD_FIELDS PROCESSORS ===" -ForegroundColor Cyan

$policiesWithProcessors = @()
$policyCount = 0

foreach ($policy in $allPolicies) {
    $policyCount++
    
    if ($policyCount % 10 -eq 0) {
        Write-Host "Processed $policyCount of $($allPolicies.Count) policies..." -ForegroundColor Gray
    }
    
    if ($null -eq $policy) {
        continue
    }
    
    $foundProcessors = Find-ProcessorsInObject -Object $policy -Path "policy"
    
    if ($foundProcessors -and $foundProcessors.Count -gt 0) {
        $customProcessors = @()
        
        foreach ($procInfo in $foundProcessors) {
            $isAddFields = $false
            
            if ($procInfo.Processor -is [hashtable] -or $procInfo.Processor.GetType().Name -eq 'PSCustomObject') {
                $keys = if ($procInfo.Processor -is [hashtable]) { $procInfo.Processor.Keys } else { $procInfo.Processor.PSObject.Properties.Name }
                if ($keys -contains 'add_fields') {
                    $isAddFields = $true
                }
            }
            
            if ($isAddFields) {
                $customProcessors += $procInfo
            }
        }
        
        if ($customProcessors.Count -gt 0) {
            $policiesWithProcessors += [PSCustomObject]@{
                Policy = $policy
                Processors = $customProcessors
            }
        }
    }
}

Write-Host "`nSearch complete!" -ForegroundColor Green
Write-Host "Found $($policiesWithProcessors.Count) policies with add_fields processors" -ForegroundColor Green

if ($policiesWithProcessors.Count -eq 0) {
    Write-Host "`nNo policies found with add_fields processors configured." -ForegroundColor Yellow
    Write-Host "add_fields processors are used to enrich data with custom fields before indexing." -ForegroundColor Gray
    exit 0
}

# Console results
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   AGENT POLICIES WITH ADD_FIELDS PROCESSORS               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$index = 1
foreach ($policyInfo in $policiesWithProcessors) {
    $policy = $policyInfo.Policy
    $processors = $policyInfo.Processors
    
    Write-Host "$index. " -NoNewline -ForegroundColor Gray
    Write-Host "$($policy.name)" -ForegroundColor White -NoNewline
    Write-Host " ($($policy.namespace))" -ForegroundColor Gray
    Write-Host "   Status: $($policy.status)" -ForegroundColor $(if ($policy.status -eq 'active') { 'Green' } else { 'Yellow' })
    Write-Host "   add_fields Found: $($processors.Count)" -ForegroundColor Cyan
    Write-Host ""
    
    $uniqueLocations = $processors | Group-Object -Property Location
    
    foreach ($locationGroup in $uniqueLocations) {
        $location = $locationGroup.Name
        $procsAtLocation = $locationGroup.Group
        
        $contextInfo = ""
        if ($location -match 'package_policies\[(\d+)\]') {
            $ppIndex = $matches[1]
            $contextInfo += " [Package Policy #$ppIndex]"
        }
        if ($location -match 'inputs\[(\d+)\]') {
            $inputIndex = $matches[1]
            $contextInfo += " [Input #$inputIndex]"
        }
        if ($location -match 'streams\[(\d+)\]') {
            $streamIndex = $matches[1]
            $contextInfo += " [Stream #$streamIndex]"
        }
        
        Write-Host "   📍 Location:$contextInfo" -ForegroundColor Yellow
        Write-Host "      $location" -ForegroundColor Gray
        
        foreach ($proc in $procsAtLocation) {
            if ($proc.Processor -is [string]) {
                Write-Host "      Type: YAML Configuration" -ForegroundColor Magenta
                Write-Host "      Config:" -ForegroundColor Gray
                $proc.Processor -split "`n" | ForEach-Object {
                    Write-Host "        $_" -ForegroundColor White
                }
            }
            elseif ($proc.Processor -is [hashtable] -or $proc.Processor.GetType().Name -eq 'PSCustomObject') {
                $procKeys = if ($proc.Processor -is [hashtable]) { $proc.Processor.Keys } else { $proc.Processor.PSObject.Properties.Name }
                $procType = $procKeys | Select-Object -First 1
                
                Write-Host "      Type: $procType" -ForegroundColor Magenta
                Write-Host "      Configuration:" -ForegroundColor Gray
                
                $configLines = ($proc.ProcessorJson | ConvertFrom-Json | ConvertTo-Json -Depth 10) -split "`n"
                foreach ($line in $configLines) {
                    Write-Host "        $line" -ForegroundColor White
                }
            }
            else {
                Write-Host "      Type: Unknown" -ForegroundColor Magenta
                Write-Host "      Value: $($proc.Processor)" -ForegroundColor White
            }
        }
        Write-Host ""
    }
    
    Write-Host ""
    $index++
}

Write-Host "`n=== PROCESSING RESULTS ===" -ForegroundColor Cyan

$structuredResults = @()

foreach ($policyInfo in $policiesWithProcessors) {
    $policy = $policyInfo.Policy
    $processors = $policyInfo.Processors
    
    $processorTypes = @()
    foreach ($proc in $processors) {
        if ($proc.Processor -is [hashtable] -or $proc.Processor.GetType().Name -eq 'PSCustomObject') {
            $keys = if ($proc.Processor -is [hashtable]) { $proc.Processor.Keys } else { $proc.Processor.PSObject.Properties.Name }
            $processorTypes += ($keys | Select-Object -First 1)
        }
    }
    
    $processorTypesSummary = ($processorTypes | Group-Object | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
    $packagePolicyCount = if ($policy.package_policies) { $policy.package_policies.Count } else { 0 }
    
    $structuredResult = [PSCustomObject]@{
        PolicyName = $policy.name
        PolicyId = $policy.id
        Namespace = $policy.namespace
        Status = $policy.status
        Description = $policy.description
        ProcessorCount = $processors.Count
        ProcessorTypes = $processorTypesSummary
        PackagePolicyCount = $packagePolicyCount
        IsManaged = $policy.is_managed
        MonitoringEnabled = if ($policy.monitoring_enabled) { ($policy.monitoring_enabled -join ", ") } else { "" }
        CreatedAt = $policy.created_at
        UpdatedAt = $policy.updated_at
        Revision = $policy.revision
        ProcessorDetails = $processors | ForEach-Object {
            [PSCustomObject]@{
                Location = $_.Location
                ProcessorType = if ($_.Processor -is [hashtable] -or $_.Processor.GetType().Name -eq 'PSCustomObject') {
                    $keys = if ($_.Processor -is [hashtable]) { $_.Processor.Keys } else { $_.Processor.PSObject.Properties.Name }
                    ($keys | Select-Object -First 1)
                } else {
                    "YAML/String"
                }
                ProcessorConfig = $_.Processor
                ProcessorJson = $_.ProcessorJson
            }
        }
    }
    
    $structuredResults += $structuredResult
}

# JSON export
if ($ExportJson) {
    $reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $jsonFileName = "FleetPoliciesWithProcessors_$reportDate.json"
    $jsonFilePath = Join-Path -Path $scriptDirectory -ChildPath $jsonFileName
    
    Write-Host "`nExporting to JSON: $jsonFilePath" -ForegroundColor Cyan
    
    $exportData = @{
        GeneratedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        KibanaUrl = $KibanaUrl
        TotalPoliciesSearched = $allPolicies.Count
        PoliciesWithProcessors = $structuredResults.Count
        Results = $structuredResults
    }
    
    $exportData | ConvertTo-Json -Depth 20 | Out-File -FilePath $jsonFilePath -Encoding UTF8
    Write-Host "✓ JSON export complete" -ForegroundColor Green
}

# CSV export
if ($ExportCsv) {
    if (-not $reportDate) {
        $reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
    }
    $csvFileName = "FleetPoliciesWithProcessors_$reportDate.csv"
    $csvFilePath = Join-Path -Path $scriptDirectory -ChildPath $csvFileName
    
    Write-Host "`nExporting to CSV: $csvFilePath" -ForegroundColor Cyan
    
    $csvResults = $structuredResults | Select-Object -Property PolicyName, PolicyId, Namespace, Status, Description, ProcessorCount, ProcessorTypes, PackagePolicyCount, IsManaged, MonitoringEnabled, CreatedAt, UpdatedAt, Revision
    
    $csvResults | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
    Write-Host "✓ CSV export complete" -ForegroundColor Green
}

# HTML export
if ($ExportHtml) {
    if (-not $reportDate) {
        $reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
    }
    Write-Host "`n=== GENERATING HTML REPORT ===" -ForegroundColor Cyan
    
    $htmlFileName = "FleetPoliciesWithProcessors_$reportDate.html"
    $htmlFilePath = Join-Path -Path $scriptDirectory -ChildPath $htmlFileName
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Fleet Agent Policies with add_fields Processors - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1600px; 
            margin: 0 auto; 
            background-color: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.1); 
        }
        h1 { 
            color: #1f2937; 
            border-bottom: 3px solid #7c3aed; 
            padding-bottom: 10px; 
        }
        h2 { 
            color: #374151; 
            margin-top: 40px; 
            border-left: 4px solid #7c3aed; 
            padding-left: 15px; 
        }
        .summary {
            background: linear-gradient(135deg, #7c3aed, #5b21b6);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-top: 20px; 
        }
        .summary-item { 
            text-align: center; 
            padding: 15px; 
            background: rgba(255,255,255,0.1); 
            border-radius: 8px; 
        }
        .summary-number { 
            font-size: 2.2em; 
            font-weight: bold; 
        }
        .summary-label { 
            font-size: 0.95em; 
            opacity: 0.95; 
            margin-top: 5px; 
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px; 
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #e5e7eb; 
        }
        th { 
            background-color: #f3f4f6; 
            font-weight: 600; 
            color: #374151; 
            position: sticky;
            top: 0;
        }
        tr:hover { 
            background-color: #f9fafb; 
        }
        .status-active { 
            color: #16a34a; 
            font-weight: bold; 
        }
        .status-inactive { 
            color: #dc2626; 
            font-weight: bold; 
        }
        .processor-details {
            font-family: 'Courier New', monospace;
            background-color: #f9fafb;
            padding: 10px;
            border-left: 3px solid #7c3aed;
            margin: 5px 0;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .processor-count {
            background-color: #e0e7ff;
            color: #4338ca;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        .filter-input { 
            width: 100%; 
            padding: 10px; 
            margin: 10px 0; 
            border: 1px solid #d1d5db; 
            border-radius: 6px; 
            font-size: 1em; 
        }
        .filter-container { 
            margin: 20px 0; 
            padding: 15px; 
            background: #f9fafb; 
            border-radius: 8px; 
        }
    </style>
    <script>
        function filterTable() {
            const input = document.getElementById('policyFilter');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('policiesTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell) {
                        const text = cell.textContent || cell.innerText;
                        if (text.toLowerCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                rows[i].style.display = found ? '' : 'none';
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>🔧 Fleet Agent Policies with add_fields Processors</h1>
        
        <div class="summary">
            <h2 style="color: white; border: none; margin-top: 0; padding: 0;">Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">$($structuredResults.Count)</div>
                    <div class="summary-label">Policies with add_fields</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($allPolicies.Count)</div>
                    <div class="summary-label">Total Policies Searched</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$(($structuredResults | Measure-Object -Property ProcessorCount -Sum).Sum)</div>
                    <div class="summary-label">Total add_fields Found</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$([Math]::Round(($structuredResults.Count / $allPolicies.Count) * 100, 1))%</div>
                    <div class="summary-label">Policies Using add_fields</div>
                </div>
            </div>
        </div>

        <h2>Agent Policies</h2>
        
        <div class="filter-container">
            <label for="policyFilter"><strong>Filter Policies:</strong></label>
            <input type="text" id="policyFilter" class="filter-input" onkeyup="filterTable()" placeholder="Search by policy name, namespace, processor types...">
        </div>

        <table id="policiesTable">
            <tr>
                <th>Policy Name</th>
                <th>Namespace</th>
                <th>Status</th>
                <th>add_fields Count</th>
                <th>Processor Types</th>
                <th>Package Policies</th>
            </tr>
"@

    foreach ($result in $structuredResults) {
        $statusClass = if ($result.Status -eq "active") { "status-active" } else { "status-inactive" }
        
        $htmlReport += @"
            <tr>
                <td>
                    <strong>$($result.PolicyName)</strong><br/>
                    <small style="color: #6b7280;">ID: $($result.PolicyId)</small>
"@
        
        if ($result.Description) {
            $htmlReport += "<br/><small style='color: #6b7280;'>$($result.Description)</small>"
        }
        
        $htmlReport += @"
                </td>
                <td>$($result.Namespace)</td>
                <td><span class="$statusClass">$($result.Status.ToUpper())</span></td>
                <td><span class="processor-count">$($result.ProcessorCount)</span></td>
                <td style="font-size: 0.9em;">$($result.ProcessorTypes)</td>
                <td>$($result.PackagePolicyCount)</td>
            </tr>
"@
    }

    $htmlReport += @"
        </table>

        <div style="margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #6b7280;">
            <h3 style="color: #374151;">Report Information</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Kibana Instance:</strong> $KibanaUrl</p>
            <p><strong>Total Policies Searched:</strong> $($allPolicies.Count)</p>
            <p><strong>Policies with Custom Processors:</strong> $($structuredResults.Count)</p>
            
            <h4 style="color: #7c3aed; margin-top: 20px;">About add_fields Processors</h4>
            <p>The <code>add_fields</code> processor is used to add custom fields to events before they are indexed in Elasticsearch. This is commonly used to:</p>
            <ul>
                <li><strong>Tag data with client information:</strong> mssp_client, customer_name, customer_number</li>
                <li><strong>Add organizational context:</strong> department, environment, location</li>
                <li><strong>Enrich events with metadata:</strong> Before data reaches Elasticsearch</li>
            </ul>
            <p>Fields added via processors are typically set at the integration/stream level and apply to all events from that data source.</p>
        </div>
    </div>
</body>
</html>
"@

    $htmlReport | Out-File -FilePath $htmlFilePath -Encoding UTF8
    Write-Host "✓ HTML report generated: $htmlFilePath" -ForegroundColor Green
}

# Summary statts
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   SUMMARY                                                 ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nTotal Policies Searched: $($allPolicies.Count)" -ForegroundColor White
Write-Host "Policies with add_fields Processors: $($structuredResults.Count)" -ForegroundColor Green
Write-Host "Total add_fields Found: $(($structuredResults | Measure-Object -Property ProcessorCount -Sum).Sum)" -ForegroundColor Cyan
Write-Host "Coverage: $([Math]::Round(($structuredResults.Count / $allPolicies.Count) * 100, 1))%" -ForegroundColor Yellow

if ($ExportJson -or $ExportCsv -or $ExportHtml) {
    Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║   EXPORT COMPLETE                                         ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host "`nFiles Generated:" -ForegroundColor Cyan
    if ($ExportJson) {
        Write-Host "  JSON: $jsonFilePath" -ForegroundColor White
    }
    if ($ExportCsv) {
        Write-Host "  CSV: $csvFilePath" -ForegroundColor White
    }
    if ($ExportHtml) {
        Write-Host "  HTML: $htmlFilePath" -ForegroundColor White
    }
    
    Write-Host "`nAll files saved to: $scriptDirectory" -ForegroundColor Cyan
} else {
    Write-Host "`n(No files exported - use -ExportJson, -ExportHtml, or -ExportCsv to save results)" -ForegroundColor Gray
}
