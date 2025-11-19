<#
.SYNOPSIS
Analyzes MITRE ATT&CK framework coverage across Elastic Security detection rules

.DESCRIPTION
Retrieves all detection rules from Kibana and analyzes the distribution of MITRE ATT&CK 
tactics and techniques to identify coverage and gaps. Provides comprehensive statistics 
on which tactics and techniques are covered by your detection rules, helping to identify 
areas where additional detections may be needed.

.PARAMETER KibanaUrl
The URL of your Kibana instance

.PARAMETER ApiKey
Kibana API key for authentication

.PARAMETER IncludeDisabled
Include disabled rules in the coverage analysis

.PARAMETER ExcludeBuildingBlocks
Exclude building block rules from the analysis

.PARAMETER OutputFormat
Output format: "Console", "CSV", "JSON", "HTML", or "All". Default: "Console"

.PARAMETER OutputPath
Output path for the report files

.EXAMPLE
.\Get-KibanaRuleMITRECoverage.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key"

.EXAMPLE
.\Get-KibanaRuleMITRECoverage.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -IncludeDisabled -OutputFormat "All"

.EXAMPLE
.\Get-KibanaRuleMITRECoverage.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key" -ExcludeBuildingBlocks -OutputFormat "HTML"

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
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExcludeBuildingBlocks,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "CSV", "JSON", "HTML", "All")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ""
)

$headers = @{
    "kbn-xsrf" = "reporting"
    "Authorization" = "ApiKey $ApiKey"
    "Content-Type" = "application/json"
}

# Set output path
$scriptDirectory = if ([string]::IsNullOrEmpty($OutputPath)) {
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        Get-Location
    } else {
        $PSScriptRoot
    }
} else {
    $OutputPath
}

# Validate output directory
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
    
    Write-Host "Calling $Method $fullUrl" -ForegroundColor Gray
    
    try {
        $response = Invoke-RestMethod -Uri $fullUrl -Method $Method -Headers $headers -Body $Body -ContentType "application/json"
        return $response
    }
    catch {
        Write-Host "Error calling $fullUrl : $_" -ForegroundColor Red
        return $null
    }
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   ELASTIC MITRE ATT&CK COVERAGE ANALYZER                 ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Kibana URL: $KibanaUrl" -ForegroundColor White
Write-Host "  Include Disabled Rules: $IncludeDisabled" -ForegroundColor White
Write-Host "  Exclude Building Blocks: $ExcludeBuildingBlocks" -ForegroundColor White
Write-Host "  Output Directory: $scriptDirectory" -ForegroundColor White
Write-Host "  Output Format: $OutputFormat" -ForegroundColor White

Write-Host "`n=== RETRIEVING DETECTION RULES ===" -ForegroundColor Cyan

# Retrieve rules
$allRules = @()
$page = 1
$perPage = 100

do {
    Write-Host "Fetching page $page..." -ForegroundColor Yellow
    $rulesResponse = Invoke-KibanaApi -Endpoint "/api/detection_engine/rules/_find?page=$page&per_page=$perPage"
    
    if (-not $rulesResponse -or -not $rulesResponse.data) {
        Write-Host "No rules found or error occurred" -ForegroundColor Red
        break
    }
    
    $allRules += $rulesResponse.data
    $totalRules = $rulesResponse.total
    $page++
    
    Write-Host "Retrieved $($allRules.Count) of $totalRules rules" -ForegroundColor Green
    
} while ($allRules.Count -lt $rulesResponse.total)

Write-Host "`nTotal rules retrieved: $($allRules.Count)" -ForegroundColor Green

Write-Host "`n=== FILTERING RULES ===" -ForegroundColor Cyan

$filteredRules = $allRules

# Filter enabled rules
if (-not $IncludeDisabled) {
    $filteredRules = $filteredRules | Where-Object { $_.enabled -eq $true }
    Write-Host "Filtered to enabled rules only: $($filteredRules.Count)" -ForegroundColor Green
}

# Filter building block rules
if ($ExcludeBuildingBlocks) {
    $filteredRules = $filteredRules | Where-Object { $_.building_block_type -ne "default" }
    Write-Host "Excluded building block rules: $($filteredRules.Count)" -ForegroundColor Green
}

if ($filteredRules.Count -eq 0) {
    Write-Host "`nNo rules match the specified criteria!" -ForegroundColor Yellow
    exit 0
}

$tacticsDistribution = @{}
$techniquesDistribution = @{}
$tacticTechniqueMapping = @{}
$rulesMitreData = @()
$rulesWithMitre = 0
$rulesWithoutMitre = 0

Write-Host "`n=== ANALYZING MITRE ATT&CK COVERAGE ===" -ForegroundColor Cyan

foreach ($rule in $filteredRules) {
    $hasMitreData = $false
    $ruleTactics = @()
    $ruleTechniques = @()
    $ruleSubtechniques = @()
    
    # Process MITRE threat data
    if ($rule.threat -and $rule.threat.Count -gt 0) {
        $hasMitreData = $true
        
        foreach ($threat in $rule.threat) {
            # Tactics
            if ($threat.tactic -and $threat.tactic.name) {
                $tacticName = $threat.tactic.name
                $tacticId = $threat.tactic.id
                $tacticReference = $threat.tactic.reference
                
                if (-not $tacticsDistribution.ContainsKey($tacticName)) {
                    $tacticsDistribution[$tacticName] = @{
                        Count = 0
                        ID = $tacticId
                        Reference = $tacticReference
                        Rules = @{}
                    }
                }
                $tacticsDistribution[$tacticName].Count++
                $tacticsDistribution[$tacticName].Rules[$rule.id] = $true
                $ruleTactics += $tacticName
            
                if (-not $tacticTechniqueMapping.ContainsKey($tacticName)) {
                    $tacticTechniqueMapping[$tacticName] = @{}
                }
                
                # Techniques
                if ($threat.technique -and $threat.technique.Count -gt 0) {
                    foreach ($technique in $threat.technique) {
                        $techniqueName = $technique.name
                        $techniqueId = $technique.id
                        $techniqueReference = $technique.reference
                        
                        if ($techniqueName) {
                            if (-not $techniquesDistribution.ContainsKey($techniqueName)) {
                                $techniquesDistribution[$techniqueName] = @{
                                    Count = 0
                                    ID = $techniqueId
                                    Reference = $techniqueReference
                                    Rules = @{}
                                }
                            }
                            $techniquesDistribution[$techniqueName].Count++
                            $techniquesDistribution[$techniqueName].Rules[$rule.id] = $true
                            $ruleTechniques += $techniqueName
                            
                            # Map tactic to technique
                            if (-not $tacticTechniqueMapping[$tacticName].ContainsKey($techniqueName)) {
                                $tacticTechniqueMapping[$tacticName][$techniqueName] = @{
                                    Count = 0
                                    ID = $techniqueId
                                    Rules = @{}
                                }
                            }
                            $tacticTechniqueMapping[$tacticName][$techniqueName].Count++
                            $tacticTechniqueMapping[$tacticName][$techniqueName].Rules[$rule.id] = $true
                            
                            # Process subtechniques
                            if ($technique.subtechnique -and $technique.subtechnique.Count -gt 0) {
                                foreach ($subtechnique in $technique.subtechnique) {
                                    $subtechniqueName = $subtechnique.name
                                    $subtechniqueId = $subtechnique.id
                                    $subtechniqueReference = $subtechnique.reference
                                    
                                    if ($subtechniqueName) {
                                        $fullSubtechniqueName = "$techniqueName - $subtechniqueName"
                                        
                                        if (-not $techniquesDistribution.ContainsKey($fullSubtechniqueName)) {
                                            $techniquesDistribution[$fullSubtechniqueName] = @{
                                                Count = 0
                                                ID = $subtechniqueId
                                                Reference = $subtechniqueReference
                                                Rules = @{}
                                                IsSubtechnique = $true
                                            }
                                        }
                                        $techniquesDistribution[$fullSubtechniqueName].Count++
                                        $techniquesDistribution[$fullSubtechniqueName].Rules[$rule.id] = $true
                                        $ruleSubtechniques += $fullSubtechniqueName
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if ($hasMitreData) {
        $rulesWithMitre++
    } else {
        $rulesWithoutMitre++
    }
    
    $rulesMitreData += [PSCustomObject]@{
        RuleName = $rule.name
        RuleId = $rule.rule_id
        Id = $rule.id
        Enabled = $rule.enabled
        Type = $rule.type
        Severity = $rule.severity
        RiskScore = $rule.risk_score
        BuildingBlock = ($rule.building_block_type -eq "default")
        HasMitreData = $hasMitreData
        Tactics = ($ruleTactics | Select-Object -Unique) -join "; "
        Techniques = ($ruleTechniques | Select-Object -Unique) -join "; "
        Subtechniques = ($ruleSubtechniques | Select-Object -Unique) -join "; "
        CreatedAt = $rule.created_at
        UpdatedAt = $rule.updated_at
    }
}

Write-Host "`nTotal Rules Analyzed: $($filteredRules.Count)" -ForegroundColor Green
Write-Host "  Rules with MITRE Data: $rulesWithMitre" -ForegroundColor Green
Write-Host "  Rules without MITRE Data: $rulesWithoutMitre" -ForegroundColor Yellow

# Stats
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   MITRE ATT&CK TACTICS COVERAGE                          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$tacticsStats = $tacticsDistribution.GetEnumerator() | 
    Sort-Object {$_.Value.Rules.Count} -Descending | 
    Select-Object @{Name="Tactic"; Expression={$_.Key}},
                  @{Name="TacticID"; Expression={$_.Value.ID}},
                  @{Name="TotalOccurrences"; Expression={$_.Value.Count}},
                  @{Name="UniqueRules"; Expression={$_.Value.Rules.Count}},
                  @{Name="PercentOfRules"; Expression={[math]::Round(($_.Value.Rules.Count / $rulesWithMitre) * 100, 2)}},
                  @{Name="Reference"; Expression={$_.Value.Reference}}

if ($tacticsStats) {
    $tacticsStats | Format-Table -AutoSize
} else {
    Write-Host "No MITRE tactics data found." -ForegroundColor Yellow
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   MITRE ATT&CK TECHNIQUES COVERAGE                       ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$techniquesStats = $techniquesDistribution.GetEnumerator() | 
    Sort-Object {$_.Value.Rules.Count} -Descending | 
    Select-Object @{Name="Technique"; Expression={$_.Key}},
                  @{Name="TechniqueID"; Expression={$_.Value.ID}},
                  @{Name="TotalOccurrences"; Expression={$_.Value.Count}},
                  @{Name="UniqueRules"; Expression={$_.Value.Rules.Count}},
                  @{Name="PercentOfRules"; Expression={[math]::Round(($_.Value.Rules.Count / $rulesWithMitre) * 100, 2)}},
                  @{Name="IsSubtechnique"; Expression={$_.Value.IsSubtechnique -eq $true}},
                  @{Name="Reference"; Expression={$_.Value.Reference}}

if ($techniquesStats) {
    $techniquesStats | Select-Object -First 20 | Format-Table -AutoSize
    
    if ($techniquesStats.Count -gt 20) {
        Write-Host "Showing top 20 techniques. Total unique techniques/subtechniques: $($techniquesStats.Count)" -ForegroundColor Yellow
    }
} else {
    Write-Host "No MITRE techniques data found." -ForegroundColor Yellow
}

$reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"

if ($OutputFormat -in @("CSV", "All")) {
    Write-Host "`n=== EXPORTING TO CSV ===" -ForegroundColor Cyan
    
    $tacticsFile = Join-Path -Path $scriptDirectory -ChildPath "KibanaRuleMITRE_Tactics_$reportDate.csv"
    $tacticsStats | Export-Csv -Path $tacticsFile -NoTypeInformation
    Write-Host "Tactics exported to: $tacticsFile" -ForegroundColor Green
    
    $techniquesFile = Join-Path -Path $scriptDirectory -ChildPath "KibanaRuleMITRE_Techniques_$reportDate.csv"
    $techniquesStats | Export-Csv -Path $techniquesFile -NoTypeInformation
    Write-Host "Techniques exported to: $techniquesFile" -ForegroundColor Green
    
    # Export all rule details
    $ruleDetailsFile = Join-Path -Path $scriptDirectory -ChildPath "KibanaRuleMITRE_AllRules_$reportDate.csv"
    $rulesMitreData | Export-Csv -Path $ruleDetailsFile -NoTypeInformation
    Write-Host "All rule details exported to: $ruleDetailsFile" -ForegroundColor Green
    
    # Export rules WITH MITRE data
    $rulesWithMitreFile = Join-Path -Path $scriptDirectory -ChildPath "KibanaRuleMITRE_RulesWithMITRE_$reportDate.csv"
    $rulesMitreData | Where-Object { $_.HasMitreData } | Export-Csv -Path $rulesWithMitreFile -NoTypeInformation
    Write-Host "Rules with MITRE data exported to: $rulesWithMitreFile" -ForegroundColor Green
    
    # Export rules WITHOUT MITRE data
    $rulesWithoutMitreFile = Join-Path -Path $scriptDirectory -ChildPath "KibanaRuleMITRE_RulesWithoutMITRE_$reportDate.csv"
    $rulesMitreData | Where-Object { -not $_.HasMitreData } | Export-Csv -Path $rulesWithoutMitreFile -NoTypeInformation
    Write-Host "Rules WITHOUT MITRE data exported to: $rulesWithoutMitreFile" -ForegroundColor Green
    
    $mappingData = @()
    foreach ($tactic in $tacticTechniqueMapping.Keys) {
        foreach ($technique in $tacticTechniqueMapping[$tactic].Keys) {
            $mappingData += [PSCustomObject]@{
                Tactic = $tactic
                Technique = $technique
                TechniqueID = $tacticTechniqueMapping[$tactic][$technique].ID
                Occurrences = $tacticTechniqueMapping[$tactic][$technique].Count
                UniqueRules = $tacticTechniqueMapping[$tactic][$technique].Rules.Count
            }
        }
    }
    $mappingFile = Join-Path -Path $scriptDirectory -ChildPath "KibanaRuleMITRE_TacticTechniqueMapping_$reportDate.csv"
    $mappingData | Export-Csv -Path $mappingFile -NoTypeInformation
    Write-Host "Tactic-Technique mapping exported to: $mappingFile" -ForegroundColor Green
}

if ($OutputFormat -in @("JSON", "All")) {
    Write-Host "`n=== EXPORTING TO JSON ===" -ForegroundColor Cyan
    
    # JSON prep
    $mappingForJson = @{}
    foreach ($tactic in $tacticTechniqueMapping.Keys) {
        $mappingForJson[$tactic] = @{}
        foreach ($technique in $tacticTechniqueMapping[$tactic].Keys) {
            $mappingForJson[$tactic][$technique] = @{
                ID = $tacticTechniqueMapping[$tactic][$technique].ID
                Count = $tacticTechniqueMapping[$tactic][$technique].Count
                UniqueRules = $tacticTechniqueMapping[$tactic][$technique].Rules.Count
            }
        }
    }
    
    $jsonData = @{
        Summary = @{
            GeneratedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            KibanaUrl = $KibanaUrl
            IncludeDisabled = $IncludeDisabled.IsPresent
            ExcludeBuildingBlocks = $ExcludeBuildingBlocks.IsPresent
            TotalRulesAnalyzed = $filteredRules.Count
            RulesWithMitre = $rulesWithMitre
            RulesWithoutMitre = $rulesWithoutMitre
            UniqueTactics = $tacticsDistribution.Count
            UniqueTechniques = ($techniquesStats | Where-Object { -not $_.IsSubtechnique }).Count
            UniqueSubtechniques = ($techniquesStats | Where-Object { $_.IsSubtechnique }).Count
        }
        Tactics = $tacticsStats
        Techniques = $techniquesStats
        TacticTechniqueMapping = $mappingForJson
        RulesWithMITRE = $rulesMitreData | Where-Object { $_.HasMitreData }
        RulesWithoutMITRE = $rulesMitreData | Where-Object { -not $_.HasMitreData }
        AllRules = $rulesMitreData
    }
    
    $jsonFile = Join-Path -Path $scriptDirectory -ChildPath "KibanaRuleMITRE_Coverage_$reportDate.json"
    $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
    Write-Host "JSON exported to: $jsonFile" -ForegroundColor Green
}

if ($OutputFormat -in @("HTML", "All")) {
    Write-Host "`n=== GENERATING HTML REPORT ===" -ForegroundColor Cyan
    
    $htmlFileName = "KibanaRuleMITRE_Coverage_$reportDate.html"
    $htmlFilePath = Join-Path -Path $scriptDirectory -ChildPath $htmlFileName
    
    # Calculate coverage percentages for main techniques vs subtechniques
    $mainTechniques = $techniquesStats | Where-Object { -not $_.IsSubtechnique }
    $subTechniques = $techniquesStats | Where-Object { $_.IsSubtechnique }
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Kibana Rule MITRE ATT&CK Coverage Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background-color: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.1); 
        }
        h1 { 
            color: #1f2937; 
            border-bottom: 3px solid #f04e23; 
            padding-bottom: 10px; 
        }
        h2 { 
            color: #374151; 
            margin-top: 40px; 
            border-left: 4px solid #f04e23; 
            padding-left: 15px; 
        }
        h3 { 
            color: #6b7280; 
            margin-top: 25px; 
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
        .summary { 
            background: linear-gradient(135deg, #f04e23, #d63301); 
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
        .coverage-high { 
            background-color: #dcfce7; 
            color: #166534; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .coverage-medium { 
            background-color: #fef3c7; 
            color: #92400e; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .coverage-low { 
            background-color: #fee2e2; 
            color: #991b1b; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .stats-box { 
            background: #f9fafb; 
            border: 1px solid #e5e7eb; 
            border-radius: 8px; 
            padding: 20px; 
            margin: 20px 0; 
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 15px; 
        }
        .stat-item { 
            padding: 15px; 
            background: white; 
            border-radius: 6px; 
            border-left: 4px solid #f04e23; 
        }
        .stat-label { 
            font-size: 0.9em; 
            color: #6b7280; 
            margin-bottom: 5px; 
        }
        .stat-value { 
            font-size: 1.5em; 
            font-weight: bold; 
            color: #1f2937; 
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
        .chart-container { 
            margin: 30px 0; 
            padding: 20px; 
            background-color: #f9fafb; 
            border-radius: 8px; 
        }
        .gap-alert {
            background-color: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .gap-alert h3 {
            color: #92400e;
            margin-top: 0;
        }
        a {
            color: #f04e23;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script>
        function filterTable(tableId) {
            const input = document.getElementById(tableId + 'Filter');
            const filter = input.value.toLowerCase();
            const table = document.getElementById(tableId);
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
        <h1>🛡️ Kibana Rule MITRE ATT&CK Coverage Report</h1>
        
        <div class="summary">
            <h2 style="color: white; border: none; margin-top: 0; padding: 0;">Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">$($filteredRules.Count)</div>
                    <div class="summary-label">Total Rules Analyzed</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$rulesWithMitre</div>
                    <div class="summary-label">Rules with MITRE Data</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($tacticsDistribution.Count)</div>
                    <div class="summary-label">Tactics Covered</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($mainTechniques.Count)</div>
                    <div class="summary-label">Techniques Covered</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">$($subTechniques.Count)</div>
                    <div class="summary-label">Subtechniques Covered</div>
                </div>
            </div>
        </div>

        <div class="gap-alert">
            <h3>⚠️ Coverage Analysis</h3>
            <p><strong>Rules without MITRE mapping:</strong> $rulesWithoutMitre rules ($([math]::Round(($rulesWithoutMitre / $filteredRules.Count) * 100, 1))%)</p>
            <p>These rules do not have MITRE ATT&CK tactics or techniques assigned and should be reviewed for proper classification.</p>
        </div>

        <h2>📊 MITRE ATT&CK Tactics Coverage</h2>
        <div class="chart-container">
            <canvas id="tacticsChart" style="max-height: 400px;"></canvas>
        </div>

        <div class="filter-container">
            <label for="tacticsTableFilter"><strong>Filter Tactics:</strong></label>
            <input type="text" id="tacticsTableFilter" class="filter-input" onkeyup="filterTable('tacticsTable')" placeholder="Search tactics...">
        </div>

        <table id="tacticsTable">
            <tr>
                <th>Tactic</th>
                <th>Tactic ID</th>
                <th>Total Occurrences</th>
                <th>Unique Rules</th>
                <th>% of Rules</th>
                <th>Reference</th>
            </tr>
"@

    foreach ($tactic in $tacticsStats) {
        $coverageClass = if ($tactic.UniqueRules -ge 10) { "coverage-high" } 
                        elseif ($tactic.UniqueRules -ge 5) { "coverage-medium" } 
                        else { "coverage-low" }
        
        $refLink = if ($tactic.Reference) { "<a href='$($tactic.Reference)' target='_blank'>🔗 View</a>" } else { "N/A" }
        
        $htmlReport += @"
            <tr>
                <td><strong>$($tactic.Tactic)</strong></td>
                <td>$($tactic.TacticID)</td>
                <td>$($tactic.TotalOccurrences)</td>
                <td><span class="$coverageClass">$($tactic.UniqueRules)</span></td>
                <td>$($tactic.PercentOfRules)%</td>
                <td>$refLink</td>
            </tr>
"@
    }

    $htmlReport += @"
        </table>

        <h2>🎯 MITRE ATT&CK Techniques Coverage (Top 50)</h2>
        <div class="chart-container">
            <canvas id="techniquesChart" style="max-height: 400px;"></canvas>
        </div>

        <div class="filter-container">
            <label for="techniquesTableFilter"><strong>Filter Techniques:</strong></label>
            <input type="text" id="techniquesTableFilter" class="filter-input" onkeyup="filterTable('techniquesTable')" placeholder="Search techniques...">
        </div>

        <table id="techniquesTable">
            <tr>
                <th>Technique</th>
                <th>Technique ID</th>
                <th>Type</th>
                <th>Total Occurrences</th>
                <th>Unique Rules</th>
                <th>% of Rules</th>
                <th>Reference</th>
            </tr>
"@

    foreach ($technique in ($techniquesStats | Select-Object -First 50)) {
        $coverageClass = if ($technique.UniqueRules -ge 5) { "coverage-high" } 
                        elseif ($technique.UniqueRules -ge 2) { "coverage-medium" } 
                        else { "coverage-low" }
        
        $typeLabel = if ($technique.IsSubtechnique) { "Subtechnique" } else { "Technique" }
        $refLink = if ($technique.Reference) { "<a href='$($technique.Reference)' target='_blank'>🔗 View</a>" } else { "N/A" }
        
        $htmlReport += @"
            <tr>
                <td><strong>$($technique.Technique)</strong></td>
                <td>$($technique.TechniqueID)</td>
                <td>$typeLabel</td>
                <td>$($technique.TotalOccurrences)</td>
                <td><span class="$coverageClass">$($technique.UniqueRules)</span></td>
                <td>$($technique.PercentOfRules)%</td>
                <td>$refLink</td>
            </tr>
"@
    }

    $htmlReport += @"
        </table>

        <h2>⚠️ Rules Without MITRE ATT&CK Mapping</h2>
        <p>The following $rulesWithoutMitre rules do not have MITRE ATT&CK tactics or techniques assigned. These should be reviewed and classified appropriately to improve detection coverage visibility.</p>
        
        <div class="filter-container">
            <label for="noMitreTableFilter"><strong>Filter Rules:</strong></label>
            <input type="text" id="noMitreTableFilter" class="filter-input" onkeyup="filterTable('noMitreTable')" placeholder="Search rules without MITRE data...">
        </div>

        <table id="noMitreTable">
            <tr>
                <th>Rule Name</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Enabled</th>
                <th>Building Block</th>
                <th>Created</th>
            </tr>
"@

    $rulesWithoutMitreData = $rulesMitreData | Where-Object { -not $_.HasMitreData } | Sort-Object -Property Severity -Descending
    
    foreach ($rule in $rulesWithoutMitreData) {
        $enabledBadge = if ($rule.Enabled) { "<span style='color: #16a34a; font-weight: bold;'>Yes</span>" } else { "<span style='color: #dc2626; font-weight: bold;'>✗ No</span>" }
        $bbBadge = if ($rule.BuildingBlock) { "Yes" } else { "No" }
        $severityClass = "severity-$($rule.Severity.ToLower())"
        
        $htmlReport += @"
            <tr>
                <td><strong>$($rule.RuleName)</strong><br/><span style='font-size: 0.85em; color: #6b7280;'>$($rule.RuleId)</span></td>
                <td>$($rule.Type)</td>
                <td><span class="$severityClass">$($rule.Severity.ToUpper())</span></td>
                <td>$($rule.RiskScore)</td>
                <td>$enabledBadge</td>
                <td>$bbBadge</td>
                <td>$([DateTime]::Parse($rule.CreatedAt).ToString("yyyy-MM-dd"))</td>
            </tr>
"@
    }

    $htmlReport += @"
        </table>
"@

    $htmlReport = $htmlReport.Replace("</style>", @"
        .severity-critical { 
            background-color: #fee2e2; 
            color: #991b1b; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .severity-high { 
            background-color: #fef3c7; 
            color: #92400e; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .severity-medium { 
            background-color: #dbeafe; 
            color: #1e40af; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
        .severity-low { 
            background-color: #f3f4f6; 
            color: #374151; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: 600; 
        }
    </style>
"@)

    $htmlReport += @"

        <div style="margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #6b7280;">
            <h3 style="color: #374151;">Report Information</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Kibana Instance:</strong> $KibanaUrl</p>
            <p><strong>Include Disabled Rules:</strong> $($IncludeDisabled.IsPresent)</p>
            <p><strong>Exclude Building Blocks:</strong> $($ExcludeBuildingBlocks.IsPresent)</p>
            
            <h4 style="color: #f04e23; margin-top: 20px;">About This Report</h4>
            <p>This report analyzes your Elastic Security detection rules against the MITRE ATT&CK framework to help identify:</p>
            <ul>
                <li><strong>Coverage Strengths:</strong> Tactics and techniques well-covered by your detection rules</li>
                <li><strong>Coverage Gaps:</strong> Areas where additional detection rules may be needed</li>
                <li><strong>Rule Distribution:</strong> How detection capabilities are distributed across the attack lifecycle</li>
            </ul>
            <p><strong>Recommendations:</strong></p>
            <ul>
                <li>Focus on tactics/techniques with low rule counts (red/yellow indicators)</li>
                <li>Review rules without MITRE mappings and add appropriate classifications</li>
                <li>Consider creating additional detections for under-covered attack vectors</li>
                <li>Regularly update this analysis as your detection portfolio evolves</li>
            </ul>
        </div>
    </div>
    
    <script>
        // Tactics distribution chart
        const tacticsCtx = document.getElementById('tacticsChart').getContext('2d');
        const tacticsChart = new Chart(tacticsCtx, {
            type: 'bar',
            data: {
                labels: [$($tacticsStats | ForEach-Object { "'$($_.Tactic)'" } | Select-Object -First 14 | Join-String -Separator ", ")],
                datasets: [{
                    label: 'Number of Rules',
                    data: [$($tacticsStats | ForEach-Object { $_.UniqueRules } | Select-Object -First 14 | Join-String -Separator ", ")],
                    backgroundColor: 'rgba(240, 78, 35, 0.7)',
                    borderColor: 'rgb(240, 78, 35)',
                    borderWidth: 2
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Rules per MITRE ATT&CK Tactic'
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });

        // Techniques distribution chart (top 15)
        const techniquesCtx = document.getElementById('techniquesChart').getContext('2d');
        const techniquesChart = new Chart(techniquesCtx, {
            type: 'bar',
            data: {
                labels: [$($techniquesStats | Select-Object -First 15 | ForEach-Object { "'$($_.TechniqueID)'" } | Join-String -Separator ", ")],
                datasets: [{
                    label: 'Number of Rules',
                    data: [$($techniquesStats | Select-Object -First 15 | ForEach-Object { $_.UniqueRules } | Join-String -Separator ", ")],
                    backgroundColor: 'rgba(214, 51, 1, 0.7)',
                    borderColor: 'rgb(214, 51, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Top 15 Techniques by Rule Count'
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

    $htmlReport | Out-File -FilePath $htmlFilePath -Encoding UTF8
    Write-Host "HTML report generated: $htmlFilePath" -ForegroundColor Green
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   COVERAGE SUMMARY                                        ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nMITRE ATT&CK Framework Coverage:" -ForegroundColor Cyan
Write-Host "  Total Tactics Covered: $($tacticsDistribution.Count) / 14" -ForegroundColor White
Write-Host "  Total Techniques Covered: $($mainTechniques.Count)" -ForegroundColor White
Write-Host "  Total Subtechniques Covered: $($subTechniques.Count)" -ForegroundColor White

if ($rulesWithoutMitre -gt 0) {
    Write-Host "`n⚠️  Rules Without MITRE ATT&CK Mapping:" -ForegroundColor Yellow
    Write-Host "  Total: $rulesWithoutMitre rules ($([math]::Round(($rulesWithoutMitre / $filteredRules.Count) * 100, 1))%)" -ForegroundColor Yellow
    
    $noMitreByType = $rulesMitreData | Where-Object { -not $_.HasMitreData } | Group-Object -Property Type | Sort-Object Count -Descending
    if ($noMitreByType) {
        Write-Host "  By Rule Type:" -ForegroundColor Yellow
        foreach ($type in $noMitreByType) {
            Write-Host "    $($type.Name): $($type.Count)" -ForegroundColor White
        }
    }
    
    $noMitreBySeverity = $rulesMitreData | Where-Object { -not $_.HasMitreData } | Group-Object -Property Severity | Sort-Object Name -Descending
    if ($noMitreBySeverity) {
        Write-Host "  By Severity:" -ForegroundColor Yellow
        foreach ($severity in $noMitreBySeverity) {
            $color = switch ($severity.Name) {
                "critical" { "Red" }
                "high" { "Red" }
                "medium" { "Yellow" }
                "low" { "White" }
                default { "Gray" }
            }
            Write-Host "    $($severity.Name): $($severity.Count)" -ForegroundColor $color
        }
    }
    
    Write-Host "`n  Action Required: Review these rules and add MITRE ATT&CK classifications" -ForegroundColor Yellow
}

# Identify tactics with low coverage
$lowCoverageTactics = $tacticsStats | Where-Object { $_.UniqueRules -lt 5 }
if ($lowCoverageTactics) {
    Write-Host "`nTactics with Low Coverage (<5 rules):" -ForegroundColor Yellow
    foreach ($tactic in $lowCoverageTactics) {
        Write-Host "  $($tactic.Tactic): $($tactic.UniqueRules) rules" -ForegroundColor Yellow
    }
}

# Identify techniques with single rule coverage
$singleRuleTechniques = $techniquesStats | Where-Object { $_.UniqueRules -eq 1 -and -not $_.IsSubtechnique }
if ($singleRuleTechniques) {
    Write-Host "`nTechniques with Only 1 Rule (potential gaps):" -ForegroundColor Yellow
    Write-Host "  Count: $($singleRuleTechniques.Count)" -ForegroundColor Yellow
    Write-Host "  Consider adding additional detection rules for these techniques" -ForegroundColor Yellow
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   ANALYSIS COMPLETE                                       ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green

if ($OutputFormat -ne "Console") {
    Write-Host "`nFiles Generated in: $scriptDirectory" -ForegroundColor Cyan
    
    if ($OutputFormat -in @("CSV", "All")) {
        Write-Host "`n  CSV Files:" -ForegroundColor Yellow
        Write-Host "    • KibanaRuleMITRE_Tactics_$reportDate.csv" -ForegroundColor White
        Write-Host "    • KibanaRuleMITRE_Techniques_$reportDate.csv" -ForegroundColor White
        Write-Host "    • KibanaRuleMITRE_AllRules_$reportDate.csv" -ForegroundColor White
        Write-Host "    • KibanaRuleMITRE_RulesWithMITRE_$reportDate.csv" -ForegroundColor White
        Write-Host "    • KibanaRuleMITRE_RulesWithoutMITRE_$reportDate.csv" -ForegroundColor White
        Write-Host "    • KibanaRuleMITRE_TacticTechniqueMapping_$reportDate.csv" -ForegroundColor White
    }
    
    if ($OutputFormat -in @("JSON", "All")) {
        Write-Host "`n  JSON Files:" -ForegroundColor Yellow
        Write-Host "    • KibanaRuleMITRE_Coverage_$reportDate.json" -ForegroundColor White
    }
    
    if ($OutputFormat -in @("HTML", "All")) {
        Write-Host "`n  HTML Files:" -ForegroundColor Yellow
        Write-Host "    • KibanaRuleMITRE_Coverage_$reportDate.html" -ForegroundColor White
    }
}

Write-Host "`n📊 Report Summary:" -ForegroundColor Cyan
Write-Host "  Analyzed $($filteredRules.Count) detection rules" -ForegroundColor Green
Write-Host "  Found $rulesWithMitre rules with MITRE mappings" -ForegroundColor Green
Write-Host "  Identified $rulesWithoutMitre rules without MITRE mappings" -ForegroundColor Yellow
Write-Host "  Covered $($tacticsDistribution.Count) tactics and $($mainTechniques.Count) techniques" -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Review tactics and techniques with low rule counts" -ForegroundColor White
Write-Host "  2. Investigate $rulesWithoutMitre rules without MITRE mappings" -ForegroundColor White
Write-Host "  3. Consider creating new rules for under-covered attack vectors" -ForegroundColor White
Write-Host "  4. Validate existing rule effectiveness through testing" -ForegroundColor White
