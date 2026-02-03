<#
.SYNOPSIS
    Analyzes Elastic detection rule execution schedules and intervals and returns a HTML report.

.DESCRIPTION
    Provides a comprehensive breakdown of rules by execution interval:
    - Distribution of rules across different schedules (5m, 15m, 30m, etc.)
    - Potential scheduling conflicts (too many rules at same interval)
    - Recommendations for schedule optimization

.PARAMETER KibanaUrl
    Your Kibana deployment URL

.PARAMETER ApiKey
    Your Kibana API Key value

.PARAMETER OutputPath
    Path to save HTML report

.EXAMPLE
    .\Get-KibanaSecurityRulesSchedules.ps1 -KibanaUrl "https://yourelasticinstance.io" -ApiKey "YOUR_KEY"

.NOTES
    Author: Geoff Tankersley
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$KibanaUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "ElasticRuleScheduleDistribution.html"
)

$headers = @{
    'Authorization' = "ApiKey $ApiKey"
    'kbn-xsrf' = 'true'
    'Content-Type' = 'application/json'
}

function Get-AllRules {
    Write-Host "[*] Fetching all enabled detection rules..." -ForegroundColor Cyan
    
    try {
        $response = Invoke-RestMethod -Uri "$KibanaUrl/api/detection_engine/rules/_find?per_page=10000" -Headers $headers
        
        # Enabled rules only
        $securityRuleTypes = @('query', 'eql', 'threshold', 'machine_learning', 'threat_match', 'new_terms', 'esql', 'saved_query')
        $enabledRules = $response.data | Where-Object { $_.enabled -eq $true -and $securityRuleTypes -contains $_.type }
        
        Write-Host "[+] Retrieved $($enabledRules.Count) enabled security detection rules" -ForegroundColor Green
        return $enabledRules
    }
    catch {
        Write-Host "[!] Error fetching rules: $_" -ForegroundColor Red
        return @()
    }
}

function Convert-IntervalToMinutes {
    param([string]$Interval)
    
    if ($Interval -match '(\d+)s') {
        return [math]::Round([int]$matches[1] / 60, 2)
    }
    elseif ($Interval -match '(\d+)m') {
        return [int]$matches[1]
    }
    elseif ($Interval -match '(\d+)h') {
        return [int]$matches[1] * 60
    }
    else {
        return 5  # Elastic rule default
    }
}

function Convert-FromToMinutes {
    param([string]$From)
    
    if ($From -match 'now-(\d+)s') {
        return [math]::Round([int]$matches[1] / 60, 2)
    }
    elseif ($From -match 'now-(\d+)m') {
        return [int]$matches[1]
    }
    elseif ($From -match 'now-(\d+)h') {
        return [int]$matches[1] * 60
    }
    else {
        return 5  # Elastic rule default
    }
}

function Get-ScheduleAnalysis {
    param($Rules)
    
    Write-Host "[*] Analyzing rule schedules..." -ForegroundColor Cyan
    
    $analysis = @{
        ByInterval = @{}
        ByLookback = @{}
        TotalRules = $Rules.Count
        PotentialConflicts = @()
        Recommendations = @()
    }
    
    foreach ($rule in $Rules) {
        $interval = $rule.interval
        $from = $rule.from
        
        # Group by interval
        if (-not $analysis.ByInterval.ContainsKey($interval)) {
            $analysis.ByInterval[$interval] = @{
                Count = 0
                Rules = @()
                IntervalMinutes = Convert-IntervalToMinutes -Interval $interval
            }
        }
        $analysis.ByInterval[$interval].Count++
        $analysis.ByInterval[$interval].Rules += @{
            Name = $rule.name
            Type = $rule.type
            From = $from
            RiskScore = $rule.risk_score
            Severity = $rule.severity
        }
        
        # Group by lookback
        if (-not $analysis.ByLookback.ContainsKey($from)) {
            $analysis.ByLookback[$from] = @{
                Count = 0
                LookbackMinutes = Convert-FromToMinutes -From $from
            }
        }
        $analysis.ByLookback[$from].Count++
    }
    
    # Identify conflicts
    foreach ($interval in $analysis.ByInterval.Keys) {
        $count = $analysis.ByInterval[$interval].Count
        $minutes = $analysis.ByInterval[$interval].IntervalMinutes
        
        if ($count -gt 100) {
            $analysis.PotentialConflicts += @{
                Interval = $interval
                Count = $count
                Severity = "High"
                Issue = "$count rules executing every $interval could cause resource contention"
                Recommendation = "Consider staggering some rules to adjacent intervals"
            }
        }
        elseif ($count -gt 50) {
            $analysis.PotentialConflicts += @{
                Interval = $interval
                Count = $count
                Severity = "Medium"
                Issue = "$count rules executing every $interval may cause performance issues"
                Recommendation = "Monitor for execution delays and consider staggering"
            }
        }
        
        if ($minutes -le 5 -and $count -gt 50) {
            $analysis.Recommendations += "Consider if all $count rules really need $interval interval - some may be candidates for less frequent execution"
        }
    }
    
    if ($analysis.ByInterval.ContainsKey("5m") -and $analysis.ByInterval["5m"].Count -gt 200) {
        $analysis.Recommendations += "Very high concentration of 5-minute rules ($($analysis.ByInterval['5m'].Count)) - review if all require real-time detection"
    }
    
    return $analysis
}

function Generate-ScheduleReport {
    param($Analysis)
    
    Write-Host "[*] Generating HTML schedule report..." -ForegroundColor Cyan
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Elastic Detection Rule Schedule Analysis</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #1a1a1a;
            border-bottom: 3px solid #0079a8;
            padding-bottom: 10px;
        }
        h2 {
            color: #333;
            margin-top: 30px;
            border-bottom: 2px solid #eee;
            padding-bottom: 8px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #0079a8;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #666;
        }
        .summary-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }
        .summary-card .subtext {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        .interval-section {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .interval-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        .interval-title {
            font-size: 20px;
            font-weight: bold;
            color: #0079a8;
        }
        .interval-count {
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }
        .interval-bar {
            height: 40px;
            background: linear-gradient(90deg, #0079a8, #00a8e8);
            border-radius: 4px;
            margin: 10px 0;
            display: flex;
            align-items: center;
            padding: 0 15px;
            color: white;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 13px;
        }
        thead {
            background-color: #f8f9fa;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        tbody tr:hover {
            background-color: #f5f5f5;
        }
        .metadata {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            font-size: 13px;
            color: #666;
        }
        .alert {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .alert.high {
            background: #f8d7da;
            border-color: #dc3545;
        }
        .alert h4 {
            margin: 0 0 10px 0;
            color: #856404;
        }
        .alert.high h4 {
            color: #721c24;
        }
        .recommendations {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-left: 4px solid #0079a8;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .recommendations h3 {
            margin: 0 0 10px 0;
            color: #0c5460;
        }
        .severity-high { color: #dc3545; font-weight: bold; }
        .severity-medium { color: #ffa500; font-weight: bold; }
        .severity-low { color: #28a745; }
        .severity-critical { color: #721c24; font-weight: bold; }
        .toggle-rules {
            background: #0079a8;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-top: 10px;
        }
        .toggle-rules:hover {
            background: #006090;
        }
        .rule-list {
            display: none;
            margin-top: 15px;
        }
        .rule-list.show {
            display: block;
        }
    </style>
    <script>
        function toggleRules(intervalId) {
            var element = document.getElementById(intervalId);
            element.classList.toggle('show');
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>📅 Detection Rule Schedule Analysis</h1>
        
        <div class="metadata">
            <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
            <strong>Kibana Instance:</strong> $KibanaUrl<br>
            <strong>Total Enabled Rules Analyzed:</strong> $($Analysis.TotalRules)
        </div>
        
        <h2>Schedule Distribution Summary</h2>
        <div class="summary-grid">
"@

    # Sort intervals by top for summary
    $sortedIntervals = $Analysis.ByInterval.GetEnumerator() | Sort-Object { $_.Value.IntervalMinutes }
    $topIntervals = $Analysis.ByInterval.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 4
    
    foreach ($entry in $topIntervals) {
        $interval = $entry.Key
        $data = $entry.Value
        $percentage = [math]::Round(($data.Count / $Analysis.TotalRules) * 100, 1)
        
        $html += @"
            <div class="summary-card">
                <h3>Every $interval</h3>
                <div class="value">$($data.Count)</div>
                <div class="subtext">$percentage% of all rules</div>
            </div>
"@
    }
    
    $html += "</div>"

    # Potential conflicts
    if ($Analysis.PotentialConflicts.Count -gt 0) {
        $html += "<h2>⚠️ Potential Scheduling Conflicts</h2>"
        
        foreach ($conflict in $Analysis.PotentialConflicts | Sort-Object Count -Descending) {
            $alertClass = if ($conflict.Severity -eq "High") { "high" } else { "alert" }
            $html += @"
            <div class="alert $alertClass">
                <h4>[$($conflict.Severity)] $($conflict.Interval) Interval</h4>
                <p><strong>Issue:</strong> $($conflict.Issue)</p>
                <p><strong>Recommendation:</strong> $($conflict.Recommendation)</p>
            </div>
"@
        }
    }
    
    # Recs
    if ($Analysis.Recommendations.Count -gt 0) {
        $html += '<div class="recommendations"><h3>💡 Schedule Optimization Recommendations</h3><ul>'
        foreach ($rec in $Analysis.Recommendations) {
            $html += "<li>$rec</li>"
        }
        $html += "</ul></div>"
    }
    
    # Detailed breakdown
    $html += "<h2>Detailed Breakdown by Interval</h2>"
    
    foreach ($entry in $sortedIntervals) {
        $interval = $entry.Key
        $data = $entry.Value
        $percentage = [math]::Round(($data.Count / $Analysis.TotalRules) * 100, 1)
        $safeId = $interval -replace '[^a-zA-Z0-9]', ''
        
        $html += @"
        <div class="interval-section">
            <div class="interval-header">
                <div class="interval-title">Every $interval ($($data.IntervalMinutes) minutes)</div>
                <div class="interval-count">$($data.Count) rules</div>
            </div>
            <div class="interval-bar" style="width: $percentage%;">
                $percentage% of total rules
            </div>
            <button class="toggle-rules" onclick="toggleRules('rules-$safeId')">Show/Hide Rules</button>
            <div id="rules-$safeId" class="rule-list">
                <table>
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Type</th>
                            <th>Lookback</th>
                            <th>Severity</th>
                            <th>Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($rule in ($data.Rules | Sort-Object Name)) {
            $severityClass = "severity-" + $rule.Severity.ToLower()
            $html += "<tr><td>$($rule.Name)</td><td>$($rule.Type)</td><td>$($rule.From)</td><td class='$severityClass'>$($rule.Severity)</td><td>$($rule.RiskScore)</td></tr>"
        }
        
        $html += "</tbody></table></div></div>"
    }
    
    # Lookback
    $html += "<h2>Lookback Time Distribution</h2><table><thead><tr><th>Lookback Period</th><th>Minutes</th><th>Rule Count</th><th>% of Total</th></tr></thead><tbody>"
    
    foreach ($entry in ($Analysis.ByLookback.GetEnumerator() | Sort-Object { $_.Value.LookbackMinutes })) {
        $lookback = $entry.Key
        $data = $entry.Value
        $percentage = [math]::Round(($data.Count / $Analysis.TotalRules) * 100, 1)
        $html += "<tr><td>$lookback</td><td>$($data.LookbackMinutes)</td><td>$($data.Count)</td><td>$percentage%</td></tr>"
    }
    
    $html += "</tbody></table></div></body></html>"

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "[+] Schedule report saved to: $OutputPath" -ForegroundColor Green
}

# MAIN
Write-Host "`n[*] Starting Rule Schedule Analysis..." -ForegroundColor Cyan
Write-Host "[*] Target: $KibanaUrl`n" -ForegroundColor Cyan

$rules = Get-AllRules

if ($rules.Count -eq 0) {
    Write-Host "[!] No enabled rules found. Exiting." -ForegroundColor Red
    exit 1
}

$analysis = Get-ScheduleAnalysis -Rules $rules

# Console summary
Write-Host "`n" ("="*100) -ForegroundColor Yellow
Write-Host " SCHEDULE ANALYSIS SUMMARY" -ForegroundColor Yellow
Write-Host ("="*100) -ForegroundColor Yellow

Write-Host "`n[*] Rule Distribution by Interval:" -ForegroundColor Cyan
$analysis.ByInterval.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | ForEach-Object {
    $percentage = [math]::Round(($_.Value.Count / $analysis.TotalRules) * 100, 1)
    Write-Host ("  {0,-10} : {1,4} rules ({2,5}%)" -f $_.Key, $_.Value.Count, $percentage) -ForegroundColor Gray
}

if ($analysis.PotentialConflicts.Count -gt 0) {
    Write-Host "`n[!] Potential Scheduling Conflicts:" -ForegroundColor Yellow
    foreach ($conflict in $analysis.PotentialConflicts) {
        $color = if($conflict.Severity -eq 'High'){'Red'}else{'Yellow'}
        Write-Host ("  [{0}] {1}: {2} rules" -f $conflict.Severity, $conflict.Interval, $conflict.Count) -ForegroundColor $color
    }
}

Write-Host "`n[+] Full report: $OutputPath" -ForegroundColor Green
Write-Host "[*] Open in browser to see detailed breakdown and recommendations`n" -ForegroundColor Cyan

Generate-ScheduleReport -Analysis $analysis
