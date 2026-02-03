<#
.SYNOPSIS
    Analyzes Kibana Security rule performance metrics

.DESCRIPTION
    Queries rule execution statistics via Kibana API and generates a report showing:
    - Rules with excessive search/query duration
    - Rules with high indexing duration
    - Rules with high total execution duration
    - Rules with schedule delays
    - Rules with warning/failed status counts
    
    Generates an HTML report (KibanaSecurityRulesPerformanceReport.html) by default.

.PARAMETER KibanaUrl
    Your Kibana deployment URL

.PARAMETER ApiKey
    Your API key for Kibana

.PARAMETER DaysBack
    Number of days to analyze

.PARAMETER OutputPath
    Path to save the report (optional). Defaults to KibanaSecurityRulesPerformanceReport.html in current directory.
    If path ends in .csv, will also export CSV in addition to HTML.

.PARAMETER IncludeDisabled
    Include disabled rules in analysis (default: only enabled rules)

.PARAMETER IncludeObservability
    Include observability/SLO rules in analysis (default: only security detection rules)

.PARAMETER UseDetailedHistory
    Attempt to query detailed execution history for each rule (SLOW - can take 30+ minutes for 800+ rules).
    Default: Uses last execution summary only (FAST - completes in 2-3 minutes).
    Only works on on-premise deployments with event log access. Not recommended for Elastic Cloud.

.EXAMPLE
    .\Get-ElasticRulePerformance-Cloud.ps1 -KibanaUrl "https://instance.kb.us-east-1.aws.found.io" -ApiKey "your-api-key"
    # Generates KibanaSecurityRulesPerformanceReport.html in current directory

.EXAMPLE
    .\Get-ElasticRulePerformance-Cloud.ps1 -KibanaUrl "https://instance.kb.us-east-1.aws.found.io" -ApiKey "your-api-key" -DaysBack 14
    # Analyzes last 14 days and generates HTML report

.EXAMPLE
    # Include disabled rules and observability rules
    .\Get-KibanaSecurityRulesPerformanceReport.ps1 -KibanaUrl "https://instance.kb.us-east-1.aws.found.io" -ApiKey "key" -IncludeDisabled -IncludeObservability

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
    [int]$DaysBack = 7,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeObservability,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseDetailedHistory
)

# Problem rule thresholds (in milliseconds)
$script:Thresholds = @{
    SearchDuration = 5000      # 5 seconds
    IndexingDuration = 2000    # 2 seconds
    ExecutionDuration = 10000  # 10 seconds
    ScheduleDelay = 30000      # 30 seconds
    WarningCount = 5
    FailureCount = 1
}

function Get-KibanaHeaders {
    return @{
        'Content-Type' = 'application/json'
        'kbn-xsrf' = 'true'
        'Authorization' = "ApiKey $ApiKey"
    }
}

function Get-AllDetectionRules {
    Write-Host "[*] Fetching all detection rules..." -ForegroundColor Cyan
    
    try {
        $uri = "$KibanaUrl/api/detection_engine/rules/_find?per_page=10000"
        $headers = Get-KibanaHeaders
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        
        Write-Host "[+] Found $($response.total) detection rules" -ForegroundColor Green
        
        # Define security detection rule types (exclude observability)
        $securityRuleTypes = @(
            'query',
            'eql', 
            'threshold',
            'machine_learning',
            'threat_match',
            'new_terms',
            'esql',
            'saved_query'
        )
        
        $filteredRules = $response.data
        
        # Filter by enabled
        if (-not $IncludeDisabled) {
            $beforeCount = $filteredRules.Count
            $filteredRules = $filteredRules | Where-Object { $_.enabled -eq $true }
            $disabledCount = $beforeCount - $filteredRules.Count
            Write-Host "[*] Filtered out $disabledCount disabled rules" -ForegroundColor DarkGray
        }
        
        # Filter out observability rules (default: exclude)
        if (-not $IncludeObservability) {
            $beforeCount = $filteredRules.Count
            $filteredRules = $filteredRules | Where-Object { $securityRuleTypes -contains $_.type }
            $observabilityCount = $beforeCount - $filteredRules.Count
            if ($observabilityCount -gt 0) {
                Write-Host "[*] Filtered out $observabilityCount observability/SLO rules" -ForegroundColor DarkGray
            }
        }
        
        Write-Host "[+] Analyzing $($filteredRules.Count) security detection rules (enabled only)" -ForegroundColor Green
        
        return $filteredRules
    }
    catch {
        Write-Host "[!] Error fetching detection rules: $_" -ForegroundColor Red
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $responseBody = $reader.ReadToEnd()
            Write-Host "[!] Response: $responseBody" -ForegroundColor Red
        }
        return $null
    }
}

function Get-RuleExecutionEvents {
    param(
        [string]$RuleId,
        [datetime]$StartDate,
        [datetime]$EndDate,
        [int]$TimeoutSeconds = 30
    )
    
    $query = @{
        size = 1000
        query = @{
            bool = @{
                must = @(
                    @{
                        term = @{
                            "rule.id" = $RuleId
                        }
                    },
                    @{
                        term = @{
                            "event.provider" = "alerting"
                        }
                    },
                    @{
                        term = @{
                            "event.action" = "execute"
                        }
                    },
                    @{
                        range = @{
                            "@timestamp" = @{
                                gte = $StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                                lte = $EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            }
                        }
                    }
                )
            }
        }
        sort = @(
            @{
                "@timestamp" = @{
                    order = "desc"
                }
            }
        )
    } | ConvertTo-Json -Depth 10
    
    try {
        $uri = "$KibanaUrl/internal/search/es"
        $body = @{
            params = @{
                index = ".kibana-event-log-*"
                body = $query
            }
        } | ConvertTo-Json -Depth 10
        
        $headers = Get-KibanaHeaders
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        
        if ($response.rawResponse -and $response.rawResponse.hits) {
            return $response.rawResponse.hits.hits
        }
        return @()
    }
    catch {
        return @()
    }
}

function Parse-RuleMetricsFromSummary {
    param($rules)
    
    Write-Host "[*] Analyzing rule execution summaries..." -ForegroundColor Cyan
    
    $results = @()
    $processedCount = 0
    
    foreach ($rule in $rules) {
        $processedCount++
        if ($processedCount % 50 -eq 0) {
            Write-Host "[*] Processed $processedCount / $($rules.Count) rules..." -ForegroundColor DarkGray
        }
        
        $summary = $rule.execution_summary
        
        if (-not $summary) {
            continue
        }
        
        # Parse last execution
        $lastExecution = $summary.last_execution
        
        if ($lastExecution) {
            $searchDuration = if ($lastExecution.metrics.total_search_duration_ms) { 
                [double]$lastExecution.metrics.total_search_duration_ms 
            } else { 0 }
            
            $indexingDuration = if ($lastExecution.metrics.total_indexing_duration_ms) { 
                [double]$lastExecution.metrics.total_indexing_duration_ms 
            } else { 0 }
            
            $execDuration = if ($lastExecution.metrics.execution_gap_duration_s) {
                [double]$lastExecution.metrics.execution_gap_duration_s * 1000
            } else { 0 }
            
            $scheduleDelay = if ($lastExecution.metrics.execution_gap_duration_s) {
                [double]$lastExecution.metrics.execution_gap_duration_s * 1000
            } else { 0 }
        }
        else {
            $searchDuration = 0
            $indexingDuration = 0
            $execDuration = 0
            $scheduleDelay = 0
        }
        
        # Get success/failure stats
        $successCount = if ($summary.last_execution.status -eq 'succeeded') { 1 } else { 0 }
        $failureCount = if ($summary.last_execution.status -eq 'failed') { 1 } else { 0 }
        $warningCount = if ($summary.last_execution.status -eq 'partial failure') { 1 } else { 0 }
        
        $results += [PSCustomObject]@{
            RuleId = $rule.id
            RuleName = $rule.name
            RuleType = $rule.type
            Enabled = $rule.enabled
            Interval = $rule.interval
            LastExecutionDate = $lastExecution.date
            LastExecutionStatus = $lastExecution.status
            AvgSearchDuration = [math]::Round($searchDuration, 2)
            AvgIndexingDuration = [math]::Round($indexingDuration, 2)
            AvgExecutionDuration = [math]::Round($execDuration, 2)
            AvgScheduleDelay = [math]::Round($scheduleDelay, 2)
            SuccessCount = $successCount
            WarningCount = $warningCount
            FailureCount = $failureCount
        }
    }
    
    return $results
}

function Get-DetailedRuleMetrics {
    param($rules)
    
    Write-Host "[*] Attempting to gather detailed execution metrics..." -ForegroundColor Cyan
    Write-Host "[!] WARNING: This can take 30+ minutes for large rule sets" -ForegroundColor Yellow
    
    $endDate = Get-Date
    $startDate = $endDate.AddDays(-$DaysBack)
    
    $detailedMetrics = @()
    $ruleCount = 0
    $failedQueries = 0
    
    foreach ($rule in $rules) {
        $ruleCount++
        
        if ($ruleCount % 10 -eq 0) {
            Write-Host "[*] Querying execution history: $ruleCount / $($rules.Count) rules..." -ForegroundColor DarkGray
            if ($failedQueries -gt 5) {
                Write-Host "[!] Multiple query failures detected - likely API does not support detailed history" -ForegroundColor Yellow
                Write-Host "[*] Stopping detailed query attempt, will use execution summary instead" -ForegroundColor Yellow
                return $null
            }
        }
        
        # Try to get execution events for this specific rule with timeout
        try {
            $events = Get-RuleExecutionEvents -RuleId $rule.id -StartDate $startDate -EndDate $endDate -TimeoutSeconds 10
            
            if (-not $events -or $events.Count -eq 0) {
                $failedQueries++
                continue
            }
        }
        catch {
            $failedQueries++
            if ($ruleCount -lt 20 -and $failedQueries -gt 10) {
                Write-Host "[!] Too many failures early in query - API likely does not support this" -ForegroundColor Yellow
                return $null
            }
            continue
        }
        
        if ($events -and $events.Count -gt 0) {
            $stats = @{
                TotalSearchDuration = 0
                TotalIndexingDuration = 0
                TotalExecutionDuration = 0
                TotalScheduleDelay = 0
                SuccessCount = 0
                WarningCount = 0
                FailureCount = 0
                ExecutionCount = $events.Count
            }
            
            foreach ($event in $events) {
                $source = $event._source
                
                if ($source.'kibana.alert.rule.execution.metrics.total_search_duration_ms') {
                    $stats.TotalSearchDuration += [double]$source.'kibana.alert.rule.execution.metrics.total_search_duration_ms'
                }
                
                if ($source.'kibana.alert.rule.execution.metrics.total_indexing_duration_ms') {
                    $stats.TotalIndexingDuration += [double]$source.'kibana.alert.rule.execution.metrics.total_indexing_duration_ms'
                }
                
                if ($source.'event.duration') {
                    $stats.TotalExecutionDuration += [double]$source.'event.duration' / 1000000
                }
                
                if ($source.'kibana.alert.rule.execution.metrics.execution_gap_duration_s') {
                    $stats.TotalScheduleDelay += [double]$source.'kibana.alert.rule.execution.metrics.execution_gap_duration_s' * 1000
                }
                
                $outcome = $source.'event.outcome'
                if ($outcome -eq 'success') {
                    $stats.SuccessCount++
                }
                elseif ($outcome -eq 'failure') {
                    $stats.FailureCount++
                }
                else {
                    $stats.WarningCount++
                }
            }
            
            $detailedMetrics += [PSCustomObject]@{
                RuleId = $rule.id
                RuleName = $rule.name
                RuleType = $rule.type
                Enabled = $rule.enabled
                Interval = $rule.interval
                ExecutionCount = $stats.ExecutionCount
                AvgSearchDuration = [math]::Round($stats.TotalSearchDuration / $stats.ExecutionCount, 2)
                AvgIndexingDuration = [math]::Round($stats.TotalIndexingDuration / $stats.ExecutionCount, 2)
                AvgExecutionDuration = [math]::Round($stats.TotalExecutionDuration / $stats.ExecutionCount, 2)
                AvgScheduleDelay = [math]::Round($stats.TotalScheduleDelay / $stats.ExecutionCount, 2)
                SuccessCount = $stats.SuccessCount
                WarningCount = $stats.WarningCount
                FailureCount = $stats.FailureCount
                SuccessRate = [math]::Round(($stats.SuccessCount / $stats.ExecutionCount) * 100, 2)
            }
        }
    }
    
    if ($detailedMetrics.Count -gt 0) {
        Write-Host "[+] Retrieved detailed metrics for $($detailedMetrics.Count) rules" -ForegroundColor Green
        return $detailedMetrics
    }
    
    return $null
}

function Get-ProblematicRules {
    param($metrics)
    
    Write-Host "`n[*] Analyzing rules against performance thresholds..." -ForegroundColor Cyan
    
    $problematic = @{
        ExcessiveSearchDuration = @()
        ExcessiveIndexingDuration = @()
        ExcessiveExecutionDuration = @()
        ExcessiveScheduleDelay = @()
        HighWarningCount = @()
        HighFailureCount = @()
        DisabledRules = @()
    }
    
    foreach ($rule in $metrics) {
        if ($rule.AvgSearchDuration -gt $script:Thresholds.SearchDuration) {
            $problematic.ExcessiveSearchDuration += $rule
        }
        if ($rule.AvgIndexingDuration -gt $script:Thresholds.IndexingDuration) {
            $problematic.ExcessiveIndexingDuration += $rule
        }
        if ($rule.AvgExecutionDuration -gt $script:Thresholds.ExecutionDuration) {
            $problematic.ExcessiveExecutionDuration += $rule
        }
        if ($rule.AvgScheduleDelay -gt $script:Thresholds.ScheduleDelay) {
            $problematic.ExcessiveScheduleDelay += $rule
        }
        if ($rule.WarningCount -gt $script:Thresholds.WarningCount) {
            $problematic.HighWarningCount += $rule
        }
        if ($rule.FailureCount -gt $script:Thresholds.FailureCount) {
            $problematic.HighFailureCount += $rule
        }
        if (-not $rule.Enabled) {
            $problematic.DisabledRules += $rule
        }
    }
    
    return $problematic
}

function Get-DetailedRootCauseForRule {
    param(
        [string]$RuleId,
        [string]$RuleName,
        [string]$RuleType,
        [string]$Status
    )
    
    # Fetch full rule details to get error message
    try {
        $ruleUri = "$KibanaUrl/api/detection_engine/rules?id=$RuleId"
        $headers = Get-KibanaHeaders
        $rule = Invoke-RestMethod -Uri $ruleUri -Method Get -Headers $headers
        
        $errorMsg = $rule.execution_summary.last_execution.message
        $rootCauses = @()
        $recommendations = @()
        
        if ($errorMsg) {
            # 1. Execution gap warnings
            if ($errorMsg -match "(\d+)\s*(second|minute|hour)s?\s*\((\d+)ms\)\s*were not queried between") {
                $gapTime = $matches[1]
                $gapUnit = $matches[2]
                $rootCauses += "Execution gap: $gapTime $gapUnit of events were skipped due to rule execution delays"
                $recommendations += "Increase lookback time or optimize slow rules to prevent execution delays"
            }
            
            # 2. Query syntax errors (backslash issues)
            if ($errorMsg -match 'Expected "\)".*but "\\"\s*found') {
                $rootCauses += "Query syntax error: Improperly escaped backslashes in Windows paths"
                $recommendations += "Fix query: Use double backslashes (C:\\\\Windows\\) or forward slashes (C:/Windows/)"
            }
            
            # 3. Field name typos
            if ($errorMsg -match "Unknown column \[([^\]]+)\], did you mean (?:any of )?\[([^\]]+)\]") {
                $wrongField = $matches[1]
                $correctField = $matches[2]
                $rootCauses += "Field name typo: '$wrongField' should be '$correctField'"
                $recommendations += "Update query to use correct field: $correctField"
            }
            elseif ($errorMsg -match "Unknown column \[([^\]]+)\]") {
                $fieldName = $matches[1]
                $rootCauses += "Missing field: $fieldName does not exist in your data"
                $recommendations += "Deploy integration or agent that provides this field"
            }
            
            # 4. ML job missing
            if ($errorMsg -match "([a-z0-9_]+)\s+missing") {
                $jobName = $matches[1]
                $rootCauses += "ML job missing: '$jobName' does not exist or is not running"
                $recommendations += "Go to ML > Anomaly Detection and start job: $jobName"
            }
            
            # 5. Rule disabled during execution
            if ($errorMsg -match "rule ran after it was disabled") {
                $rootCauses += "Rule was disabled while execution was in progress (transient error)"
                $recommendations += "Re-enable rule if you want it to run, otherwise ignore"
            }
            
            # 6. Timeout errors
            if ($errorMsg -match "execution cancelled due to timeout|exceeded rule type timeout of (\d+)([mh])") {
                $timeoutValue = if ($matches[1]) { $matches[1] } else { "5" }
                $timeoutUnit = if ($matches[2]) { $matches[2] } else { "m" }
                $rootCauses += "Query timeout: Execution exceeded $timeoutValue$timeoutUnit limit"
                $recommendations += "Reduce lookback time (currently: $($rule.from))"
                $recommendations += "Add more specific filters to reduce data volume"
            }
            
            # 7. Index not found
            if ($errorMsg -match "no such index|index_not_found_exception") {
                $rootCauses += "Missing index: Rule searches for indices that don't exist"
                $recommendations += "Deploy agents to create required indices"
            }
            
            # 8. Circuit breaker
            if ($errorMsg -match "circuit_breaking_exception") {
                $rootCauses += "Memory exhaustion: Query consuming too much memory"
                $recommendations += "Reduce query complexity or increase Elasticsearch heap"
            }
            
            # 9. Too many buckets
            if ($errorMsg -match "too_many_buckets") {
                $rootCauses += "Too many aggregation buckets created by query"
                $recommendations += "Reduce cardinality in group-by fields"
            }
            
            # 10. Permission errors
            if ($errorMsg -match "security_exception|authorization") {
                $rootCauses += "Permission denied: Insufficient API key permissions"
                $recommendations += "Grant read permissions on required indices"
            }
            
            # Default if no pattern matched
            if ($rootCauses.Count -eq 0) {
                $rootCauses += "Review error message for details"
            }
        }
        
        return @{
            ErrorMessage = $errorMsg
            RootCauses = $rootCauses
            Recommendations = $recommendations
        }
    }
    catch {
        return @{
            ErrorMessage = "Unable to retrieve error details"
            RootCauses = @("Could not fetch rule details")
            Recommendations = @()
        }
    }
}

function Generate-HtmlReport {
    param(
        $metrics,
        $problematic,
        $detailedAvailable,
        $outputPath
    )
    
    Write-Host "`n[*] Generating HTML report..." -ForegroundColor Cyan
    
    # Stat summary
    $enabledRules = ($metrics | Where-Object { $_.Enabled }).Count
    $disabledRules = ($metrics | Where-Object { -not $_.Enabled }).Count
    $failedRules = ($metrics | Where-Object { $_.LastExecutionStatus -eq 'failed' }).Count
    $warningRules = ($metrics | Where-Object { $_.LastExecutionStatus -eq 'partial failure' }).Count
    
    # Top 10s
    $topSearch = $metrics | Where-Object { $_.AvgSearchDuration -gt 0 } | Sort-Object AvgSearchDuration -Descending | Select-Object -First 10
    $topIndexing = $metrics | Where-Object { $_.AvgIndexingDuration -gt 0 } | Sort-Object AvgIndexingDuration -Descending | Select-Object -First 10
    $failures = $metrics | Where-Object { $_.LastExecutionStatus -eq 'failed' -or $_.FailureCount -gt 0 }
    $warnings = $metrics | Where-Object { $_.LastExecutionStatus -eq 'partial failure' -or $_.WarningCount -gt 0 }
    
    # Rule types
    $ruleTypes = $metrics | Group-Object RuleType | Sort-Object Count -Descending
    
    # HTML report
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Elastic Security Rule Performance Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
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
        h3 {
            color: #555;
            margin-top: 20px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #0079a8;
        }
        .summary-card.warning {
            border-left-color: #ffa500;
        }
        .summary-card.error {
            border-left-color: #dc3545;
        }
        .summary-card.success {
            border-left-color: #28a745;
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
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }
        thead {
            background-color: #0079a8;
            color: white;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        tbody tr:hover {
            background-color: #f5f5f5;
        }
        .status-failed {
            color: #dc3545;
            font-weight: bold;
        }
        .status-warning {
            color: #ffa500;
            font-weight: bold;
        }
        .status-success {
            color: #28a745;
            font-weight: bold;
        }
        .threshold-exceeded {
            background-color: #fff3cd;
        }
        .metadata {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            font-size: 13px;
            color: #666;
        }
        .recommendations {
            background: #e7f3ff;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #0079a8;
        }
        .recommendations h3 {
            margin-top: 0;
            color: #0079a8;
        }
        .recommendations ul {
            line-height: 1.8;
        }
        .rule-type-chart {
            margin: 20px 0;
        }
        .rule-type-bar {
            display: flex;
            align-items: center;
            margin: 10px 0;
        }
        .rule-type-name {
            width: 200px;
            font-weight: 500;
        }
        .rule-type-count {
            flex: 1;
            height: 30px;
            background: linear-gradient(90deg, #0079a8, #00a8e8);
            margin: 0 10px;
            display: flex;
            align-items: center;
            padding: 0 10px;
            color: white;
            border-radius: 4px;
        }
        .rule-analysis {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .rule-analysis.failed {
            border-left: 4px solid #dc3545;
        }
        .rule-analysis.warning {
            border-left: 4px solid #ffa500;
        }
        .rule-header {
            font-size: 16px;
            font-weight: bold;
            color: #333;
            margin-bottom: 8px;
        }
        .error-box {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 4px;
            padding: 12px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 11px;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .root-causes {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            padding: 12px;
            margin: 10px 0;
        }
        .root-causes h4 {
            margin: 0 0 8px 0;
            color: #721c24;
            font-size: 14px;
        }
        .root-causes ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .root-causes li {
            margin: 4px 0;
            color: #721c24;
            font-size: 13px;
        }
        .rule-meta {
            font-size: 12px;
            color: #666;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Elastic Security Rule Performance Report</h1>
        
        <div class="metadata">
            <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
            <strong>Analysis Period:</strong> Last $DaysBack days<br>
            <strong>Total Rules Analyzed:</strong> $($metrics.Count)<br>
            <strong>Data Source:</strong> $(if($detailedAvailable){'Detailed execution history'}else{'Last execution summary (limited history)'})<br>
            <strong>Kibana Instance:</strong> $KibanaUrl
        </div>
        
        <h2>Summary Statistics</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Rules</h3>
                <div class="value">$($metrics.Count)</div>
            </div>
            <div class="summary-card success">
                <h3>Enabled Rules</h3>
                <div class="value">$enabledRules</div>
            </div>
            <div class="summary-card error">
                <h3>Failed Rules</h3>
                <div class="value">$failedRules</div>
            </div>
            <div class="summary-card warning">
                <h3>Partial Failures</h3>
                <div class="value">$warningRules</div>
            </div>
            <div class="summary-card">
                <h3>Disabled Rules</h3>
                <div class="value">$disabledRules</div>
            </div>
            <div class="summary-card warning">
                <h3>Slow Rules (>5s)</h3>
                <div class="value">$($problematic.ExcessiveSearchDuration.Count)</div>
            </div>
        </div>
        
        <h2>Rules by Type</h2>
        <div class="rule-type-chart">
"@

    # Add rule type bars
    $maxCount = ($ruleTypes | Measure-Object -Property Count -Maximum).Maximum
    foreach ($type in $ruleTypes) {
        $percentage = ($type.Count / $maxCount) * 100
        $html += @"
            <div class="rule-type-bar">
                <div class="rule-type-name">$($type.Name)</div>
                <div class="rule-type-count" style="width: $percentage%;">$($type.Count) rules</div>
            </div>
"@
    }

    $html += @"
        </div>
        
        <h2>Top 10 Rules - Excessive Search Duration</h2>
        <p><strong>Threshold:</strong> $($script:Thresholds.SearchDuration)ms</p>
"@

    if ($topSearch) {
        $html += "<table><thead><tr><th>Rule Name</th><th>Rule Type</th><th>Avg Search Duration (ms)</th><th>Interval</th><th>Enabled</th></tr></thead><tbody>"
        foreach ($rule in $topSearch) {
            $rowClass = if ($rule.AvgSearchDuration -gt $script:Thresholds.SearchDuration) { 'class="threshold-exceeded"' } else { '' }
            $html += "<tr $rowClass><td>$($rule.RuleName)</td><td>$($rule.RuleType)</td><td>$([math]::Round($rule.AvgSearchDuration, 2))</td><td>$($rule.Interval)</td><td>$($rule.Enabled)</td></tr>"
        }
        $html += "</tbody></table>"
    } else {
        $html += "<p>No data available</p>"
    }

    $html += @"
        <h2>Top 10 Rules - Excessive Indexing Duration</h2>
        <p><strong>Threshold:</strong> $($script:Thresholds.IndexingDuration)ms</p>
"@

    if ($topIndexing) {
        $html += "<table><thead><tr><th>Rule Name</th><th>Rule Type</th><th>Avg Indexing Duration (ms)</th><th>Interval</th><th>Enabled</th></tr></thead><tbody>"
        foreach ($rule in $topIndexing) {
            $rowClass = if ($rule.AvgIndexingDuration -gt $script:Thresholds.IndexingDuration) { 'class="threshold-exceeded"' } else { '' }
            $html += "<tr $rowClass><td>$($rule.RuleName)</td><td>$($rule.RuleType)</td><td>$([math]::Round($rule.AvgIndexingDuration, 2))</td><td>$($rule.Interval)</td><td>$($rule.Enabled)</td></tr>"
        }
        $html += "</tbody></table>"
    } else {
        $html += "<p>No data available</p>"
    }

    $html += "<h2>Rules with Failures</h2>"

    if ($failures) {
        $html += "<table><thead><tr><th>Rule Name</th><th>Rule Type</th><th>Last Execution Status</th><th>Enabled</th></tr></thead><tbody>"
        foreach ($rule in $failures) {
            $html += "<tr><td>$($rule.RuleName)</td><td>$($rule.RuleType)</td><td class='status-failed'>$($rule.LastExecutionStatus)</td><td>$($rule.Enabled)</td></tr>"
        }
        $html += "</tbody></table>"
        
        # Add detailed root cause analysis for failed rules
        Write-Host "[*] Analyzing root causes for failed rules..." -ForegroundColor Cyan
        
        $html += "<h2>🔍 Root Cause Analysis - Failed Rules</h2>"
        $html += "<p>Detailed diagnostics showing WHY each rule is failing and how to fix it.</p>"
        
        foreach ($rule in $failures) {
            $analysis = Get-DetailedRootCauseForRule -RuleId $rule.RuleId -RuleName $rule.RuleName -RuleType $rule.RuleType -Status $rule.LastExecutionStatus
            
            $html += @"
            <div class="rule-analysis failed">
                <div class="rule-header">$($rule.RuleName)</div>
                <div class="rule-meta"><strong>Type:</strong> $($rule.RuleType) | <strong>Status:</strong> <span class="status-failed">$($rule.LastExecutionStatus)</span></div>
"@
            
            if ($analysis.ErrorMessage) {
                $escapedError = $analysis.ErrorMessage -replace '<', '&lt;' -replace '>', '&gt;'
                $html += @"
                <div class="error-box"><strong>Error Message:</strong><br>$escapedError</div>
"@
            }
            
            if ($analysis.RootCauses.Count -gt 0) {
                $html += '<div class="root-causes"><h4>🎯 Root Causes:</h4><ul>'
                foreach ($cause in $analysis.RootCauses) {
                    $html += "<li>$cause</li>"
                }
                $html += '</ul></div>'
            }
            
            if ($analysis.Recommendations.Count -gt 0) {
                $html += '<div class="recommendations"><h4>💡 Recommended Fixes:</h4><ul>'
                foreach ($rec in $analysis.Recommendations) {
                    $html += "<li>$rec</li>"
                }
                $html += '</ul></div>'
            }
            
            $html += "</div>"
        }
    } else {
        $html += "<p class='status-success'>No rule failures detected</p>"
    }

    $html += "<h2>Rules with Warnings/Partial Failures</h2>"

    if ($warnings) {
        $html += "<table><thead><tr><th>Rule Name</th><th>Rule Type</th><th>Last Execution Status</th><th>Enabled</th></tr></thead><tbody>"
        foreach ($rule in $warnings) {
            $html += "<tr><td>$($rule.RuleName)</td><td>$($rule.RuleType)</td><td class='status-warning'>$($rule.LastExecutionStatus)</td><td>$($rule.Enabled)</td></tr>"
        }
        $html += "</tbody></table>"
        
        # Add detailed root cause analysis for warning rules
        Write-Host "[*] Analyzing root causes for rules with warnings..." -ForegroundColor Cyan
        
        $html += "<h2>🔍 Root Cause Analysis - Partial Failures</h2>"
        $html += "<p>Detailed diagnostics for rules with warnings or partial failures.</p>"
        
        foreach ($rule in $warnings) {
            $analysis = Get-DetailedRootCauseForRule -RuleId $rule.RuleId -RuleName $rule.RuleName -RuleType $rule.RuleType -Status $rule.LastExecutionStatus
            
            $html += @"
            <div class="rule-analysis warning">
                <div class="rule-header">$($rule.RuleName)</div>
                <div class="rule-meta"><strong>Type:</strong> $($rule.RuleType) | <strong>Status:</strong> <span class="status-warning">$($rule.LastExecutionStatus)</span></div>
"@
            
            if ($analysis.ErrorMessage) {
                $escapedError = $analysis.ErrorMessage -replace '<', '&lt;' -replace '>', '&gt;'
                $html += @"
                <div class="error-box"><strong>Warning Message:</strong><br>$escapedError</div>
"@
            }
            
            if ($analysis.RootCauses.Count -gt 0) {
                $html += '<div class="root-causes"><h4>🎯 Likely Causes:</h4><ul>'
                foreach ($cause in $analysis.RootCauses) {
                    $html += "<li>$cause</li>"
                }
                $html += '</ul></div>'
            }
            
            if ($analysis.Recommendations.Count -gt 0) {
                $html += '<div class="recommendations"><h4>💡 Recommended Actions:</h4><ul>'
                foreach ($rec in $analysis.Recommendations) {
                    $html += "<li>$rec</li>"
                }
                $html += '</ul></div>'
            }
            
            $html += "</div>"
        }
    } else {
        $html += "<p class='status-success'>No warnings detected</p>"
    }

    $html += @"
        <h2>Optimization Recommendations</h2>
        
        <div class="recommendations">
            <h3>1. Rules with Slow Search Times</h3>
            <p><strong>Found:</strong> $($problematic.ExcessiveSearchDuration.Count) rules</p>
            <ul>
                <li>Review and optimize KQL/EQL queries</li>
                <li>Reduce lookback time windows</li>
                <li>Add specific index patterns</li>
                <li>Remove excessive wildcards</li>
            </ul>
        </div>
        
        <div class="recommendations">
            <h3>2. Rules with Slow Indexing</h3>
            <p><strong>Found:</strong> $($problematic.ExcessiveIndexingDuration.Count) rules</p>
            <ul>
                <li>Implement alert suppression</li>
                <li>Use alert grouping</li>
                <li>Reduce max_signals threshold</li>
            </ul>
        </div>
        
        <div class="recommendations">
            <h3>3. Failing Rules</h3>
            <p><strong>Found:</strong> $failedRules rules</p>
            <ul>
                <li>Check Kibana logs for specific errors</li>
                <li>Verify rule syntax and field mappings</li>
                <li>Test queries in Dev Tools</li>
                <li>Review connector configurations</li>
            </ul>
        </div>
        
        <div class="recommendations">
            <h3>Next Steps</h3>
            <ol>
                <li>Review failing rules first (highest priority)</li>
                <li>Optimize slow-running rules to reduce cluster load</li>
                <li>Consider using rule exceptions to reduce alert volume</li>
                <li>Monitor rule performance trends weekly</li>
            </ol>
        </div>
    </div>
</body>
</html>
"@

    # Write HTML to file
    $html | Out-File -FilePath $outputPath -Encoding UTF8
    Write-Host "[+] HTML report generated: $outputPath" -ForegroundColor Green
}

function Show-PerformanceReport {
    param(
        $metrics,
        $problematic,
        $detailedAvailable
    )
    
    Write-Host "`n" ("="*100) -ForegroundColor Yellow
    Write-Host " ELASTIC SECURITY RULE PERFORMANCE REPORT" -ForegroundColor Yellow
    Write-Host " Analysis Period: Last $DaysBack days" -ForegroundColor Yellow
    Write-Host " Total Rules Analyzed: $($metrics.Count)" -ForegroundColor Yellow
    if (-not $detailedAvailable) {
        Write-Host " NOTE: Using last execution summary (detailed history not accessible)" -ForegroundColor DarkYellow
    }
    Write-Host ("="*100) -ForegroundColor Yellow
    
    # Console summary
    Write-Host "`n[+] SUMMARY STATISTICS" -ForegroundColor Green
    Write-Host ("-" * 100)
    $enabledRules = ($metrics | Where-Object { $_.Enabled }).Count
    $disabledRules = ($metrics | Where-Object { -not $_.Enabled }).Count
    Write-Host "Enabled Rules: $enabledRules"
    Write-Host "Disabled Rules: $disabledRules"
    
    if ($metrics | Get-Member -Name SuccessRate) {
        $avgSuccessRate = ($metrics | Where-Object { $_.ExecutionCount -gt 0 } | Measure-Object -Property SuccessRate -Average).Average
        Write-Host "Average Success Rate: $([math]::Round($avgSuccessRate, 2))%"
    }
    
    # Rule types
    Write-Host "`n[+] RULES BY TYPE" -ForegroundColor Green
    Write-Host ("-" * 100)
    $metrics | Group-Object RuleType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("{0,-30}: {1,5} rules" -f $_.Name, $_.Count)
    }
    
    # Top 10 Slowest Rules by Search Duration
    Write-Host "`n[!] TOP 10 RULES - SEARCH DURATION" -ForegroundColor Red
    Write-Host ("-" * 100)
    Write-Host ("Threshold: {0}ms" -f $script:Thresholds.SearchDuration) -ForegroundColor DarkGray
    $topSearch = $metrics | Where-Object { $_.AvgSearchDuration -gt 0 } | Sort-Object AvgSearchDuration -Descending | Select-Object -First 10
    if ($topSearch) {
        $topSearch | Format-Table RuleName, RuleType, AvgSearchDuration, Interval, Enabled -AutoSize
    } else {
        Write-Host "No data available" -ForegroundColor DarkGray
    }
    
    # Top 10 Rules by Indexing Duration
    Write-Host "`n[!] TOP 10 RULES - INDEXING DURATION" -ForegroundColor Red
    Write-Host ("-" * 100)
    Write-Host ("Threshold: {0}ms" -f $script:Thresholds.IndexingDuration) -ForegroundColor DarkGray
    $topIndexing = $metrics | Where-Object { $_.AvgIndexingDuration -gt 0 } | Sort-Object AvgIndexingDuration -Descending | Select-Object -First 10
    if ($topIndexing) {
        $topIndexing | Format-Table RuleName, RuleType, AvgIndexingDuration, Interval, Enabled -AutoSize
    } else {
        Write-Host "No data available" -ForegroundColor DarkGray
    }
    
    # Rules with Failures
    Write-Host "`n[!] RULES WITH FAILURES" -ForegroundColor Red
    Write-Host ("-" * 100)
    $failures = $metrics | Where-Object { $_.LastExecutionStatus -eq 'failed' -or $_.FailureCount -gt 0 }
    if ($failures) {
        $failures | Sort-Object FailureCount -Descending | Format-Table RuleName, RuleType, LastExecutionStatus, FailureCount, Enabled -AutoSize
    } else {
        Write-Host "No rule failures detected" -ForegroundColor Green
    }
    
    # Rules with Warnings
    Write-Host "`n[!] RULES WITH WARNINGS/PARTIAL FAILURES" -ForegroundColor Yellow
    Write-Host ("-" * 100)
    $warnings = $metrics | Where-Object { $_.LastExecutionStatus -eq 'partial failure' -or $_.WarningCount -gt 0 }
    if ($warnings) {
        $warnings | Sort-Object WarningCount -Descending | Format-Table RuleName, RuleType, LastExecutionStatus, WarningCount, Enabled -AutoSize
    } else {
        Write-Host "No warnings detected" -ForegroundColor Green
    }
    
    # Disabled Rules
    Write-Host "`n[*] DISABLED RULES" -ForegroundColor Cyan
    Write-Host ("-" * 100)
    Write-Host "Total Disabled: $($problematic.DisabledRules.Count)"
    if ($problematic.DisabledRules.Count -gt 0 -and $problematic.DisabledRules.Count -le 20) {
        $problematic.DisabledRules | Format-Table RuleName, RuleType, LastExecutionStatus -AutoSize
    }
    
    # Recommendations
    Write-Host "`n[+] OPTIMIZATION RECOMMENDATIONS" -ForegroundColor Cyan
    Write-Host ("-" * 100)
    
    Write-Host "`n1. RULES WITH SLOW SEARCH TIMES" -ForegroundColor Yellow
    if ($problematic.ExcessiveSearchDuration.Count -gt 0) {
        Write-Host "   Found: $($problematic.ExcessiveSearchDuration.Count) rules" -ForegroundColor Red
        Write-Host "   Solutions:"
        Write-Host "   - Review and optimize KQL/EQL queries"
        Write-Host "   - Reduce lookback time windows"
        Write-Host "   - Add specific index patterns"
        Write-Host "   - Remove excessive wildcards"
    } else {
        Write-Host "   No issues detected" -ForegroundColor Green
    }
    
    Write-Host "`n2. RULES WITH SLOW INDEXING" -ForegroundColor Yellow
    if ($problematic.ExcessiveIndexingDuration.Count -gt 0) {
        Write-Host "   Found: $($problematic.ExcessiveIndexingDuration.Count) rules" -ForegroundColor Red
        Write-Host "   Solutions:"
        Write-Host "   - Implement alert suppression"
        Write-Host "   - Use alert grouping"
        Write-Host "   - Reduce max_signals threshold"
    } else {
        Write-Host "   No issues detected" -ForegroundColor Green
    }
    
    Write-Host "`n3. FAILING RULES" -ForegroundColor Yellow
    if ($problematic.HighFailureCount.Count -gt 0) {
        Write-Host "   Found: $($problematic.HighFailureCount.Count) rules" -ForegroundColor Red
        Write-Host "   Solutions:"
        Write-Host "   - Check Kibana logs for specific errors"
        Write-Host "   - Verify rule syntax and field mappings"
        Write-Host "   - Test queries in Dev Tools"
        Write-Host "   - Review connector configurations"
    } else {
        Write-Host "   No issues detected" -ForegroundColor Green
    }
    
    Write-Host "`n4. DISABLED RULES" -ForegroundColor Yellow
    if ($problematic.DisabledRules.Count -gt 0) {
        Write-Host "   Found: $($problematic.DisabledRules.Count) rules" -ForegroundColor Cyan
        Write-Host "   Recommendations:"
        Write-Host "   - Review if these rules should be re-enabled"
        Write-Host "   - Archive rules no longer needed"
        Write-Host "   - Document why rules are disabled"
    }
    
    Write-Host "`n[*] NEXT STEPS:" -ForegroundColor Cyan
    Write-Host "   1. Review failing rules first (highest priority)"
    Write-Host "   2. Optimize slow-running rules to reduce cluster load"
    Write-Host "   3. Consider using rule exceptions to reduce alert volume"
    Write-Host "   4. Monitor rule performance trends weekly"
    
    Write-Host "`n" ("="*100) -ForegroundColor Yellow
    Write-Host " END OF REPORT" -ForegroundColor Yellow
    Write-Host ("="*100) -ForegroundColor Yellow
}

# MAIN
Write-Host "`n[*] Starting Elastic Rule Performance Analysis..." -ForegroundColor Cyan
Write-Host "[*] Target: $KibanaUrl" -ForegroundColor Cyan
Write-Host "[*] Analysis Period: $DaysBack days" -ForegroundColor Cyan
Write-Host "[*] Filters: $(if($IncludeDisabled){'All rules'}else{'Enabled only'}), $(if($IncludeObservability){'All rule types'}else{'Security rules only'})" -ForegroundColor Cyan

# Get all rules
$rules = Get-AllDetectionRules
if (-not $rules -or $rules.Count -eq 0) {
    Write-Host "[!] No detection rules found. Check your Kibana connection and API permissions." -ForegroundColor Red
    exit 1
}

# Check execution data
if ($UseDetailedHistory) {
    Write-Host "[*] Attempting to gather detailed execution history (this may take a while)..." -ForegroundColor Yellow
    $metrics = Get-DetailedRuleMetrics -rules $rules
    
    # If detailed metrics not available, fall back to summary
    if (-not $metrics -or $metrics.Count -eq 0) {
        Write-Host "[!] Detailed execution history not accessible, using last execution summary instead" -ForegroundColor Yellow
        $metrics = Parse-RuleMetricsFromSummary -rules $rules
        $detailedAvailable = $false
    }
    else {
        $detailedAvailable = $true
    }
}
else {
    # Use execution summary (fast approach - recommended for Elastic Cloud)
    Write-Host "[*] Using last execution summary from Detection Rules API (fast mode)..." -ForegroundColor Cyan
    Write-Host "[*] Note: For detailed history, use -UseDetailedHistory flag (slow, only works on-premise)" -ForegroundColor DarkGray
    $metrics = Parse-RuleMetricsFromSummary -rules $rules
    $detailedAvailable = $false
}

Write-Host "[*] Analyzed $($metrics.Count) rules" -ForegroundColor Green

$problematic = Get-ProblematicRules -metrics $metrics

# Display report
Show-PerformanceReport -metrics $metrics -problematic $problematic -detailedAvailable $detailedAvailable

# Generate HTML report
$htmlOutputPath = if ($OutputPath) { 
    $OutputPath 
} else { 
    Join-Path (Get-Location) "KibanaSecurityRulesPerformanceReport.html"
}

Generate-HtmlReport -metrics $metrics -problematic $problematic -detailedAvailable $detailedAvailable -outputPath $htmlOutputPath

# Export to CSV if requested
if ($OutputPath -and $OutputPath -like "*.csv") {
    Write-Host "`n[*] Exporting detailed metrics to CSV: $OutputPath" -ForegroundColor Cyan
    $metrics | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "[+] CSV export complete!" -ForegroundColor Green
}

Write-Host "`n[*] Analysis complete!" -ForegroundColor Green
