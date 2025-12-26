<#
.SYNOPSIS
    Elastic Fleet Agent Distribution Report

.DESCRIPTION
    Analyzes Fleet agents across the deployment and generates a report showing:
    - Agent distribution by client
    - Server vs workstation breakdown
    - Machine details with last check-in times
    - Applied agent policies
    - OS distribution
    - Agent version distribution
    - Agent status distribution
    - Stale agents (not checked in for 7+ days)
    - Client search functionality

.PARAMETER KibanaUrl
    The URL of your Kibana instance

.PARAMETER ApiKey
    API key for authentication

.EXAMPLE
    .\Get-ElasticAgentReport.ps1 -KibanaUrl "https://your-kibana.com" -ApiKey "your-key"

.EXAMPLE
    .\Get-ElasticAgentReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$KibanaUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$ApiKey
)

$headers = @{
    "kbn-xsrf" = "reporting"
    "Authorization" = "ApiKey $ApiKey"
    "Content-Type" = "application/json"
}

# Output path
$scriptDirectory = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDirectory)) {
    $scriptDirectory = Get-Location
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
    
    Write-Host "Calling $Method $fullUrl" -ForegroundColor Gray
    
    try {
        if ($Body) {
            $response = Invoke-RestMethod -Uri $fullUrl -Method $Method -Headers $headers -Body $Body -ContentType "application/json"
        } else {
            $response = Invoke-RestMethod -Uri $fullUrl -Method $Method -Headers $headers
        }
        return $response
    }
    catch {
        Write-Host "Error calling $fullUrl : $_" -ForegroundColor Red
        return $null
    }
}

function Get-NestedProperty {
    param(
        [object]$Object,
        [string]$Path
    )
    
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    
    $parts = $Path -split '\.'
    $current = $Object
    
    foreach ($part in $parts) {
        if ($null -eq $current) {
            return $null
        }
        
        if ($current -is [hashtable]) {
            $current = $current[$part]
        } elseif ($current.PSObject.Properties.Name -contains $part) {
            $current = $current.$part
        } else {
            return $null
        }
    }
    
    return $current
}

function Test-EndpointPolicy {
    param([string]$PolicyName)
    
    # Include patterns for endpoint/computer policies
    $includePatterns = @(
        'windows', 'macos', 'linux', 'endpoint', 'laptop', 'workstation', 
        'desktop', 'computer', 'server', 'edr', 'epp'
    )
    
    # Exclude patterns for non-endpoint policies
    $excludePatterns = @(
        'office', 'o365', 'microsoft 365', 'firewall', 'fortigate', 
        'google workspace', 'gsuite', 'aws', 'azure', 'gcp', 'cloud'
    )
    
    $lowerName = $PolicyName.ToLower()
    
    # Check if it matches exclude patterns
    foreach ($pattern in $excludePatterns) {
        if ($lowerName -match $pattern) {
            return $false
        }
    }
    
    # Check if it matches include patterns
    foreach ($pattern in $includePatterns) {
        if ($lowerName -match $pattern) {
            return $true
        }
    }
    
    return $false
}

function Get-HostName {
    param([object]$Agent)
    
    # Try multiple fields in priority order to get the actual hostname
    $possibleFields = @(
        'local_metadata.host.name',
        'local_metadata.host.hostname',
        'local_metadata.elastic.agent.name',
        'agent.name',
        'host.name',
        'local_metadata.hostname',
        'local_metadata.agent.name'
    )
    
    foreach ($field in $possibleFields) {
        $value = Get-NestedProperty -Object $Agent -Path $field
        
        # Check if we got a valid value (not null, not empty, not a GUID)
        if ($value -and 
            -not [string]::IsNullOrWhiteSpace($value) -and
            $value -notmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
            return $value
        }
    }
    
    # Failover to agent ID
    return $Agent.id
}

function Get-OsInfo {
    param([object]$Agent)
    
    # Get OS
    $osTypeFields = @(
        'local_metadata.os.family',
        'local_metadata.os.platform',
        'local_metadata.os.name',
        'local_metadata.host.os.family',
        'local_metadata.host.os.platform',
        'local_metadata.os.type',
        'local_metadata.host.os.type'
    )
    
    $osType = $null
    foreach ($field in $osTypeFields) {
        $value = Get-NestedProperty -Object $Agent -Path $field
        if ($value -and -not [string]::IsNullOrWhiteSpace($value)) {
            $osType = $value.ToLower()
            break
        }
    }
    
    $osVersionFields = @(
        'local_metadata.os.full',
        'local_metadata.os.name',
        'local_metadata.os.version',
        'local_metadata.host.os.full',
        'local_metadata.host.os.name',
        'local_metadata.host.os.version'
    )
    
    $osVersion = $null
    foreach ($field in $osVersionFields) {
        $value = Get-NestedProperty -Object $Agent -Path $field
        if ($value -and -not [string]::IsNullOrWhiteSpace($value)) {
            $osVersion = $value
            break
        }
    }
    
    return @{
        Type = if ($osType) { $osType } else { "unknown" }
        Version = if ($osVersion) { $osVersion } else { "Unknown" }
    }
}

function Get-MachineType {
    param(
        [string]$PolicyName,
        [string]$OsType,
        [string]$HostName
    )
    
    $lowerPolicy = $PolicyName.ToLower()
    $lowerHost = $HostName.ToLower()
    
    if ($lowerPolicy -match 'server') {
        return 'Server'
    }
    
    if ($lowerHost -match 'srv|server|dc\d+|sql|exch|ad\d+') {
        return 'Server'
    }
    
    if ($OsType -eq 'windows') {
        # Default Windows to workstation unless identified as server
        return 'Workstation'
    }
    
    if ($OsType -eq 'macos') {
        return 'Workstation'
    }
    
    if ($OsType -eq 'linux') {
        if ($lowerPolicy -match 'desktop|laptop|workstation') {
            return 'Workstation'
        }
        return 'Server'
    }
    
    return 'Workstation'
}

function Get-ClientName {
    param(
        [object]$Agent,
        [hashtable]$PolicyDetails
    )
    
    $clientFields = @(
        'local_metadata.ame.client',
        'local_metadata.ame.q360.customer_name',
        'ame.client',
        'ame.q360.customer_name'
    )
    
    foreach ($field in $clientFields) {
        $value = Get-NestedProperty -Object $Agent -Path $field
        if ($value -and -not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }
    
    # Try policy namespace
    if ($Agent.policy_id -and $PolicyDetails.ContainsKey($Agent.policy_id)) {
        $policy = $PolicyDetails[$Agent.policy_id]
        if ($policy.namespace -and $policy.namespace -ne 'default') {
            return $policy.namespace
        }
    }

    return "Unknown"
}

function Get-LastCheckinTime {
    param([string]$LastCheckin)
    
    if ([string]::IsNullOrWhiteSpace($LastCheckin)) {
        return "Never"
    }
    
    try {
        # ISO 8601 datetime
        $checkinDate = [DateTime]::Parse($LastCheckin, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $timeAgo = (Get-Date).ToUniversalTime() - $checkinDate.ToUniversalTime()
        
        if ($timeAgo.TotalMinutes -lt 1) {
            return "Just now"
        } elseif ($timeAgo.TotalMinutes -lt 60) {
            return "$([Math]::Floor($timeAgo.TotalMinutes)) min ago"
        } elseif ($timeAgo.TotalHours -lt 24) {
            return "$([Math]::Floor($timeAgo.TotalHours)) hours ago"
        } else {
            return "$([Math]::Floor($timeAgo.TotalDays)) days ago"
        }
    } catch {
        # If parsing fails, return the raw value
        return $LastCheckin
    }
}

function Get-DaysSinceCheckin {
    param([string]$LastCheckin)
    
    if ([string]::IsNullOrWhiteSpace($LastCheckin)) {
        return 9999
    }
    
    try {
        $checkinDate = [DateTime]::Parse($LastCheckin, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $timeAgo = (Get-Date).ToUniversalTime() - $checkinDate.ToUniversalTime()
        return [Math]::Floor($timeAgo.TotalDays)
    } catch {
        return 9999
    }
}

Write-Host "`n=== ELASTIC FLEET AGENT REPORT ===" -ForegroundColor Cyan
Write-Host "Analyzing Fleet agents across deployment..." -ForegroundColor Cyan

# Get all agent policies
Write-Host "`nFetching agent policies..." -ForegroundColor Yellow
$policiesResponse = Invoke-KibanaApi -Endpoint "/api/fleet/agent_policies?perPage=1000"

$policyDetails = @{}
$endpointPolicies = @()

if ($policiesResponse -and $policiesResponse.items) {
    Write-Host "Found $($policiesResponse.items.Count) policies" -ForegroundColor Green
    
    foreach ($policy in $policiesResponse.items) {
        $policyDetails[$policy.id] = $policy
        
        if (Test-EndpointPolicy -PolicyName $policy.name) {
            $endpointPolicies += $policy.id
            Write-Host "  ✓ Endpoint policy: $($policy.name)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "Failed to retrieve policies" -ForegroundColor Red
    exit 1
}

Write-Host "`nIdentified $($endpointPolicies.Count) endpoint policies" -ForegroundColor Cyan

# Get all agents
Write-Host "`nFetching all Fleet agents..." -ForegroundColor Yellow
$allAgents = @()
$page = 1
$perPage = 1000

do {
    $agentsResponse = Invoke-KibanaApi -Endpoint "/api/fleet/agents?page=$page&perPage=$perPage&showInactive=false"
    
    if ($agentsResponse -and $agentsResponse.items) {
        $allAgents += $agentsResponse.items
        Write-Host "  Retrieved page $page ($($agentsResponse.items.Count) agents)" -ForegroundColor Gray
        $page++
    } else {
        break
    }
    
    if ($agentsResponse.total -le ($allAgents.Count)) {
        break
    }
    
} while ($true)

Write-Host "Total agents retrieved: $($allAgents.Count)" -ForegroundColor Green

# Filter to only endpoint agents
Write-Host "`nFiltering to endpoint agents only..." -ForegroundColor Yellow
$endpointAgents = $allAgents | Where-Object { $endpointPolicies -contains $_.policy_id }

Write-Host "Endpoint agents: $($endpointAgents.Count)" -ForegroundColor Green

# Setup distribution counts
$osDistribution = @{}
$versionDistribution = @{}
$statusDistribution = @{}
$staleAgents = @()

# Group by client
Write-Host "`nGrouping agents by client..." -ForegroundColor Yellow
$clientGroups = @{}

foreach ($agent in $endpointAgents) {
    $clientName = Get-ClientName -Agent $agent -PolicyDetails $policyDetails
    
    if (-not $clientGroups.ContainsKey($clientName)) {
        $clientGroups[$clientName] = @{
            Name = $clientName
            Agents = @()
            Servers = @()
            Workstations = @()
        }
    }

    $policyName = if ($agent.policy_id -and $policyDetails.ContainsKey($agent.policy_id)) {
        $policyDetails[$agent.policy_id].name
    } else {
        "Unknown Policy"
    }

    $osInfo = Get-OsInfo -Agent $agent

    $hostName = Get-HostName -Agent $agent
    
    $machineType = Get-MachineType -PolicyName $policyName -OsType $osInfo.Type -HostName $hostName
    
    $agentVersion = if ($agent.agent -and $agent.agent.version) { $agent.agent.version } else { "Unknown" }
    
    $daysSinceCheckin = Get-DaysSinceCheckin -LastCheckin $agent.last_checkin
    
    $agentInfo = [PSCustomObject]@{
        HostName = $hostName
        Status = $agent.status
        LastCheckIn = Get-LastCheckinTime -LastCheckin $agent.last_checkin
        LastCheckInRaw = $agent.last_checkin
        DaysSinceCheckin = $daysSinceCheckin
        PolicyName = $policyName
        PolicyId = $agent.policy_id
        OsType = $osInfo.Type
        OsVersion = $osInfo.Version
        OsFull = "$($osInfo.Type) - $($osInfo.Version)"
        AgentVersion = $agentVersion
        MachineType = $machineType
        AgentId = $agent.id
        ClientName = $clientName
    }
    
    $clientGroups[$clientName].Agents += $agentInfo
    
    if ($machineType -eq 'Server') {
        $clientGroups[$clientName].Servers += $agentInfo
    } else {
        $clientGroups[$clientName].Workstations += $agentInfo
    }
    
    $osKey = $osInfo.Type
    if (-not $osDistribution.ContainsKey($osKey)) {
        $osDistribution[$osKey] = 0
    }
    $osDistribution[$osKey]++

    if (-not $versionDistribution.ContainsKey($agentVersion)) {
        $versionDistribution[$agentVersion] = 0
    }
    $versionDistribution[$agentVersion]++
    
    # Track status distribution
    $agentStatus = $agent.status
    if (-not $statusDistribution.ContainsKey($agentStatus)) {
        $statusDistribution[$agentStatus] = 0
    }
    $statusDistribution[$agentStatus]++
    
    # Track stale agents (haven't checked in for 7+ days)
    if ($daysSinceCheckin -ge 7) {
        $staleAgents += $agentInfo
    }
}

Write-Host "Found $($clientGroups.Count) unique clients" -ForegroundColor Green
Write-Host "Found $($staleAgents.Count) stale agents (7+ days since last check-in)" -ForegroundColor Yellow

# HTML generation
Write-Host "`nGenerating HTML report..." -ForegroundColor Yellow

$reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$totalAgents = $endpointAgents.Count
$totalServers = ($clientGroups.Values | ForEach-Object { $_.Servers.Count } | Measure-Object -Sum).Sum
$totalWorkstations = ($clientGroups.Values | ForEach-Object { $_.Workstations.Count } | Measure-Object -Sum).Sum

# OS distribution data 
$osDistSorted = $osDistribution.GetEnumerator() | Sort-Object Value -Descending
$osLabels = ($osDistSorted | ForEach-Object { "'$($_.Key)'" }) -join ","
$osValues = ($osDistSorted | ForEach-Object { $_.Value }) -join ","

# version distribution data
$versionDistSorted = $versionDistribution.GetEnumerator() | Sort-Object Value -Descending
$versionLabels = ($versionDistSorted | ForEach-Object { "'$($_.Key)'" }) -join ","
$versionValues = ($versionDistSorted | ForEach-Object { $_.Value }) -join ","

# status distribution data
$statusDistSorted = $statusDistribution.GetEnumerator() | Sort-Object Value -Descending
$statusLabels = ($statusDistSorted | ForEach-Object { "'$($_.Key)'" }) -join ","
$statusValues = ($statusDistSorted | ForEach-Object { $_.Value }) -join ","

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Elastic Fleet Agent Distribution Report - $reportDate</title>
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
        
        .summary-card.warning .value {
            color: #dc2626;
        }
        
        .content {
            padding: 40px;
        }
        
        .distribution-section {
            background: #f8fafc;
            padding: 40px;
            margin-bottom: 20px;
        }
        
        .distribution-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        
        .chart-card {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .chart-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: #1e293b;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .section-title {
            font-size: 2rem;
            color: #005571;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #e2e8f0;
        }
        
        .search-container {
            margin-bottom: 30px;
            position: relative;
        }
        
        .search-box {
            width: 100%;
            padding: 15px 20px;
            font-size: 1.1rem;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            outline: none;
            transition: all 0.3s ease;
            background: white;
        }
        
        .search-box:focus {
            border-color: #009eb4;
            box-shadow: 0 0 0 3px rgba(0, 158, 180, 0.1);
        }
        
        .search-results {
            margin-top: 10px;
            font-size: 0.9rem;
            color: #64748b;
        }
        
        .client-section.hidden {
            display: none;
        }
        
        .highlight {
            background-color: #fef3c7;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: 600;
        }
        
        .client-section {
            margin-bottom: 30px;
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .client-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 25px 30px;
            background: #f8fafc;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        
        .client-header:hover {
            background: #f1f5f9;
        }
        
        .client-header-left {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .expand-icon {
            font-size: 1.5rem;
            color: #64748b;
            transition: transform 0.3s ease;
            width: 30px;
            text-align: center;
        }
        
        .client-section.expanded .expand-icon {
            transform: rotate(90deg);
        }
        
        .client-name {
            font-size: 1.8rem;
            font-weight: 700;
            color: #1e293b;
        }
        
        .client-stats {
            display: flex;
            gap: 20px;
        }
        
        .stat-badge {
            background: white;
            padding: 10px 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .stat-badge .count {
            font-size: 1.5rem;
            font-weight: 700;
            color: #009eb4;
        }
        
        .stat-badge .label {
            font-size: 0.85rem;
            color: #64748b;
            text-transform: uppercase;
        }
        
        .server-badge .count {
            color: #dc2626;
        }
        
        .workstation-badge .count {
            color: #16a34a;
        }
        
        .client-details {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.5s ease;
        }
        
        .client-section.expanded .client-details {
            max-height: 10000px;
        }
        
        .agent-table-wrapper {
            padding: 0 30px 30px 30px;
        }
        
        .agent-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }
        
        .agent-table th {
            background: #005571;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
        }
        
        .agent-table td {
            padding: 15px;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .agent-table tr:hover {
            background: #f8fafc;
        }
        
        .agent-table tr:last-child td {
            border-bottom: none;
        }
        
        .status-online {
            background: #dcfce7;
            color: #166534;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .status-offline {
            background: #fee2e2;
            color: #991b1b;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .status-updating {
            background: #fef3c7;
            color: #92400e;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .status-unenrolled, .status-orphaned {
            background: #fecaca;
            color: #7f1d1d;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .type-server {
            background: #fef2f2;
            color: #991b1b;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .type-workstation {
            background: #f0fdf4;
            color: #166534;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .last-checkin {
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            color: #475569;
        }
        
        .last-checkin-stale {
            color: #dc2626;
            font-weight: 700;
        }
        
        .policy-name {
            color: #1e40af;
            font-weight: 500;
        }
        
        .stale-warning {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .stale-warning h3 {
            color: #92400e;
            margin-bottom: 10px;
        }
        
        .footer {
            background: #f1f5f9;
            padding: 30px;
            text-align: center;
            color: #64748b;
            border-top: 1px solid #e2e8f0;
        }
        
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .distribution-grid {
                grid-template-columns: 1fr;
            }
            
            .client-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }
            
            .agent-table {
                font-size: 0.85rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ Elastic Fleet Agent Distribution Report</h1>
            <p>Generated on $reportDate</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="icon">🏢</div>
                <div class="value">$($clientGroups.Count)</div>
                <div class="label">Total Clients</div>
            </div>
            <div class="summary-card">
                <div class="icon">💻</div>
                <div class="value">$totalAgents</div>
                <div class="label">Total Agents</div>
            </div>
            <div class="summary-card">
                <div class="icon">🖥️</div>
                <div class="value">$totalServers</div>
                <div class="label">Servers</div>
            </div>
            <div class="summary-card">
                <div class="icon">💼</div>
                <div class="value">$totalWorkstations</div>
                <div class="label">Workstations</div>
            </div>
            <div class="summary-card warning">
                <div class="icon">⚠️</div>
                <div class="value">$($staleAgents.Count)</div>
                <div class="label">Stale Agents (7+ Days)</div>
            </div>
        </div>
        
        <div class="distribution-section">
            <h2 class="section-title">📊 Distribution Analytics</h2>
            <div class="distribution-grid">
                <div class="chart-card">
                    <h3 class="chart-title">Operating System Distribution</h3>
                    <canvas id="osChart"></canvas>
                </div>
                <div class="chart-card">
                    <h3 class="chart-title">Agent Version Distribution</h3>
                    <canvas id="versionChart"></canvas>
                </div>
                <div class="chart-card">
                    <h3 class="chart-title">Agent Status Distribution</h3>
                    <canvas id="statusChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="content">
"@

# Stale agent info if present
if ($staleAgents.Count -gt 0) {
    $htmlReport += @"
            <div class="client-section expanded" id="stale-agents">
                <div class="client-header" onclick="toggleClient('stale-agents')">
                    <div class="client-header-left">
                        <div class="expand-icon">▶</div>
                        <div class="client-name">⚠️ Stale Agents (Not Checked In for 7+ Days)</div>
                    </div>
                    <div class="client-stats">
                        <div class="stat-badge warning">
                            <div class="count">$($staleAgents.Count)</div>
                            <div class="label">Stale Agents</div>
                        </div>
                    </div>
                </div>
                
                <div class="client-details">
                    <div class="stale-warning">
                        <h3>🚨 Action Required</h3>
                        <p>These agents have not checked in for 7 or more days. They may be offline, decommissioned, or experiencing connectivity issues.</p>
                    </div>
                    <div class="agent-table-wrapper">
                        <table class="agent-table">
                            <thead>
                                <tr>
                                    <th>Hostname</th>
                                    <th>Client</th>
                                    <th>Type</th>
                                    <th>Status</th>
                                    <th>OS</th>
                                    <th>Last Check-In</th>
                                    <th>Days Since Check-In</th>
                                    <th>Policy</th>
                                </tr>
                            </thead>
                            <tbody>
"@
    
    foreach ($agent in ($staleAgents | Sort-Object DaysSinceCheckin -Descending)) {
        $statusClass = switch ($agent.Status) {
            "online" { "status-online" }
            "offline" { "status-offline" }
            "updating" { "status-updating" }
            "unenrolled" { "status-unenrolled" }
            "orphaned" { "status-orphaned" }
            default { "status-offline" }
        }
        
        $typeClass = if ($agent.MachineType -eq 'Server') { "type-server" } else { "type-workstation" }
        $osDisplay = "$($agent.OsType) - $($agent.OsVersion)"
        
        $htmlReport += @"
                                <tr>
                                    <td><strong>$($agent.HostName)</strong></td>
                                    <td>$($agent.ClientName)</td>
                                    <td><span class="$typeClass">$($agent.MachineType)</span></td>
                                    <td><span class="$statusClass">$($agent.Status)</span></td>
                                    <td>$osDisplay</td>
                                    <td class="last-checkin last-checkin-stale">$($agent.LastCheckIn)</td>
                                    <td class="last-checkin-stale">$($agent.DaysSinceCheckin) days</td>
                                    <td class="policy-name">$($agent.PolicyName)</td>
                                </tr>
"@
    }
    
    $htmlReport += @"
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
"@
}

$htmlReport += @"
            <h2 class="section-title">👥 Agents by Client</h2>
            
            <div class="search-container">
                <input type="text" id="clientSearch" class="search-box" placeholder="🔍 Search for a client..." onkeyup="filterClients()">
                <div class="search-results" id="searchResults"></div>
            </div>
"@

# Alphabetize clients
$sortedClients = $clientGroups.Values | Sort-Object Name

foreach ($client in $sortedClients) {
    # Create a safe ID for this client
    $clientId = ($client.Name -replace '[^a-zA-Z0-9]', '_').ToLower()
    
    $htmlReport += @"
            <div class="client-section" id="client-$clientId">
                <div class="client-header" onclick="toggleClient('client-$clientId')">
                    <div class="client-header-left">
                        <div class="expand-icon">▶</div>
                        <div class="client-name">$($client.Name)</div>
                    </div>
                    <div class="client-stats">
                        <div class="stat-badge">
                            <div class="count">$($client.Agents.Count)</div>
                            <div class="label">Total</div>
                        </div>
                        <div class="stat-badge server-badge">
                            <div class="count">$($client.Servers.Count)</div>
                            <div class="label">Servers</div>
                        </div>
                        <div class="stat-badge workstation-badge">
                            <div class="count">$($client.Workstations.Count)</div>
                            <div class="label">Workstations</div>
                        </div>
                    </div>
                </div>
                
                <div class="client-details">
                    <div class="agent-table-wrapper">
                        <table class="agent-table">
                            <thead>
                                <tr>
                                    <th>Hostname</th>
                                    <th>Type</th>
                                    <th>Status</th>
                                    <th>OS</th>
                                    <th>Last Check-In</th>
                                    <th>Policy</th>
                                    <th>Agent Version</th>
                                </tr>
                            </thead>
                            <tbody>
"@
    
    # Sort by hostname
    $sortedAgents = $client.Agents | Sort-Object HostName
    
    foreach ($agent in $sortedAgents) {
        $statusClass = switch ($agent.Status) {
            "online" { "status-online" }
            "offline" { "status-offline" }
            "updating" { "status-updating" }
            "unenrolled" { "status-unenrolled" }
            "orphaned" { "status-orphaned" }
            default { "status-offline" }
        }
        
        $typeClass = if ($agent.MachineType -eq 'Server') { "type-server" } else { "type-workstation" }
        $osDisplay = "$($agent.OsType) - $($agent.OsVersion)"
        $checkinClass = if ($agent.DaysSinceCheckin -ge 7) { "last-checkin last-checkin-stale" } else { "last-checkin" }
        
        $htmlReport += @"
                                <tr>
                                    <td><strong>$($agent.HostName)</strong></td>
                                    <td><span class="$typeClass">$($agent.MachineType)</span></td>
                                    <td><span class="$statusClass">$($agent.Status)</span></td>
                                    <td>$osDisplay</td>
                                    <td class="$checkinClass">$($agent.LastCheckIn)</td>
                                    <td class="policy-name">$($agent.PolicyName)</td>
                                    <td>$($agent.AgentVersion)</td>
                                </tr>
"@
    }
    
    $htmlReport += @"
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
"@
}

$htmlReport += @"
        </div>
        
        <div class="footer">
            <p><strong>Report Information</strong></p>
            <p>Generated from: $KibanaUrl</p>
            <p>Total endpoint policies analyzed: $($endpointPolicies.Count)</p>
            <p>Excluded non-endpoint policies (O365, Firewalls, Cloud integrations)</p>
            <p style="margin-top: 10px; font-size: 0.9rem; color: #94a3b8;">💡 Click on any client to expand/collapse their agent list</p>
        </div>
    </div>
    
    <script>
        function toggleClient(clientId) {
            const section = document.getElementById(clientId);
            section.classList.toggle('expanded');
        }
        
        function filterClients() {
            const searchTerm = document.getElementById('clientSearch').value.toLowerCase();
            const clientSections = document.querySelectorAll('[id^="client-"]');
            let visibleCount = 0;
            let totalCount = 0;
            
            clientSections.forEach(section => {
                // Skip the stale-agents section
                if (section.id === 'stale-agents') {
                    return;
                }
                
                totalCount++;
                
                const nameElement = section.querySelector('.client-name');
                const originalText = nameElement.getAttribute('data-original-text') || nameElement.textContent;
                
                // Store original text if not already stored
                if (!nameElement.getAttribute('data-original-text')) {
                    nameElement.setAttribute('data-original-text', originalText);
                }
                
                const clientName = originalText.toLowerCase();
                
                if (clientName.includes(searchTerm)) {
                    section.classList.remove('hidden');
                    visibleCount++;
                    
                    // Highlight matching text
                    if (searchTerm && searchTerm.length > 0) {
                        const regex = new RegExp('(' + searchTerm.replace(/[.*+?^`${}()|[\]\\]/g, '\\`$&') + ')', 'gi');
                        nameElement.innerHTML = originalText.replace(regex, '<span class="highlight">`$1</span>');
                    } else {
                        nameElement.textContent = originalText;
                    }
                } else {
                    section.classList.add('hidden');
                    nameElement.textContent = originalText;
                }
            });
            
            // Update search results
            const resultsDiv = document.getElementById('searchResults');
            if (searchTerm) {
                resultsDiv.textContent = 'Showing ' + visibleCount + ' of ' + totalCount + ' clients';
            } else {
                resultsDiv.textContent = '';
            }
        }
        
        // OS Distribution Chart
        const osCtx = document.getElementById('osChart').getContext('2d');
        new Chart(osCtx, {
            type: 'doughnut',
            data: {
                labels: [$osLabels],
                datasets: [{
                    data: [$osValues],
                    backgroundColor: [
                        '#3b82f6',
                        '#10b981',
                        '#f59e0b',
                        '#ef4444',
                        '#8b5cf6',
                        '#ec4899'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Agent Version Distribution Chart
        const versionCtx = document.getElementById('versionChart').getContext('2d');
        new Chart(versionCtx, {
            type: 'bar',
            data: {
                labels: [$versionLabels],
                datasets: [{
                    label: 'Agent Count',
                    data: [$versionValues],
                    backgroundColor: 'rgba(0, 158, 180, 0.8)',
                    borderColor: 'rgb(0, 158, 180)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
        
        // Agent Status Distribution Chart
        const statusCtx = document.getElementById('statusChart').getContext('2d');
        new Chart(statusCtx, {
            type: 'doughnut',
            data: {
                labels: [$statusLabels],
                datasets: [{
                    data: [$statusValues],
                    backgroundColor: [
                        '#22c55e',  // green for online
                        '#ef4444',  // red for offline
                        '#f59e0b',  // yellow for updating
                        '#dc2626',  // dark red for orphaned
                        '#7c3aed',  // purple for unenrolled
                        '#64748b'   // gray for other
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

# Save report
$reportPath = Join-Path -Path $scriptDirectory -ChildPath "ElasticAgentReport.html"
$htmlReport | Out-File -FilePath $reportPath -Encoding UTF8 -Force

Write-Host "`n=== REPORT GENERATED SUCCESSFULLY ===" -ForegroundColor Green
Write-Host "Report saved to: $reportPath" -ForegroundColor Green

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Clients: $($clientGroups.Count)" -ForegroundColor White
Write-Host "Total Endpoint Agents: $totalAgents" -ForegroundColor White
Write-Host "  Servers: $totalServers" -ForegroundColor Red
Write-Host "  Workstations: $totalWorkstations" -ForegroundColor Green
Write-Host "  Stale Agents (7+ days): $($staleAgents.Count)" -ForegroundColor Yellow

Write-Host "`nOS Distribution:" -ForegroundColor Cyan
foreach ($os in $osDistSorted) {
    Write-Host "  $($os.Key): $($os.Value)" -ForegroundColor White
}

Write-Host "`nAgent Version Distribution:" -ForegroundColor Cyan
foreach ($version in $versionDistSorted) {
    Write-Host "  $($version.Key): $($version.Value)" -ForegroundColor White
}

Write-Host "`nAgent Status Distribution:" -ForegroundColor Cyan
foreach ($status in $statusDistSorted) {
    $color = switch ($status.Key) {
        "online" { "Green" }
        "offline" { "Red" }
        "orphaned" { "Red" }
        "updating" { "Yellow" }
        default { "White" }
    }
    Write-Host "  $($status.Key): $($status.Value)" -ForegroundColor $color
}
