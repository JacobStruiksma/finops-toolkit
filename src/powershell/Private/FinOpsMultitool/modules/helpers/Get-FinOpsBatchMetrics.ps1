# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-FinOpsBatchMetrics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resources,
        [Parameter(Mandatory)][string]$ArmEndpoint,
        [Parameter(Mandatory)][string]$MetricNamespace,
        [Parameter(Mandatory)][string[]]$MetricNames,
        [Parameter(Mandatory)][string[]]$Aggregation,
        [Parameter(Mandatory)][string]$StartTime,
        [Parameter(Mandatory)][string]$EndTime,
        [Parameter(Mandatory)][ValidateSet('VM', 'Storage')][string]$Label
    )

    $metrics = @{}
    $errors = @{}
    $result = @{ Metrics = $metrics; Errors = $errors }
    $fallback = if ($Label -eq 'VM') { 'per-VM requests' } else { 'per-account requests' }
    $groups = @($Resources | Group-Object subscriptionId, location | Where-Object { $_.Count -gt 1 -and $_.Group[0].location -match '^[a-z0-9]+$' })
    if ($ArmEndpoint.TrimEnd('/') -ne 'https://management.azure.com' -or $groups.Count -eq 0) {
        Write-Verbose "$Label metrics: using $fallback (no eligible batches or batch endpoint unavailable)"
        return $result
    }

    try {
        $token = Get-PlainAccessToken -ResourceUrl 'https://metrics.monitor.azure.com/'
        if ([string]::IsNullOrWhiteSpace($token)) { throw 'No Metrics access token was returned.' }
        $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
    }
    catch {
        Write-Warning "$Label metrics batching is unavailable: $($_.Exception.Message) Using $fallback."
        return $result
    }

    $batchCount = ($groups | ForEach-Object { [math]::Ceiling($_.Count / 50) } | Measure-Object -Sum).Sum
    $batchIndex = 0
    $namespace = [uri]::EscapeDataString($MetricNamespace)
    $names = [uri]::EscapeDataString($MetricNames -join ',')
    $aggregations = $Aggregation -join ','
    foreach ($group in $groups) {
        $region = $group.Group[0].location
        $subscriptionId = $group.Group[0].subscriptionId
        for ($offset = 0; $offset -lt $group.Count; $offset += 50) {
            $batchIndex++
            $resourceIds = @($group.Group | Select-Object -Skip $offset -First 50 | ForEach-Object { $_.Id })
            $context = "$Label metrics batch [$batchIndex/$batchCount] for subscription $subscriptionId in $region ($($resourceIds.Count) resources)"
            Write-Verbose "${context}: requesting $($MetricNames -join ', ') from $StartTime to $EndTime"
            if (Get-Command Update-ScanStatus -ErrorAction SilentlyContinue) { Update-ScanStatus $context }
            try {
                $uri = "https://$region.metrics.monitor.azure.com/subscriptions/$subscriptionId/metrics:getBatch?api-version=2023-10-01&metricnamespace=$namespace&metricnames=$names&starttime=$StartTime&endtime=$EndTime&aggregation=$aggregations&interval=FULL"
                $body = @{ resourceids = $resourceIds } | ConvertTo-Json -Compress
                $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post -Body $body -UseBasicParsing -TimeoutSec 60 -MaximumRedirection 0 -ErrorAction Stop
                $payload = $response.Content | ConvertFrom-Json -ErrorAction Stop
                if ($payload.values -isnot [array]) { throw 'The batch response is missing its values array.' }
                $returned = @{}
                foreach ($item in $payload.values) {
                    $id = [string]$item.resourceid
                    if ($id -notin $resourceIds -or $returned.ContainsKey($id)) { throw 'The batch response contains an unexpected or duplicate resource ID.' }
                    $returned[$id] = $item
                }
                foreach ($id in $resourceIds) {
                    $item = $returned[$id]
                    if (-not $item) { $errors[$id] = 'The metrics batch omitted this resource.' }
                    elseif ($item.errorCode -and $item.errorCode -ne 'Success') { $errors[$id] = "Metrics batch returned $($item.errorCode): $($item.errorMessage)" }
                    else { $metrics[$id] = $item }
                }
                Write-Verbose "${context}: received $($returned.Count) resource responses"
            }
            catch {
                if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 429) {
                    foreach ($id in $resourceIds) { $errors[$id] = 'Metrics batch was rate limited (HTTP 429); the resource was not evaluated.' }
                    Write-Warning "${context}: rate limited; these resources were not evaluated."
                }
                else {
                    Write-Warning "${context}: $($_.Exception.Message) Falling back to $fallback for this batch."
                }
            }
        }
    }
    return $result
}
