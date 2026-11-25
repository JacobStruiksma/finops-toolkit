# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console tool; the formatted console output is the user interface.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Private helper named for the collection it processes.')]
param()

###########################################################################
# GET-ORPHANEDRESOURCES.PS1
# AZURE FINOPS MULTITOOL - Orphaned & Idle Resource Detection
###########################################################################
# Purpose: Use Azure Resource Graph to find resources that are costing
#          money but serving no purpose: orphaned disks, unattached IPs,
#          empty App Service Plans, unattached NICs, and stopped VMs
#          that are still incurring compute charges.
###########################################################################

function Get-OrphanedResources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Subscriptions,

        [Parameter()]
        [switch]$SkipCost,

        [Parameter()]
        [hashtable]$HubProvider
    )

    Write-Host "  Scanning for orphaned and idle resources..." -ForegroundColor Cyan

    $subIds = $Subscriptions | ForEach-Object { $_.Id }
    $allOrphans = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -- 1: Orphaned Managed Disks (no ownerVM) --------------------------
    try {
        $diskQuery = @"
resources
| where type =~ 'microsoft.compute/disks'
| where managedBy == '' or isnull(managedBy)
| where properties.diskState == 'Unattached'
| project id, name, resourceGroup, subscriptionId, location,
          diskSizeGb = properties.diskSizeGB,
          sku = sku.name, diskState = properties.diskState,
          type = 'Orphaned Disk'
"@
        $result = Search-AzGraphSafe -Query $diskQuery -Subscription $subIds -First 1000 -All
        $rows = if ($result) { @($result.Data) } else { @() }
        foreach ($r in $rows) {
            [void]$allOrphans.Add([PSCustomObject]@{
                    Category       = 'Orphaned Disk'
                    ResourceId     = $r.id
                    ResourceName   = $r.name
                    ResourceGroup  = $r.resourceGroup
                    SubscriptionId = $r.subscriptionId
                    Location       = $r.location
                    Detail         = "$($r.diskSizeGb) GB ($($r.sku))"
                    Impact         = 'Medium'
                })
        }
        Write-Host "    Orphaned disks: $($rows.Count)" -ForegroundColor Gray
    }
    catch {
        throw "Orphaned disk inventory is incomplete: $($_.Exception.Message)"
    }

    # -- 2: Idle Public IPs ------------------------------------------------
    # Two distinct cases with different remediation: an IP attached to nothing,
    # and an IP still reserved by a stopped VM. Both bill; only the first is
    # safe to simply delete.
    try {
        $pipQuery = @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| extend ipConfigId = tolower(tostring(properties.ipConfiguration.id))
| extend natGw = tostring(properties.natGateway.id)
| project id, name, resourceGroup, subscriptionId, location,
          sku = tostring(sku.name),
          allocationMethod = tostring(properties.publicIPAllocationMethod),
          ipAddress = tostring(properties.ipAddress),
          ipConfigId, natGw
| join kind=leftouter (
    resources
    | where type =~ 'microsoft.network/networkinterfaces'
    | mv-expand ipc = properties.ipConfigurations limit 256
    | project nicName = name,
              nicVmId = tolower(tostring(properties.virtualMachine.id)),
              ipConfigId = tolower(tostring(ipc.id))
  ) on ipConfigId
| join kind=leftouter (
    resources
    | where type =~ 'microsoft.compute/virtualmachines'
    | project nicVmId = tolower(tostring(id)), vmName = name,
              vmPower = tostring(properties.extended.instanceView.powerState.displayStatus)
  ) on nicVmId
| project id, name, resourceGroup, subscriptionId, location, sku, allocationMethod,
          ipAddress, ipConfigId, natGw, nicName, vmName, vmPower
"@
        $result = Search-AzGraphSafe -Query $pipQuery -Subscription $subIds -First 1000 -All
        $rows = if ($result) { @($result.Data) } else { @() }
        $pipUnattached = 0
        $pipStoppedVm = 0
        foreach ($r in $rows) {
            $addr = if ($r.ipAddress) { $r.ipAddress } else { 'no address' }
            $held = if ($r.allocationMethod -eq 'Static') { 'address is reserved' } else { 'address is dynamic' }
            $isStoppedVm = ($r.vmName -and $r.vmPower -and $r.vmPower -notmatch '(?i)running')
            $isUnattached = ([string]::IsNullOrWhiteSpace([string]$r.ipConfigId) -and [string]::IsNullOrWhiteSpace([string]$r.natGw))

            if ($isStoppedVm) {
                $category = 'Public IP on stopped VM'
                $detail = "$($r.sku)/$($r.allocationMethod) $addr - held by stopped VM $($r.vmName), $held"
                $pipStoppedVm++
            }
            elseif ($isUnattached) {
                $category = 'Unattached Public IP'
                $detail = "$($r.sku)/$($r.allocationMethod) $addr - attached to nothing, $held"
                $pipUnattached++
            }
            else {
                # In use by a load balancer, gateway, Bastion, firewall or running VM.
                continue
            }

            [void]$allOrphans.Add([PSCustomObject]@{
                    Category       = $category
                    ResourceId     = $r.id
                    ResourceName   = $r.name
                    ResourceGroup  = $r.resourceGroup
                    SubscriptionId = $r.subscriptionId
                    Location       = $r.location
                    IpAddress      = $r.ipAddress
                    AttachedTo     = if ($isStoppedVm) { $r.vmName } else { $null }
                    Detail         = $detail
                    Impact         = if ($r.sku -eq 'Standard') { 'Medium' } else { 'Low' }
                })
        }
        Write-Host "    Unattached public IPs: $pipUnattached" -ForegroundColor Gray
        Write-Host "    Public IPs on stopped VMs: $pipStoppedVm" -ForegroundColor Gray
    }
    catch {
        throw "Public IP inventory is incomplete: $($_.Exception.Message)"
    }

    # -- 3: Unattached NICs -----------------------------------------------
    try {
        $nicQuery = @"
resources
| where type =~ 'microsoft.network/networkinterfaces'
| where isnull(properties.virtualMachine) or properties.virtualMachine == ''
| where isnull(properties.privateEndpoint) or properties.privateEndpoint == ''
| project id, name, resourceGroup, subscriptionId, location,
          enableAcceleratedNetworking = properties.enableAcceleratedNetworking,
          type = 'Unattached NIC'
"@
        $result = Search-AzGraphSafe -Query $nicQuery -Subscription $subIds -First 1000 -All
        $rows = if ($result) { @($result.Data) } else { @() }
        foreach ($r in $rows) {
            [void]$allOrphans.Add([PSCustomObject]@{
                    Category       = 'Unattached NIC'
                    ResourceId     = $r.id
                    ResourceName   = $r.name
                    ResourceGroup  = $r.resourceGroup
                    SubscriptionId = $r.subscriptionId
                    Location       = $r.location
                    Detail         = "Accelerated: $($r.enableAcceleratedNetworking)"
                    Impact         = 'Low'
                })
        }
        Write-Host "    Unattached NICs: $($rows.Count)" -ForegroundColor Gray
    }
    catch {
        throw "NIC inventory is incomplete: $($_.Exception.Message)"
    }

    # -- 4: Stopped (deallocated) VMs still on disk -----------------------
    try {
        $vmQuery = @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where properties.extended.instanceView.powerState.displayStatus == 'VM deallocated'
    or properties.extended.instanceView.powerState.code == 'PowerState/deallocated'
| project id, name, resourceGroup, subscriptionId, location,
          vmSize = properties.hardwareProfile.vmSize,
          powerState = properties.extended.instanceView.powerState.displayStatus,
          osDiskId = tostring(properties.storageProfile.osDisk.managedDisk.id),
          dataDisks = properties.storageProfile.dataDisks,
          type = 'Deallocated VM'
"@
        $result = Search-AzGraphSafe -Query $vmQuery -Subscription $subIds -First 1000 -All
        $rows = if ($result) { @($result.Data) } else { @() }
        foreach ($r in $rows) {
            # A stopped VM bills nothing itself; the spend sits on its managed disks.
            $vmDiskIds = [System.Collections.Generic.List[string]]::new()
            if ($r.osDiskId) { [void]$vmDiskIds.Add([string]$r.osDiskId) }
            foreach ($dd in @($r.dataDisks)) {
                if ($dd -and $dd.managedDisk -and $dd.managedDisk.id) { [void]$vmDiskIds.Add([string]$dd.managedDisk.id) }
            }
            $diskLabel = if ($vmDiskIds.Count -eq 1) { '1 disk' } else { "$($vmDiskIds.Count) disks" }
            [void]$allOrphans.Add([PSCustomObject]@{
                    Category         = 'Deallocated VM'
                    ResourceId       = $r.id
                    ChildResourceIds = @($vmDiskIds)
                    ResourceName     = $r.name
                    ResourceGroup    = $r.resourceGroup
                    SubscriptionId   = $r.subscriptionId
                    Location         = $r.location
                    Detail           = "$($r.vmSize) - $diskLabel still billing"
                    Impact           = 'Medium'
                })
        }
        Write-Host "    Deallocated VMs: $($rows.Count)" -ForegroundColor Gray
    }
    catch {
        throw "Deallocated VM inventory is incomplete: $($_.Exception.Message)"
    }

    # -- 5: Empty App Service Plans (0 apps) ------------------------------
    try {
        $aspQuery = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where properties.numberOfSites == 0
| where sku.tier != 'Free' and sku.tier != 'Shared'
| project id, name, resourceGroup, subscriptionId, location,
          sku = strcat(sku.tier, ' / ', sku.name),
          workers = properties.numberOfWorkers,
          type = 'Empty App Service Plan'
"@
        $result = Search-AzGraphSafe -Query $aspQuery -Subscription $subIds -First 1000 -All
        $rows = if ($result) { @($result.Data) } else { @() }
        foreach ($r in $rows) {
            [void]$allOrphans.Add([PSCustomObject]@{
                    Category       = 'Empty App Service Plan'
                    ResourceId     = $r.id
                    ResourceName   = $r.name
                    ResourceGroup  = $r.resourceGroup
                    SubscriptionId = $r.subscriptionId
                    Location       = $r.location
                    Detail         = "$($r.sku), $($r.workers) worker(s), 0 apps"
                    Impact         = 'High'
                })
        }
        Write-Host "    Empty App Service Plans: $($rows.Count)" -ForegroundColor Gray
    }
    catch {
        throw "App Service plan inventory is incomplete: $($_.Exception.Message)"
    }

    # -- 6: Orphaned Snapshots (older than 30 days) -----------------------
    try {
        $snapshotCutoff = (Get-Date).AddDays(-30).ToString('yyyy-MM-dd')
        $snapQuery = @"
resources
| where type =~ 'microsoft.compute/snapshots'
| where properties.timeCreated < datetime('$snapshotCutoff')
| project id, name, resourceGroup, subscriptionId, location,
          diskSizeGb = properties.diskSizeGB,
          timeCreated = properties.timeCreated,
          type = 'Old Snapshot'
"@
        $result = Search-AzGraphSafe -Query $snapQuery -Subscription $subIds -First 1000 -All
        $rows = if ($result) { @($result.Data) } else { @() }
        foreach ($r in $rows) {
            [void]$allOrphans.Add([PSCustomObject]@{
                    Category       = 'Old Snapshot (30d+)'
                    ResourceId     = $r.id
                    ResourceName   = $r.name
                    ResourceGroup  = $r.resourceGroup
                    SubscriptionId = $r.subscriptionId
                    Location       = $r.location
                    Detail         = "$($r.diskSizeGb) GB, created $($r.timeCreated)"
                    Impact         = 'Low'
                })
        }
        Write-Host "    Old snapshots (30d+): $($rows.Count)" -ForegroundColor Gray
    }
    catch {
        throw "Snapshot inventory is incomplete: $($_.Exception.Message)"
    }

    # -- Observed cost per orphan (best effort) ---------------------------
    # A selected Kusto provider aggregates ingested costs without live API fallback.
    # Otherwise, use Cost Management with a custom previous-month range and a
    # month-to-date fallback. Cost lookup failures leave inventory intact.
    $costMap = @{}
    $costFailures = [System.Collections.Generic.List[string]]::new()
    if ($SkipCost) { [void]$costFailures.Add('Cost lookup was not requested for the selected data source.') }
    $costQueried = 0
    $costPeriodLabel = $null
    $firstOfThisMonth = (Get-Date -Day 1).Date
    $lastMonthStart = $firstOfThisMonth.AddMonths(-1)
    $lastMonthEnd = $firstOfThisMonth.AddDays(-1)
    $costAttempts = @(
        @{
            Label = $lastMonthStart.ToString('MMM yyyy')
            Body  = @{
                type       = 'ActualCost'
                timeframe  = 'Custom'
                timePeriod = @{
                    from = $lastMonthStart.ToString('yyyy-MM-ddT00:00:00Z')
                    to   = $lastMonthEnd.ToString('yyyy-MM-ddT23:59:59Z')
                }
                dataset    = @{
                    granularity = 'None'
                    aggregation = @{ totalCost = @{ name = 'Cost'; function = 'Sum' } }
                    grouping    = @(@{ type = 'Dimension'; name = 'ResourceId' })
                }
            }
        }
        @{
            Label = 'Month to date'
            Body  = @{
                type      = 'ActualCost'
                timeframe = 'MonthToDate'
                dataset   = @{
                    granularity = 'None'
                    aggregation = @{ totalCost = @{ name = 'Cost'; function = 'Sum' } }
                    grouping    = @(@{ type = 'Dimension'; name = 'ResourceId' })
                }
            }
        }
    )
    if ($allOrphans.Count -gt 0 -and -not $SkipCost -and $HubProvider) {
        Write-Host "    Reading orphan costs from the Hub Kusto database..." -ForegroundColor Gray
        try {
            $resourceIds = @(
                foreach ($orphan in $allOrphans) {
                    if ($orphan.ResourceId) { [string]$orphan.ResourceId }
                    if ($orphan.PSObject.Properties['ChildResourceIds']) {
                        foreach ($childId in @($orphan.ChildResourceIds)) {
                            if ($childId) { [string]$childId }
                        }
                    }
                }
            )
            $hubPeriod = $lastMonthStart.ToString('MMM yyyy')
            Write-Verbose "Orphan cost lookup: querying Hub Kusto for $hubPeriod across $($Subscriptions.Count) selected subscriptions and $($resourceIds.Count) resource IDs"
            $hubCosts = Get-FOHubOrphanCosts -Provider $HubProvider -SubscriptionIds @($subIds) -ResourceIds $resourceIds -PeriodStart $lastMonthStart -PeriodEnd $firstOfThisMonth
            if (-not $hubCosts.Ok) { throw "Hub orphan cost query failed: $($hubCosts.Error)" }
            $hubCostMap = @{}
            foreach ($row in $hubCosts.Rows) {
                if ([string]::IsNullOrWhiteSpace($row.ResourceId) -or [string]::IsNullOrWhiteSpace($row.Currency)) {
                    throw 'Hub orphan cost query returned a missing resource ID or billing currency.'
                }
                $key = ([string]$row.ResourceId).ToLowerInvariant()
                if ($hubCostMap.ContainsKey($key)) { throw "Hub orphan cost query returned a duplicate resource ID: $($row.ResourceId)" }
                $hubCostMap[$key] = [pscustomobject]@{
                    Amount = [math]::Round((Get-HubCostValue -Row $row -Column 'Cost'), 2)
                    Currency = ([string]$row.Currency).Trim().ToUpperInvariant()
                }
            }
            $costMap = $hubCostMap
            $costQueried = $Subscriptions.Count
            $costPeriodLabel = $hubPeriod
            Write-Verbose "Orphan cost lookup: Hub Kusto completed ($hubPeriod); received costs for $($costMap.Count) resource IDs"
        }
        catch {
            [void]$costFailures.Add("$($_.Exception.Message) No live Cost Management fallback was attempted.")
            Write-Verbose "Orphan cost lookup failed for the Hub Kusto source: $($_.Exception.Message)"
        }
    }
    elseif ($allOrphans.Count -gt 0 -and -not $SkipCost) {
        $subscriptionIndex = 0
        foreach ($sub in $Subscriptions) {
            $subscriptionIndex++
            $costContext = "Orphan cost lookup [$subscriptionIndex/$($Subscriptions.Count)] for '$($sub.Name)' ($($sub.Id))"
            Write-Verbose "${costContext}: starting"
            $costResp = $null
            $usedLabel = $null
            $lastCode = 'no response'
            foreach ($attempt in $costAttempts) {
                # A later subscription reuses whatever period already worked.
                if ($costPeriodLabel -and $attempt.Label -ne $costPeriodLabel) { continue }
                try {
                    Write-Verbose "${costContext}: requesting $($attempt.Label) actual costs from Cost Management"
                    $body = $attempt.Body | ConvertTo-Json -Depth 10
                    $r = Invoke-AzRestMethodWithRetry -Path "/subscriptions/$($sub.Id)/providers/Microsoft.CostManagement/query?api-version=2023-11-01" -Method POST -Payload $body
                    if ($r -and $r.StatusCode -eq 200) { $costResp = $r; $usedLabel = $attempt.Label; break }
                    $lastCode = if ($r) { [string]$r.StatusCode } else { 'no response' }
                    Write-Verbose "${costContext}: $($attempt.Label) request returned $lastCode"
                }
                catch {
                    $lastCode = $_.Exception.Message
                    Write-Verbose "${costContext}: $($attempt.Label) request failed: $lastCode"
                }
            }

            if (-not $costResp) {
                $reason = switch ($lastCode) {
                    '429' { 'rate limited by Cost Management' }
                    '401' { 'not authorized for Cost Management' }
                    '403' { 'not authorized for Cost Management' }
                    default { "Cost Management returned $lastCode" }
                }
                [void]$costFailures.Add("$($sub.Name): $reason")
                Write-Verbose "${costContext}: skipping cost enrichment ($reason)"
                continue
            }

            try {
                # Follow nextLink: one page only would leave later orphans uncosted.
                foreach ($page in (Get-CostQueryResponsePage -FirstResponse $costResp -Payload $body -Context $costContext)) {
                    $costResult = ($page.Content | ConvertFrom-Json)
                    $costCols = @{}
                    for ($cIdx = 0; $cIdx -lt $costResult.properties.columns.Count; $cIdx++) {
                        $costCols[$costResult.properties.columns[$cIdx].name] = $cIdx
                    }
                    if (-not $costCols.ContainsKey('Currency')) { throw 'Cost response did not expose the expected Currency column.' }
                    foreach ($costRow in $costResult.properties.rows) {
                        $rid = [string]$costRow[$costCols['ResourceId']]
                        # Resource Graph and Cost Management disagree on ID casing.
                        if ($rid) {
                            $costMap[$rid.ToLowerInvariant()] = [pscustomobject]@{
                                Amount   = [math]::Round([double]$costRow[$costCols['Cost']], 2)
                                Currency = ([string]$costRow[$costCols['Currency']]).Trim().ToUpperInvariant()
                            }
                        }
                    }
                }
                if (-not $costPeriodLabel) { $costPeriodLabel = $usedLabel }
                $costQueried++
                Write-Verbose "${costContext}: completed ($usedLabel)"
            }
            catch {
                [void]$costFailures.Add("$($sub.Name): $($_.Exception.Message)")
                Write-Verbose "Orphan cost lookup failed for $($sub.Name): $($_.Exception.Message)"
            }
        }
    }

    # Shared disks can appear on multiple VM rows; total each billed ID only once.
    $aggregateCosts = @{}
    foreach ($orphan in $allOrphans) {
        $ridKey = if ($orphan.ResourceId) { ([string]$orphan.ResourceId).ToLowerInvariant() } else { $null }
        $ownParts = @(if ($ridKey -and $costMap.ContainsKey($ridKey)) { $costMap[$ridKey] })
        $partKeys = @(if ($ownParts.Count -gt 0) { $ridKey })

        # A deallocated VM bills nothing on its own object, so fold in its disks.
        $attachedParts = @()
        if ($orphan.PSObject.Properties['ChildResourceIds']) {
            foreach ($childId in @($orphan.ChildResourceIds)) {
                $childKey = ([string]$childId).ToLowerInvariant()
                if ($costMap.ContainsKey($childKey)) {
                    $attachedParts += $costMap[$childKey]
                    $partKeys += $childKey
                }
            }
        }

        $parts = @($ownParts) + @($attachedParts)
        $partCurrencies = @($parts | ForEach-Object { $_.Currency } | Select-Object -Unique)
        $combined = $null
        $attachedCost = $null
        $orphanCurrency = $null
        if ($partCurrencies.Count -eq 1) {
            $orphanCurrency = [string]$partCurrencies[0]
            $combined = [math]::Round(($parts | Measure-Object -Property Amount -Sum).Sum, 2)
            if ($attachedParts.Count -gt 0) { $attachedCost = [math]::Round(($attachedParts | Measure-Object -Property Amount -Sum).Sum, 2) }
            foreach ($key in $partKeys) { $aggregateCosts[$key] = $costMap[$key] }
        }
        elseif ($partCurrencies.Count -gt 1) {
            [void]$costFailures.Add("$($orphan.ResourceName): costs use multiple billing currencies")
        }
        $orphan | Add-Member -NotePropertyName MonthlyCost -NotePropertyValue $combined -Force
        $orphan | Add-Member -NotePropertyName AttachedCost -NotePropertyValue $attachedCost -Force
        $orphan | Add-Member -NotePropertyName Currency -NotePropertyValue $orphanCurrency -Force
    }

    $costed = @($allOrphans | Where-Object { $null -ne $_.MonthlyCost })
    $costCurrencies = @($costed | ForEach-Object { $_.Currency } | Select-Object -Unique)
    $totalCurrency = if ($costCurrencies.Count -eq 1) { [string]$costCurrencies[0] } else { $null }
    $totalMonthlyCost = if ($costed.Count -gt 0 -and $totalCurrency) { [math]::Round((($aggregateCosts.Values | Measure-Object -Property Amount -Sum).Sum), 2) } else { $null }
    if ($costCurrencies.Count -gt 1) { [void]$costFailures.Add('Observed costs use multiple billing currencies, so no combined total is shown') }
    $costAvailable = ($costQueried -gt 0)
    $costIssue = if ($costFailures.Count -gt 0) { ($costFailures | Select-Object -Unique) -join '; ' } else { $null }
    if ($costed.Count -gt 0) {
        Write-Host "    Observed cost ($costPeriodLabel) on $($costed.Count) of $($allOrphans.Count) orphans." -ForegroundColor Gray
    }
    if ($costIssue) {
        Write-Host "    Cost lookup incomplete - $costIssue" -ForegroundColor Yellow
    }

    # -- Summary by category --
    $summary = $allOrphans | Group-Object Category | ForEach-Object {
        [PSCustomObject]@{
            Category = $_.Name
            Count    = $_.Count
        }
    }

    return [PSCustomObject]@{
        Orphans       = @($allOrphans)
        Summary       = @($summary)
        TotalCount    = $allOrphans.Count
        HasData       = ($allOrphans.Count -gt 0)
        MonthlyCost   = $totalMonthlyCost
        Currency      = $totalCurrency
        CostedCount   = $costed.Count
        CostAvailable = $costAvailable
        CostPeriod    = $costPeriodLabel
        CostIssue     = $costIssue
        CostSource    = if ($SkipCost) { 'None' } elseif ($HubProvider) { 'Kusto' } else { 'CostManagement' }
    }
}
