# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console tool; the formatted console output is the user interface.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Private helper; the returned shape varies by scan and is not a declared contract.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Accepted for signature parity; the dispatcher passes -TenantId to every scan module.')]
param()

###########################################################################
# GET-POLICYINVENTORY.PS1
# FINOPS EXPLORER - Policy Inventory Across the Tenant
###########################################################################
# Purpose: Scan all policy assignments across the tenant's subscriptions
#          and return a summary of assigned policies, their effects,
#          scopes, and compliance state.
#
# Strategy: Resource Graph for effective assignments (a few tenant-wide
#           queries, with ARM per-subscription reads only for subscriptions
#           Resource Graph can't fully cover) + Resource Graph compliance.
#           Falls back to per-sub only if above fail.
###########################################################################

function Format-PolicyEffectName {
    # Azure stores effect names inconsistently across definitions: some authored as
    # "modify", others as "AuditIfNotExists". Capitalizing the first character keeps
    # one column from mixing both conventions.
    param([string]$Effect)
    if ([string]::IsNullOrWhiteSpace($Effect)) { return $Effect }
    $trimmed = $Effect.Trim()
    return $trimmed.Substring(0, 1).ToUpperInvariant() + $trimmed.Substring(1)
}

function Resolve-PolicyEffect {
    # An assignment only carries an effect when it overrides the parameter, which
    # is the exception rather than the rule. Everything else has to come from the
    # definition, or the report understates what is actually enforced.
    #
    # Precedence: assignment override, definition literal, definition parameter default.
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$AssignmentEffect,

        [Parameter()]
        [object]$Definition,

        # An initiative bundles policies with differing effects, so there is no
        # single value to report. That is not the same as an unknown effect.
        [Parameter()]
        [switch]$IsInitiative
    )

    if (-not [string]::IsNullOrWhiteSpace($AssignmentEffect) -and $AssignmentEffect -ne '-') {
        return (Format-PolicyEffectName $AssignmentEffect)
    }
    if ($IsInitiative) { return 'varies (Initiative)' }
    if (-not $Definition) { return '-' }

    # "[parameters('effect')]" defers to the parameter default; a bare word is the effect.
    $literal = [string]$Definition.policyRule.then.effect
    if (-not [string]::IsNullOrWhiteSpace($literal) -and $literal -notmatch '^\s*\[') {
        return (Format-PolicyEffectName $literal)
    }

    $default = [string]$Definition.parameters.effect.defaultValue
    if (-not [string]::IsNullOrWhiteSpace($default)) { return (Format-PolicyEffectName $default) }

    return '-'
}

function Get-PolicyDefinitionMap {
    # Fetched by resource ID rather than queried. Resource Graph's policyresources
    # only returns definitions scoped to the subscriptions being queried, which
    # excludes tenant-level built-ins and management-group definitions - and those
    # are exactly where inherited assignments point. A GET against the definition
    # ID works for all three scopes.
    #
    # Callers pass only the IDs they could not resolve, deduplicated, so this stays
    # proportional to distinct definitions rather than to assignment count.
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$DefinitionIds,

        [Parameter()]
        [System.Collections.Generic.List[string]]$ReadErrors
    )

    $map = @{}
    foreach ($id in @($DefinitionIds | Where-Object { $_ } | Select-Object -Unique)) {
        # The ID is concatenated ahead of a query string, so anything carrying '?',
        # '#' or '&' could rewrite the request. Accept only well-formed definition IDs.
        # The scope prefix is optional: built-ins start at /providers directly.
        try {
            if ($id -notmatch '^(/[A-Za-z0-9._\-()/]+)?/providers/Microsoft\.Authorization/policyDefinitions/[A-Za-z0-9._\-()]+$') {
                throw 'The policy definition resource ID is invalid. No request was sent.'
            }
            $resp = Invoke-AzRestMethodWithRetry -Path "$($id)?api-version=2023-04-01" -Method GET
            if (-not $resp -or $resp.StatusCode -ne 200) { throw "HTTP $($resp.StatusCode) while reading policy definition." }
            $def = $resp.Content | ConvertFrom-Json -ErrorAction Stop
            if (-not $def.properties) { throw 'The policy definition response has no properties.' }
            $map[[string]$id] = $def.properties
        }
        catch {
            $message = "Policy definition '$id' could not be read: $($_.Exception.Message)"
            if ($null -ne $ReadErrors) { [void]$ReadErrors.Add($message) }
            Write-Warning $message
            continue
        }
    }
    return $map
}

function ConvertTo-PolicyAssignmentRecord {
    # One record shape for both the Resource Graph and ARM paths; both return
    # the same assignment resource (id, name, properties).
    param(
        [Parameter(Mandatory)][object]$Assignment,
        [string]$SubscriptionName
    )
    if ([string]::IsNullOrWhiteSpace([string]$Assignment.id) -or [string]::IsNullOrWhiteSpace([string]$Assignment.properties.policyDefinitionId)) {
        throw 'A policy assignment has no resource ID or policy definition ID.'
    }
    $props = $Assignment.properties
    $defId = $props.policyDefinitionId
    $origin = if ($defId -match '/policySetDefinitions/') { 'Initiative' }
    elseif ($defId -match '/providers/Microsoft\.Authorization/policyDefinitions/') { 'BuiltIn' }
    else { 'Custom' }
    $scope = if ($Assignment.id -match '^(.*)/providers/Microsoft\.Authorization/policyAssignments/') { $Matches[1] } else { '' }

    return [PSCustomObject]@{
        AssignmentName  = if ($props.displayName) { $props.displayName } else { $Assignment.name }
        AssignmentId    = $Assignment.id
        PolicyDefId     = $defId
        Scope           = $scope
        Effect          = if ($props.parameters -and $props.parameters.effect) { $props.parameters.effect.value } else { '-' }
        EnforcementMode = if ($props.enforcementMode) { $props.enforcementMode } else { 'Default' }
        Origin          = $origin
        Subscription    = $SubscriptionName
        Description     = if ($props.description) { $props.description } else { '' }
    }
}

function Get-PolicyAssignmentGraphCoverage {
    # Lists effective assignments for many subscriptions with a few tenant-wide
    # Resource Graph queries instead of one ARM request per subscription.
    #
    # Subscription-scoped Resource Graph queries miss assignments inherited from
    # management groups, so assignments are read at tenant scope and matched to
    # each subscription's management group ancestors. A subscription counts as
    # covered only when Resource Graph returns its ancestor chain and every
    # ancestor management group is readable, either through Resource Graph or
    # through one ARM read of a descendant subscription. Otherwise inherited
    # assignments could be silently missing, so the caller reads it through ARM.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Subscriptions
    )

    $subIds = @($Subscriptions | ForEach-Object { [string]$_.Id })
    $chains = @{}
    $subQuery = @"
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project id, subscriptionId, chain = properties.managementGroupAncestorsChain
"@
    $subResult = Search-AzGraphSafe -Query $subQuery -Subscription $subIds -First 1000 -All
    foreach ($row in @($subResult.Data)) {
        $names = @($row.chain | ForEach-Object { [string]$_.name } | Where-Object { $_ })
        if ($row.subscriptionId -and $names.Count -gt 0) { $chains[[string]$row.subscriptionId] = $names }
    }
    Write-Verbose "Policy assignments: Resource Graph returned management group ancestors for $($chains.Count) of $($Subscriptions.Count) subscriptions"

    $readableGroups = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($chains.Count -gt 0) {
        $mgQuery = @"
resourcecontainers
| where type =~ 'microsoft.management/managementgroups'
| project id, name
"@
        $mgResult = Search-AzGraphSafe -Query $mgQuery -UseTenantScope -First 1000 -All
        foreach ($row in @($mgResult.Data)) { if ($row.name) { [void]$readableGroups.Add([string]$row.name) } }
        Write-Verbose "Policy assignments: $($readableGroups.Count) management groups readable through Resource Graph"
    }

    # Resource Graph omits groups the caller can't read (often the tenant root
    # group), so their assignments may be missing there. Any descendant
    # subscription's ARM listing includes every inherited assignment, so one
    # ARM read per unreadable group recovers them.
    $probeByGroup = @{}
    $failedGroups = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($subId in @($chains.Keys)) {
        $hidden = @($chains[$subId] | Where-Object { -not $readableGroups.Contains($_) })
        if ($hidden.Count -eq 0) { continue }
        if (@($hidden | Where-Object { $failedGroups.Contains($_) }).Count -gt 0) { continue }
        Write-Verbose "Policy assignments: reading subscription $subId through ARM to recover assignments at unreadable group(s) $($hidden -join ', ')"
        $rows = [System.Collections.Generic.List[object]]::new()
        $nextLink = "/subscriptions/$subId/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
        $ok = $true
        while ($nextLink) {
            $resp = Invoke-AzRestMethodWithRetry -Path $nextLink -Method GET
            if ($resp.StatusCode -ne 200) { $ok = $false; break }
            $body = $resp.Content | ConvertFrom-Json
            if ($null -eq $body -or $body.value -isnot [array]) { $ok = $false; break }
            $rows.AddRange([object[]]$body.value)
            $nextLink = if ($body.nextLink) { $body.nextLink -replace '^https://management\.azure\.com', '' }
        }
        if (-not $ok) {
            Write-Verbose "Policy assignments: ARM read of $subId failed; subscriptions under $($hidden -join ', ') use ARM"
            foreach ($group in $hidden) { [void]$failedGroups.Add($group) }
            continue
        }
        foreach ($group in $hidden) {
            [void]$readableGroups.Add($group)
            $probeByGroup[$group] = [System.Collections.Generic.List[object]]::new()
        }
        foreach ($row in $rows) {
            if ([string]$row.id -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)/providers/Microsoft\.Authorization/policyAssignments/[^/]+$' -and $hidden -contains $Matches[1]) {
                [void]$probeByGroup[$Matches[1]].Add($row)
            }
        }
    }

    $covered = [System.Collections.Generic.List[object]]::new()
    $uncovered = [System.Collections.Generic.List[object]]::new()
    foreach ($sub in $Subscriptions) {
        $chain = $chains[[string]$sub.Id]
        if ($chain -and @($chain | Where-Object { -not $readableGroups.Contains($_) }).Count -eq 0) { [void]$covered.Add($sub) }
        else { [void]$uncovered.Add($sub) }
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    if ($covered.Count -gt 0) {
        $assignmentQuery = @"
policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| project id, name, properties
"@
        $assignmentResult = Search-AzGraphSafe -Query $assignmentQuery -UseTenantScope -First 1000 -All
        $bySubscription = @{}
        $byGroup = @{}
        foreach ($row in @($assignmentResult.Data)) {
            if ([string]::IsNullOrWhiteSpace([string]$row.id) -or [string]::IsNullOrWhiteSpace([string]$row.properties.policyDefinitionId)) {
                throw 'A policy assignment has no resource ID or policy definition ID.'
            }
            $id = [string]$row.id
            $map = $null
            if ($id -match '^/subscriptions/([^/]+)/') { $key = $Matches[1]; $map = $bySubscription }
            elseif ($id -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)/providers/Microsoft\.Authorization/policyAssignments/[^/]+$') { $key = $Matches[1]; $map = $byGroup }
            else { throw "Policy assignment '$id' has an unsupported scope." }
            if (-not $map.ContainsKey($key)) { $map[$key] = [System.Collections.Generic.List[object]]::new() }
            [void]$map[$key].Add($row)
        }
        Write-Verbose "Policy assignments: Resource Graph returned $(@($assignmentResult.Data).Count) assignments across the tenant"

        foreach ($sub in $covered) {
            $rows = [System.Collections.Generic.List[object]]::new()
            if ($bySubscription.ContainsKey([string]$sub.Id)) { $rows.AddRange($bySubscription[[string]$sub.Id]) }
            foreach ($group in $chains[[string]$sub.Id]) {
                if ($byGroup.ContainsKey($group)) { $rows.AddRange($byGroup[$group]) }
                if ($probeByGroup.ContainsKey($group)) { $rows.AddRange($probeByGroup[$group]) }
            }
            [void]$entries.Add([pscustomobject]@{ Subscription = $sub; Assignments = $rows.ToArray() })
        }
    }

    return [pscustomobject]@{
        Covered   = $entries.ToArray()
        Uncovered = $uncovered.ToArray()
    }
}

function Get-PolicyInventory {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [object[]]$Subscriptions
    )

    $subCount = $Subscriptions.Count
    Write-Host "  Scanning policy assignments across $subCount subscriptions..." -ForegroundColor Cyan

    $allAssignments = [System.Collections.Generic.List[PSCustomObject]]::new()
    $complianceMap = @{}
    $gotAssignments = $false
    $gotCompliance = $false
    $subFailures = [System.Collections.Generic.List[string]]::new()

    # -- Strategy 1: Resource Graph, then ARM for anything it can't cover --
    # Resource Graph lists every effective assignment in a few tenant-wide
    # queries. The ARM Policy API returns ALL effective assignments for one
    # subscription, including those inherited from management groups and the
    # tenant root group, but needs a request per subscription.
    $seenIds = @{}
    $armSubscriptions = @($Subscriptions)
    try {
        Write-Host "  Querying policy assignments via Resource Graph..." -ForegroundColor Cyan
        $graph = Get-PolicyAssignmentGraphCoverage -Subscriptions $Subscriptions
        $graphRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
        $graphSeen = @{}
        foreach ($entry in $graph.Covered) {
            foreach ($a in $entry.Assignments) {
                if ($graphSeen.ContainsKey($a.id)) { continue }
                $graphSeen[$a.id] = $true
                [void]$graphRecords.Add((ConvertTo-PolicyAssignmentRecord -Assignment $a -SubscriptionName $entry.Subscription.Name))
            }
        }
        # Commit only after every row converted, so a malformed row can't leave a partial set.
        $allAssignments.AddRange($graphRecords)
        foreach ($id in $graphSeen.Keys) { $seenIds[$id] = $true }
        $armSubscriptions = @($graph.Uncovered)
        Write-Host "  Resource Graph: $($graphRecords.Count) unique policy assignments for $(@($graph.Covered).Count) of $subCount subscriptions (including inherited)" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Resource Graph policy assignment query failed: $($_.Exception.Message) Using per-subscription ARM requests."
    }

    try {
        if ($armSubscriptions.Count -gt 0) {
            Write-Host "  Querying policy assignments via ARM REST API for $($armSubscriptions.Count) subscription(s)..." -ForegroundColor Cyan
        }
        $armIndex = 0
        foreach ($sub in $armSubscriptions) {
            $armIndex++
            Write-Verbose "Policy assignments [$armIndex/$($armSubscriptions.Count)]: reading '$($sub.Name)' ($($sub.Id)) through ARM"
            # Scoped per subscription: a transient failure on one must not abandon
            # the rest of the tenant and leave a partial result looking complete.
            try {
                $subName = $sub.Name
                $nextLink = "/subscriptions/$($sub.Id)/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
                while ($nextLink) {
                    $resp = Invoke-AzRestMethodWithRetry -Path $nextLink -Method GET
                    if ($resp.StatusCode -ne 200) {
                        [void]$subFailures.Add("$($sub.Name): HTTP $($resp.StatusCode)")
                        break
                    }
                    $body = $resp.Content | ConvertFrom-Json
                    if ($null -eq $body -or $body.value -isnot [array]) {
                        throw 'The policy assignment response has no valid value collection.'
                    }
                    foreach ($a in $body.value) {
                        $record = ConvertTo-PolicyAssignmentRecord -Assignment $a -SubscriptionName $subName
                        # De-duplicate (same MG assignment appears under each sub)
                        if ($seenIds.ContainsKey($a.id)) { continue }
                        $seenIds[$a.id] = $true
                        [void]$allAssignments.Add($record)
                    }
                    # Handle pagination via nextLink
                    $nextLink = if ($body.nextLink) {
                        $body.nextLink -replace '^https://management\.azure\.com', ''
                    }
                    else { $null }
                }
            }
            catch {
                [void]$subFailures.Add("$($sub.Name): $($_.Exception.Message)")
            }
        }

        if ($subFailures.Count -gt 0) {
            Write-Warning "  Policy assignments could not be read for $($subFailures.Count) of $subCount subscription(s); the inventory below is partial."
            foreach ($f in ($subFailures | Select-Object -First 3)) { Write-Verbose "    $f" }
        }

        if ($subFailures.Count -eq 0 -or $allAssignments.Count -gt 0) {
            $gotAssignments = $true
            if ($armSubscriptions.Count -gt 0) {
                Write-Host "  Policy assignments: $($allAssignments.Count) unique (including inherited)" -ForegroundColor Green
            }
        }
    }
    catch {
        [void]$subFailures.Add("ARM REST policy query: $($_.Exception.Message)")
        Write-Warning "  ARM REST policy query failed: $($_.Exception.Message)"
    }

    # Fallback: Resource Graph if ARM REST didn't find any
    if (-not $gotAssignments) {
        try {
            Write-Host "  Falling back to Resource Graph for policy assignments..." -ForegroundColor Yellow
            $argQuery = @"
policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| project id, name, properties, subscriptionId, type
"@
            $subIds = $Subscriptions | ForEach-Object { $_.Id }
            $skipToken = $null
            $pageNum = 0
            do {
                $pageNum++
                $result = Search-AzGraphSafe -Query $argQuery -Subscription $subIds -First 1000 -SkipToken $skipToken
                if ($result -and $result.Data) {
                    foreach ($r in $result.Data) {
                        $props = $r.properties
                        $defId = $props.policyDefinitionId
                        $origin = if ($defId -match '/policySetDefinitions/') { 'Initiative' }
                        elseif ($defId -match '/providers/Microsoft\.Authorization/policyDefinitions/') { 'BuiltIn' }
                        else { 'Custom' }
                        $subName = $r.subscriptionId
                        $matchSub = $Subscriptions | Where-Object { $_.Id -eq $r.subscriptionId } | Select-Object -First 1
                        if ($matchSub) { $subName = $matchSub.Name }
                        [void]$allAssignments.Add([PSCustomObject]@{
                                AssignmentName  = if ($props.displayName) { $props.displayName } else { $r.name }
                                AssignmentId    = $r.id
                                PolicyDefId     = $defId
                                Scope           = if ($props.scope) { $props.scope } else { ($r.id -replace '/providers/Microsoft\.Authorization/policyAssignments/.*', '') }
                                Effect          = if ($props.parameters -and $props.parameters.effect) { $props.parameters.effect.value } else { '-' }
                                EnforcementMode = if ($props.enforcementMode) { $props.enforcementMode } else { 'Default' }
                                Origin          = $origin
                                Subscription    = $subName
                                Description     = if ($props.description) { $props.description } else { '' }
                            })
                    }
                    $skipToken = $result.SkipToken
                }
                else { $skipToken = $null }
            } while ($skipToken)
            if ($allAssignments.Count -gt 0) {
                $gotAssignments = $true
                Write-Host "  Resource Graph fallback: $($allAssignments.Count) assignments" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "  Resource Graph policy query failed: $($_.Exception.Message)"
        }
    }

    $complianceErrors = [System.Collections.Generic.List[string]]::new()
    # -- Strategy 2: Resource Graph for compliance (tenant-wide, fast) ---
    # The MG-scope PolicyInsights summarize REST API hangs indefinitely,
    # and per-sub REST loops are slow on large tenants.
    # Resource Graph policyresources table gives us compliance across ALL
    # subscriptions in a single paginated call - fast and complete.
    try {
        Write-Host "  Querying policy compliance via Resource Graph..." -ForegroundColor Cyan
        $compQuery = @"
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend complianceState = tostring(properties.complianceState)
| extend resourceId = tolower(tostring(properties.resourceId)),
    stateWeight = case(
        complianceState =~ 'NonCompliant', 7,
        complianceState =~ 'Compliant', 6,
        complianceState =~ 'Error', 5,
        complianceState in~ ('Conflict', 'Conflicting'), 4,
        complianceState =~ 'Protected', 3,
        complianceState =~ 'Exempt', 2,
        complianceState =~ 'Unknown', 1,
        0)
| where stateWeight > 0
| summarize stateWeight = max(stateWeight) by subscriptionId, resourceId
| summarize
    Compliant    = countif(stateWeight == 6),
    NonCompliant = countif(stateWeight == 7),
    Total        = count()
    by subscriptionId
"@
        $subIds = $Subscriptions | ForEach-Object { $_.Id }
        $compResult = Search-AzGraphSafe -Query $compQuery -Subscription $subIds -First 1000 -All

        if ($compResult -and $compResult.Data -and $compResult.Data.Count -gt 0) {
            foreach ($row in $compResult.Data) {
                $subName = $row.subscriptionId
                $matchSub = $Subscriptions | Where-Object { $_.Id -eq $row.subscriptionId } | Select-Object -First 1
                if (-not $matchSub) { continue }
                $subName = $matchSub.Name
                foreach ($column in @('Total', 'NonCompliant', 'Compliant')) {
                    if ((Get-HubCostValue -Row $row -Column $column) -lt 0) { throw 'Policy compliance contains an invalid count.' }
                }

                $complianceMap[$row.subscriptionId] = [PSCustomObject]@{
                    Subscription   = $subName
                    SubscriptionId = $row.subscriptionId
                    TotalResources = $row.Total
                    NonCompliant   = $row.NonCompliant
                    Compliant      = $row.Compliant
                    # Not derivable from the compliance query; the REST fallback
                    # computes it. $null distinguishes "unknown" from a real zero.
                    PolicyCount    = $null
                }
            }
            $gotCompliance = @($Subscriptions | Where-Object { $complianceMap.ContainsKey([string]$_.Id) }).Count -eq $subCount
            Write-Host "  Resource Graph compliance: $($complianceMap.Count) subscriptions" -ForegroundColor Green
        }
    }
    catch {
        $complianceMap.Clear()
        Write-Warning "  Resource Graph compliance query failed: $($_.Exception.Message)"
    }

    # -- Compliance fallback: per-sub REST (only if ARG compliance failed) --
    if (-not $gotCompliance) {
        Write-Host "  Falling back to per-sub compliance queries..." -ForegroundColor Yellow
        $complianceMap.Clear()
        $i = 0
        foreach ($sub in $Subscriptions) {
            $i++
            if ($subCount -gt 20 -and ($i % 10 -eq 0)) {
                if (Get-Command Update-ScanStatus -ErrorAction SilentlyContinue) {
                    Update-ScanStatus "Scanning policy compliance ($i/$subCount)..."
                }
            }
            try {
                $compPath = "/subscriptions/$($sub.Id)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
                $compResp = Invoke-AzRestMethodWithRetry -Path $compPath -Method POST
                if (-not $compResp -or $compResp.StatusCode -ne 200) { throw "Policy compliance returned HTTP $($compResp.StatusCode)." }
                $summary = ($compResp.Content | ConvertFrom-Json -ErrorAction Stop).value
                if ($summary -isnot [array] -or $summary.Count -gt 1) { throw 'Policy compliance returned an invalid summary.' }
                $total = 0.0
                $compliant = 0.0
                $nonCompliant = 0.0
                $policyCount = $null
                if ($summary.Count -eq 1) {
                    $summaryResult = $summary[0].results
                    if ($summaryResult.resourceDetails -isnot [array]) { throw 'Policy compliance has no resource counts.' }
                    foreach ($detail in $summaryResult.resourceDetails) {
                        $count = Get-HubCostValue -Row $detail -Column 'count'
                        if ($count -lt 0) { throw 'Policy compliance contains a negative count.' }
                        $total += $count
                        if ($detail.complianceState -eq 'compliant') { $compliant += $count }
                        elseif ($detail.complianceState -eq 'noncompliant') { $nonCompliant += $count }
                    }
                    $policyCount = ($summaryResult.policyDetails | ForEach-Object { $_.count } | Measure-Object -Sum).Sum
                }
                $complianceMap[$sub.Id] = [PSCustomObject]@{
                    Subscription = $sub.Name; SubscriptionId = $sub.Id; TotalResources = $total
                    NonCompliant = $nonCompliant; Compliant = $compliant; PolicyCount = $policyCount
                }
            }
            catch {
                [void]$complianceErrors.Add("$($sub.Name): $($_.Exception.Message)")
                Write-Warning "  Policy compliance failed for $($sub.Name): $($_.Exception.Message)"
            }
        }
    }

    # -- Strategy 3: Per-sub fallback (only if Resource Graph failed) ---
    if (-not $gotAssignments) {
        Write-Host "  Falling back to per-subscription policy scan..." -ForegroundColor Yellow
        $i = 0
        foreach ($sub in $Subscriptions) {
            $i++
            if ($i -eq 1 -or $i -eq $subCount -or ($subCount -gt 5 -and $i % [math]::Max(1, [int]($subCount / 10)) -eq 0)) {
                if (Get-Command Update-ScanStatus -ErrorAction SilentlyContinue) {
                    Update-ScanStatus "Scanning policies ($i/$subCount subs)..."
                }
            }
            try {
                $assignPath = "/subscriptions/$($sub.Id)/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
                $resp = Invoke-AzRestMethodWithRetry -Path $assignPath -Method GET
                if ($resp.StatusCode -eq 200) {
                    $assignments = ($resp.Content | ConvertFrom-Json).value
                    foreach ($a in $assignments) {
                        $props = $a.properties
                        $defId = $props.policyDefinitionId
                        $origin = if ($defId -match '/providers/Microsoft\.Authorization/policyDefinitions/') { 'BuiltIn' } else { 'Custom' }
                        if ($defId -match '/policySetDefinitions/') { $origin = 'Initiative' }

                        [void]$allAssignments.Add([PSCustomObject]@{
                                AssignmentName  = $props.displayName
                                AssignmentId    = $a.id
                                PolicyDefId     = $defId
                                Scope           = $props.scope
                                Effect          = if ($props.parameters -and $props.parameters.effect) { $props.parameters.effect.value } else { '-' }
                                EnforcementMode = if ($props.enforcementMode) { $props.enforcementMode } else { 'Default' }
                                Origin          = $origin
                                Subscription    = $sub.Name
                                Description     = if ($props.description) { $props.description } else { '' }
                            })
                    }
                }
            }
            catch {
                Write-Warning "  Policy assignments failed for $($sub.Name): $($_.Exception.Message)"
            }
        }
    }

    # -- Deduplicate assignments by resource ID -----------------------
    $seen = @{}
    $unique = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($a in $allAssignments) {
        $key = [string]$a.AssignmentId
        if ([string]::IsNullOrWhiteSpace($key)) {
            [void]$subFailures.Add('An assignment has no resource ID; assignment coverage is incomplete.')
            [void]$unique.Add($a)
            continue
        }
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            [void]$unique.Add($a)
        }
    }

    $scopeNames = @{}
    $scopeNameErrors = [System.Collections.Generic.List[string]]::new()
    foreach ($subscription in $Subscriptions) {
        if ($subscription.Id -and $subscription.Name) { $scopeNames["/subscriptions/$($subscription.Id)"] = [string]$subscription.Name }
    }
    foreach ($assignment in $unique) {
        $scopeId = ([string]$assignment.Scope).TrimEnd('/')
        if (-not $scopeNames.ContainsKey($scopeId)) {
            $scopeNames[$scopeId] = [string]$assignment.Scope
            if ($scopeId -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)$' -and $scopeNames.ContainsKey("/subscriptions/$($Matches[1])")) {
                $scopeNames[$scopeId] = "$($scopeNames["/subscriptions/$($Matches[1])"]) / $($Matches[2])"
            }
            elseif ($TenantId -and $scopeId -match '^/providers/Microsoft\.Management/managementGroups/[A-Za-z0-9._()\-]+$') {
                try {
                    $scopeResponse = Invoke-AzRestMethodWithRetry -Path "$($scopeId)?api-version=2020-05-01" -Method GET
                    if (-not $scopeResponse -or $scopeResponse.StatusCode -ne 200) { throw "HTTP $($scopeResponse.StatusCode)." }
                    $scopeBody = $scopeResponse.Content | ConvertFrom-Json -ErrorAction Stop
                    if ($scopeBody.id -ne $scopeId -or $scopeBody.properties.tenantId -ne $TenantId) { throw 'The returned management group does not match the requested scope and tenant.' }
                    if ([string]::IsNullOrWhiteSpace([string]$scopeBody.properties.displayName)) { throw 'The management group display name is missing.' }
                    $scopeNames[$scopeId] = [string]$scopeBody.properties.displayName
                }
                catch {
                    $message = "Policy scope name unavailable for '$scopeId': $($_.Exception.Message) The scope ID is retained."
                    [void]$scopeNameErrors.Add($message)
                    Write-Warning $message
                }
            }
        }
        $assignment | Add-Member -NotePropertyName ScopeDisplayName -NotePropertyValue $scopeNames[$scopeId]
    }

    # -- Resolve effects the assignment did not override ---------------
    $definitionErrors = [System.Collections.Generic.List[string]]::new()
    if ($unique.Count -gt 0) {
        # Only single policies need a definition lookup; initiatives resolve to 'varies'.
        $needsLookup = @($unique |
            Where-Object { $_.Origin -ne 'Initiative' -and (-not $_.Effect -or $_.Effect -eq '-') } |
            ForEach-Object { $_.PolicyDefId })
        $defMap = if ($needsLookup.Count -gt 0) { Get-PolicyDefinitionMap -DefinitionIds $needsLookup -ReadErrors $definitionErrors } else { @{} }

        foreach ($a in $unique) {
            $override = if ($a.Effect -and $a.Effect -ne '-') { $a.Effect } else { '' }
            $a.Effect = Resolve-PolicyEffect -AssignmentEffect $override -Definition $defMap[[string]$a.PolicyDefId] -IsInitiative:($a.Origin -eq 'Initiative')
        }
        $resolved = @($unique | Where-Object { $_.Effect -ne '-' }).Count
        Write-Host "  Effects resolved for $resolved of $($unique.Count) assignments." -ForegroundColor Green
    }

    # -- Compliance totals ---------------------------------------------
    $totalCompliant = 0
    $totalNonCompliant = 0
    foreach ($c in $complianceMap.Values) {
        $totalCompliant += $c.Compliant
        $totalNonCompliant += $c.NonCompliant
    }
    $totalEvaluated = $totalCompliant + $totalNonCompliant
    $complianceIncomplete = $complianceErrors.Count -gt 0 -or @($Subscriptions | Where-Object { -not $complianceMap.ContainsKey([string]$_.Id) }).Count -gt 0
    $compliancePct = if (-not $complianceIncomplete -and $totalEvaluated -gt 0) { [math]::Round(($totalCompliant / $totalEvaluated) * 100, 1) } else { $null }

    return [PSCustomObject]@{
        Assignments                  = $unique
        AssignmentCount              = $unique.Count
        CoverageIncomplete           = ($subFailures.Count -gt 0)
        AssignmentErrors             = $subFailures.ToArray()
        DefinitionCoverageIncomplete = ($definitionErrors.Count -gt 0)
        DefinitionErrors             = $definitionErrors.ToArray()
        ScopeNameErrors              = $scopeNameErrors.ToArray()
        Note                         = (@(
                if ($subFailures.Count -gt 0) { 'Some effective policy assignments could not be read. Missing assignments cannot be determined from this inventory.' }
                if ($complianceIncomplete) { 'Policy compliance coverage is incomplete. Partial results do not establish a percentage for the selected scope.' }
            if ($definitionErrors.Count -gt 0) { 'Policy definition coverage is incomplete. Some effects could not be resolved because their definitions could not be read.' }
            ) -join ' ')
        ComplianceCoverageIncomplete = $complianceIncomplete
        ComplianceErrors             = $complianceErrors.ToArray()
        ComplianceBySubMap           = $complianceMap
        CompliancePct                = $compliancePct
        TotalCompliant               = $totalCompliant
        TotalNonCompliant            = $totalNonCompliant
        TotalEvaluated               = $totalEvaluated
        HasComplianceData            = (-not $complianceIncomplete -and $totalEvaluated -gt 0)
    }
}
