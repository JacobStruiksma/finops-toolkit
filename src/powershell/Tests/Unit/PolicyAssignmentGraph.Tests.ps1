# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

& "$PSScriptRoot/../Initialize-Tests.ps1"

Describe 'Policy assignments through Resource Graph' {

    # Scoped to this Describe: Initialize-Tests.ps1 already declares a root-level
    # BeforeAll, and Pester 6 rejects a second one during discovery.
    BeforeAll {
        $script:MultitoolModule = Join-Path $PSScriptRoot '../../Private/FinOpsMultitool/FinOpsMultitool.psm1'
        Import-Module $script:MultitoolModule -Force
    }

    AfterAll {
        Remove-Module FinOpsMultitool -ErrorAction SilentlyContinue
    }

    BeforeEach {
        InModuleScope FinOpsMultitool {
            $script:subA = '11111111-1111-1111-1111-111111111111'
            $script:subB = '22222222-2222-2222-2222-222222222222'
            $script:subs = @(
                [pscustomobject]@{ Id = $script:subA; Name = 'Sub A' }
                [pscustomobject]@{ Id = $script:subB; Name = 'Sub B' }
            )
            $script:graphChains = @{
                $script:subA = @('child', 'root')
                $script:subB = @('child', 'root')
            }
            $script:graphGroups = @('child', 'root')
            $script:graphAssignments = @(
                @{ id = "/subscriptions/$($script:subA)/providers/Microsoft.Authorization/policyAssignments/sub-a"; name = 'sub-a'; properties = @{ displayName = 'Sub A only'; policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/a' } }
                @{ id = "/subscriptions/$($script:subB)/resourceGroups/rg/providers/Microsoft.Authorization/policyAssignments/rg-b"; name = 'rg-b'; properties = @{ displayName = 'RG in B'; policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/b' } }
                @{ id = '/providers/Microsoft.Management/managementGroups/root/providers/Microsoft.Authorization/policyAssignments/root-mg'; name = 'root-mg'; properties = @{ displayName = 'Root MG'; policyDefinitionId = '/providers/Microsoft.Authorization/policySetDefinitions/s'; parameters = @{ effect = @{ value = 'Audit' } } } }
                @{ id = '/providers/Microsoft.Management/managementGroups/other/providers/Microsoft.Authorization/policyAssignments/other-mg'; name = 'other-mg'; properties = @{ displayName = 'Unrelated MG'; policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/o' } }
            )
            $script:graphFailAssignments = $false
            $script:armFail = $false
            $script:armPaths = [System.Collections.Generic.List[string]]::new()

            Mock Write-Host { }
            Mock Write-Warning { }
            Mock Get-AzContext { throw 'Must not read an Azure context.' }
            Mock Invoke-RestMethod { throw 'Must not send HTTP requests.' }
            Mock Search-AzGraphSafe {
                if ($Query -like '*microsoft.resources/subscriptions*') {
                    return [pscustomobject]@{ Data = @(foreach ($k in $script:graphChains.Keys) {
                                [pscustomobject]@{ id = "/subscriptions/$k"; subscriptionId = $k; chain = @($script:graphChains[$k] | ForEach-Object { [pscustomobject]@{ name = $_ } }) }
                            }) }
                }
                if ($Query -like '*microsoft.management/managementgroups*') {
                    return [pscustomobject]@{ Data = @($script:graphGroups | ForEach-Object { [pscustomobject]@{ id = "/providers/Microsoft.Management/managementGroups/$_"; name = $_ } }) }
                }
                if ($Query -like '*policyassignments*') {
                    if ($script:graphFailAssignments) { throw 'Synthetic Resource Graph failure.' }
                    return [pscustomobject]@{ Data = @($script:graphAssignments | ForEach-Object { $_ | ConvertTo-Json -Depth 8 | ConvertFrom-Json }) }
                }
                [pscustomobject]@{ Data = @() }
            }
            Mock Invoke-AzRestMethodWithRetry {
                if ($Path -like '*policyAssignments*') {
                    [void]$script:armPaths.Add($Path)
                    if ($script:armFail) { return [pscustomobject]@{ StatusCode = 403; Content = '{}' } }
                    $subId = if ($Path -match '^/subscriptions/([^/]+)/') { $Matches[1] }
                    $value = @(
                        @{ id = "/subscriptions/$subId/providers/Microsoft.Authorization/policyAssignments/arm-$subId"; name = "arm-$subId"; properties = @{ displayName = "ARM $subId"; policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/arm' } }
                        @{ id = '/providers/Microsoft.Management/managementGroups/hidden/providers/Microsoft.Authorization/policyAssignments/hidden-mg'; name = 'hidden-mg'; properties = @{ displayName = 'Hidden MG'; policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/h' } }
                        @{ id = '/providers/Microsoft.Management/managementGroups/root/providers/Microsoft.Authorization/policyAssignments/root-mg'; name = 'root-mg'; properties = @{ displayName = 'Root MG'; policyDefinitionId = '/providers/Microsoft.Authorization/policySetDefinitions/s' } }
                    )
                    return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = $value } | ConvertTo-Json -Depth 8) }
                }
                [pscustomobject]@{ StatusCode = 200; Content = '{"value":[]}' }
            }
        }
    }

    It 'Reads every covered subscription from Resource Graph without ARM requests' {
        InModuleScope FinOpsMultitool {
            $inventory = Get-PolicyInventory -Subscriptions $script:subs

            $script:armPaths.Count | Should -Be 0
            $inventory.CoverageIncomplete | Should -BeFalse
            $inventory.AssignmentCount | Should -Be 3
            $ids = @($inventory.Assignments | ForEach-Object AssignmentId)
            $ids | Should -Not -Contain '/providers/Microsoft.Management/managementGroups/other/providers/Microsoft.Authorization/policyAssignments/other-mg'
            $root = $inventory.Assignments | Where-Object AssignmentId -like '*root-mg'
            @($root).Count | Should -Be 1
            $root.Subscription | Should -Be 'Sub A'
            $root.Origin | Should -Be 'Initiative'
            $root.Scope | Should -Be '/providers/Microsoft.Management/managementGroups/root'
            ($inventory.Assignments | Where-Object AssignmentId -like '*rg-b').Subscription | Should -Be 'Sub B'
            Should -Invoke Search-AzGraphSafe -Times 2 -Exactly -ParameterFilter { $UseTenantScope }
        }
    }

    It 'Sends only the subscription without an ancestor chain to ARM' {
        InModuleScope FinOpsMultitool {
            $script:graphChains.Remove($script:subB)

            $inventory = Get-PolicyInventory -Subscriptions $script:subs

            @($script:armPaths) | Should -Be @("/subscriptions/$($script:subB)/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01")
            $inventory.CoverageIncomplete | Should -BeFalse
            $ids = @($inventory.Assignments | ForEach-Object AssignmentId)
            $ids | Should -Contain "/subscriptions/$($script:subB)/providers/Microsoft.Authorization/policyAssignments/arm-$($script:subB)"
            $ids | Should -Contain "/subscriptions/$($script:subA)/providers/Microsoft.Authorization/policyAssignments/sub-a"
            $ids | Should -Not -Contain "/subscriptions/$($script:subB)/resourceGroups/rg/providers/Microsoft.Authorization/policyAssignments/rg-b"
        }
    }

    It 'Recovers assignments at an unreadable group with one ARM read' {
        InModuleScope FinOpsMultitool {
            $script:graphChains[$script:subA] = @('hidden', 'root')
            $script:graphChains[$script:subB] = @('hidden', 'root')

            $inventory = Get-PolicyInventory -Subscriptions $script:subs

            $script:armPaths.Count | Should -Be 1
            $inventory.CoverageIncomplete | Should -BeFalse
            $ids = @($inventory.Assignments | ForEach-Object AssignmentId)
            $ids | Should -Contain '/providers/Microsoft.Management/managementGroups/hidden/providers/Microsoft.Authorization/policyAssignments/hidden-mg'
            @($ids | Where-Object { $_ -like '*root-mg' }).Count | Should -Be 1
            @($ids | Where-Object { $_ -like '*/arm-*' }).Count | Should -Be 0
            @($inventory.Assignments | Where-Object AssignmentId -like '*hidden-mg').Count | Should -Be 1
        }
    }

    It 'Sends subscriptions under an unreadable group to ARM when the recovery read fails' {
        InModuleScope FinOpsMultitool {
            $script:graphChains[$script:subB] = @('hidden', 'root')
            $script:armFail = $true

            $inventory = Get-PolicyInventory -Subscriptions $script:subs

            # One failed recovery read, then the regular ARM read for the same subscription.
            $script:armPaths.Count | Should -Be 2
            @($script:armPaths | Select-Object -Unique) | Should -Be @("/subscriptions/$($script:subB)/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01")
            $inventory.CoverageIncomplete | Should -BeTrue
            @($inventory.Assignments | ForEach-Object AssignmentId) | Should -Contain "/subscriptions/$($script:subA)/providers/Microsoft.Authorization/policyAssignments/sub-a"
        }
    }

    It 'Falls back to ARM for every subscription when Resource Graph <Case>' -ForEach @(
        @{ Case = 'throws' }
        @{ Case = 'returns an unsupported scope' }
        @{ Case = 'returns a row without a definition' }
    ) {
        InModuleScope FinOpsMultitool -Parameters @{ Case = $Case } {
            param($Case)
            switch ($Case) {
                'throws' { $script:graphFailAssignments = $true }
                'returns an unsupported scope' { $script:graphAssignments += @{ id = '/providers/Microsoft.Authorization/policyAssignments/tenant'; name = 'tenant'; properties = @{ policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/t' } } }
                'returns a row without a definition' { $script:graphAssignments += @{ id = "/subscriptions/$($script:subA)/providers/Microsoft.Authorization/policyAssignments/bad"; name = 'bad'; properties = @{} } }
            }

            $inventory = Get-PolicyInventory -Subscriptions $script:subs

            $script:armPaths.Count | Should -Be 2
            $ids = @($inventory.Assignments | ForEach-Object AssignmentId)
            $ids | Should -Not -Contain "/subscriptions/$($script:subA)/providers/Microsoft.Authorization/policyAssignments/sub-a"
            @($ids | Where-Object { $_ -like '*/arm-*' }).Count | Should -Be 2
            $inventory.AssignmentCount | Should -Be 4
            Should -Invoke Write-Warning -ParameterFilter { $Message -like '*Resource Graph policy assignment query failed*' }
        }
    }
}
