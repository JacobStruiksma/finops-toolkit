# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

& "$PSScriptRoot/../Initialize-Tests.ps1"

Describe 'Idle VM batch metrics' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '../../Private/FinOpsMultitool/FinOpsMultitool.psm1') -Force
    }

    AfterAll {
        Remove-Module FinOpsMultitool -ErrorAction SilentlyContinue
    }

    BeforeEach {
        Mock Write-Host -ModuleName FinOpsMultitool { }
        Mock Get-FinOpsArmEndpoint -ModuleName FinOpsMultitool { 'https://management.azure.com' }
        Mock Get-PlainAccessToken -ModuleName FinOpsMultitool { 'synthetic-token' }
        $script:fixtureVMs = @(
            foreach ($i in 1..52) {
                [pscustomobject]@{
                    name = "vm$i"; subscriptionId = '11111111-1111-1111-1111-111111111111'; resourceGroup = 'fixture'
                    location = 'eastus'; powerState = 'PowerState/running'; vmSize = 'Standard_D2s_v5'; osType = 'Linux'
                }
            }
        )
        Mock Search-AzGraphSafe -ModuleName FinOpsMultitool { @{ Data = $script:fixtureVMs } }
        Mock Invoke-WebRequest -ModuleName FinOpsMultitool {
            $metrics = @(
                @{ name = @{ value = 'Percentage CPU' }; timeseries = @(@{ data = @(@{ average = 2 }) }) }
                @{ name = @{ value = 'Network In Total' }; timeseries = @(@{ data = @(@{ total = 0 }) }) }
                @{ name = @{ value = 'Network Out Total' }; timeseries = @(@{ data = @(@{ total = 0 }) }) }
            )
            if ($Method -eq 'Post') {
                $items = @(
                    foreach ($id in ($Body | ConvertFrom-Json).resourceids) {
                        @{ resourceid = $id; value = $metrics }
                    }
                )
                [pscustomobject]@{ Content = (@{ values = $items } | ConvertTo-Json -Depth 10) }
            }
            else {
                [pscustomobject]@{ Content = (@{ value = $metrics } | ConvertTo-Json -Depth 10) }
            }
        }
    }

    It 'Splits batches at 50 VMs and logs progress only with verbose <Enabled>' -ForEach @(
        @{ Enabled = $true }
        @{ Enabled = $false }
    ) {
        $output = @(Get-IdleVMs -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }) -Verbose:$Enabled 4>&1)
        $result = $output | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] }
        $messages = @($output | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object Message)
        $result.Count | Should -Be 52
        $result.EvaluatedVMs | Should -Be 52
        $result.MetricFailures | Should -Be 0
        if ($Enabled) {
            @($messages | Where-Object { $_ -match 'batch \[\d+/\d+\]' }).Count | Should -BeGreaterThan 0
            $messages | Should -Contain 'VM metrics completed: 52/52 VMs evaluated; 0 failed'
        }
        else { $messages.Count | Should -Be 0 }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 2 -Exactly
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 1 -Exactly -ParameterFilter { ($Body | ConvertFrom-Json).resourceids.Count -eq 50 }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 1 -Exactly -ParameterFilter { ($Body | ConvertFrom-Json).resourceids.Count -eq 2 }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 0 -Exactly -ParameterFilter { $MaximumRedirection -ne 0 -or $Uri -notlike '*interval=FULL*' }
    }

    It 'Keeps subscription and region groups separate and skips stopped VMs' {
        $script:fixtureVMs[2].subscriptionId = '22222222-2222-2222-2222-222222222222'
        $script:fixtureVMs[3].subscriptionId = '22222222-2222-2222-2222-222222222222'
        $script:fixtureVMs[4].location = 'westeurope'
        $script:fixtureVMs[5].location = 'westeurope'
        $script:fixtureVMs[6].powerState = 'PowerState/deallocated'
        $result = Get-IdleVMs -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }, [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222' })
        $result.EvaluatedVMs | Should -Be 51
        $result.DeallocatedVMs | Should -Be 1
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 3 -Exactly
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 0 -Exactly -ParameterFilter {
            $ids = @(($Body | ConvertFrom-Json).resourceids)
            @($ids | ForEach-Object { ($_ -split '/')[2] } | Select-Object -Unique).Count -ne 1 -or
            ($Uri -like '*eastus*' -and ($ids -match '/vm[56]$').Count -gt 0)
        }
    }

    It 'Falls back to per-VM requests when the batch endpoint fails' {
        $script:fixtureVMs = @($script:fixtureVMs | Select-Object -First 2)
        Mock Invoke-WebRequest -ModuleName FinOpsMultitool { throw 'Synthetic batch failure.' } -ParameterFilter { $Method -eq 'Post' }
        $result = Get-IdleVMs -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }) -WarningVariable warnings
        $result.EvaluatedVMs | Should -Be 2
        $result.MetricFailures | Should -Be 0
        "$warnings" | Should -BeLike '*Falling back to per-VM requests*'
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 2 -Exactly -ParameterFilter { $Method -eq 'Get' }
    }

    It 'Preserves per-VM access for other clouds' {
        $script:fixtureVMs = @($script:fixtureVMs | Select-Object -First 2)
        Mock Get-FinOpsArmEndpoint -ModuleName FinOpsMultitool { 'https://management.usgovcloudapi.net' }
        $result = Get-IdleVMs -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' })
        $result.EvaluatedVMs | Should -Be 2
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 2 -Exactly -ParameterFilter { $Method -eq 'Get' -and $Uri -like 'https://management.usgovcloudapi.net/*' }
        Should -Invoke Get-PlainAccessToken -ModuleName FinOpsMultitool -Times 0 -Exactly -ParameterFilter { $ResourceUrl -eq 'https://metrics.monitor.azure.com/' }
    }

    It 'Falls back with a warning when a Metrics token cannot be acquired' {
        $script:fixtureVMs = @($script:fixtureVMs | Select-Object -First 2)
        Mock Get-PlainAccessToken -ModuleName FinOpsMultitool { throw 'Synthetic token failure.' } -ParameterFilter { $ResourceUrl -eq 'https://metrics.monitor.azure.com/' }
        $result = Get-IdleVMs -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }) -WarningVariable warnings
        $result.EvaluatedVMs | Should -Be 2
        "$warnings" | Should -BeLike '*batching is unavailable*Synthetic token failure*'
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 2 -Exactly -ParameterFilter { $Method -eq 'Get' }
    }

    It 'Does not fan out per-VM requests after a batch is rate limited' {
        $script:fixtureVMs = @($script:fixtureVMs | Select-Object -First 2)
        Mock Invoke-WebRequest -ModuleName FinOpsMultitool {
            $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
            throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Synthetic throttle.', $response)
        }
        $result = Get-IdleVMs -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }) -WarningVariable warnings
        $result.EvaluatedVMs | Should -Be 0
        $result.MetricFailures | Should -Be 2
        "$warnings" | Should -BeLike '*rate limited*'
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 1 -Exactly
    }

    It 'Keeps existing classifications with batched <Case> measurements' -ForEach @(
        @{ Case = 'idle'; Cpu = 2; Network = 1MB; Classification = 'Idle' }
        @{ Case = 'underutilized'; Cpu = 7; Network = 1MB; Classification = 'Underutilized' }
        @{ Case = 'busy'; Cpu = 20; Network = 1MB; Classification = $null }
        @{ Case = 'zero'; Cpu = 0; Network = 0; Classification = 'Idle' }
    ) {
        $script:fixtureVMs = @($script:fixtureVMs | Select-Object -First 2)
        $fixtureCpu = $Cpu
        $fixtureNetwork = $Network
        Mock Invoke-WebRequest -ModuleName FinOpsMultitool {
            $metrics = @(
                @{ name = @{ value = 'Percentage CPU' }; timeseries = @(@{ data = @(@{ average = $fixtureCpu }) }) }
                @{ name = @{ value = 'Network In Total' }; timeseries = @(@{ data = @(@{ total = $fixtureNetwork }) }) }
                @{ name = @{ value = 'Network Out Total' }; timeseries = @(@{ data = @(@{ total = 0 }) }) }
            )
            $items = @(foreach ($id in ($Body | ConvertFrom-Json).resourceids) { @{ resourceid = $id; value = $metrics } })
            [pscustomobject]@{ Content = (@{ values = $items } | ConvertTo-Json -Depth 10) }
        }
        $result = Get-IdleVMs -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' })
        $result.EvaluatedVMs | Should -Be 2
        $result.MetricFailures | Should -Be 0
        if ($Classification) {
            $result.Count | Should -Be 2
            $result.IdleVMs[0].Classification | Should -Be $Classification
        }
        else { $result.Count | Should -Be 0 }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 1 -Exactly
    }

    It 'Does not assume missing or failed batch metrics indicate an active VM' -ForEach @(
        @{ Case = 'missing VM' }
        @{ Case = 'resource error' }
        @{ Case = 'metric error' }
        @{ Case = 'missing measurements' }
    ) {
        $script:fixtureVMs = @($script:fixtureVMs | Select-Object -First 2)
        $failureCase = $Case
        Mock Invoke-WebRequest -ModuleName FinOpsMultitool {
            $items = @(
                foreach ($id in ($Body | ConvertFrom-Json).resourceids) {
                    if ($failureCase -eq 'missing VM') { continue }
                    $item = @{ resourceid = $id; value = @() }
                    if ($failureCase -eq 'resource error') { $item.errorCode = 'Forbidden' }
                    if ($failureCase -eq 'metric error') { $item.value = @(@{ errorCode = 'InvalidMetric' }) }
                    $item
                }
            )
            [pscustomobject]@{ Content = (@{ values = $items } | ConvertTo-Json -Depth 10) }
        }
        $result = Get-IdleVMs -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' })
        $result.EvaluatedVMs | Should -Be 0
        $result.MetricFailures | Should -Be 2
        $result.Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 1 -Exactly
    }
}
