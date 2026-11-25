# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

& "$PSScriptRoot/../Initialize-Tests.ps1"

Describe 'Storage tier batch metrics' {
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
        $script:fixtureAccounts = @(
            foreach ($i in 1..52) {
                [pscustomobject]@{
                    name = "storage$i"; subscriptionId = '11111111-1111-1111-1111-111111111111'; resourceGroup = 'fixture'
                    location = 'eastus'; accessTier = 'Hot'; sku = 'Standard_LRS'
                }
            }
        )
        Mock Search-AzGraphSafe -ModuleName FinOpsMultitool { @{ Data = $script:fixtureAccounts } }
        $script:transactions = 0
        $script:capacity = 10GB
        Mock Invoke-WebRequest -ModuleName FinOpsMultitool {
            $metrics = @(
                @{ name = @{ value = 'Transactions' }; timeseries = @(@{ data = @(@{ total = $script:transactions }) }) }
                @{ name = @{ value = 'BlobCapacity' }; timeseries = @(@{ data = @(@{ average = $script:capacity }) }) }
            )
            if ($Method -eq 'Post') {
                $items = @(foreach ($id in ($Body | ConvertFrom-Json).resourceids) { @{ resourceid = $id; value = $metrics } })
                [pscustomobject]@{ Content = (@{ values = $items } | ConvertTo-Json -Depth 10) }
            }
            else {
                $metric = if ($Uri -like '*metricnames=Transactions*') { $metrics[0] } else { $metrics[1] }
                [pscustomobject]@{ Content = (@{ value = @($metric) } | ConvertTo-Json -Depth 10) }
            }
        }
    }

    It 'Fetches both metrics in batches of 50 and reports progress with verbose <Enabled>' -ForEach @(
        @{ Enabled = $true }
        @{ Enabled = $false }
    ) {
        $output = @(Get-StorageTierAdvice -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }) -Verbose:$Enabled 4>&1)
        $result = $output | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] }
        $messages = @($output | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object Message)
        $result.EvaluatedAccounts | Should -Be 52
        $result.MetricFailures | Should -Be 0
        $result.Count | Should -Be 52
        $result.Recommendations[0].Recommendation | Should -Be 'Archive'
        if ($Enabled) {
            @($messages | Where-Object { $_ -match 'Storage metrics batch \[2/2\]' }).Count | Should -Be 2
            $messages | Should -Contain 'Storage metrics completed: 52/52 accounts evaluated; 0 failed'
        }
        else { $messages.Count | Should -Be 0 }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 2 -Exactly
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 1 -Exactly -ParameterFilter { ($Body | ConvertFrom-Json).resourceids.Count -eq 50 }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 1 -Exactly -ParameterFilter { ($Body | ConvertFrom-Json).resourceids.Count -eq 2 }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 0 -Exactly -ParameterFilter {
            $MaximumRedirection -ne 0 -or $Method -ne 'Post' -or
            $Uri -notlike '*metricnamespace=microsoft.storage%2Fstorageaccounts%2Fblobservices*' -or
            $Uri -notlike '*metricnames=Transactions%2CBlobCapacity*' -or
            $Uri -notlike '*aggregation=Total,Average&interval=FULL' -or
            @(($Body | ConvertFrom-Json).resourceids | Where-Object { $_ -notlike '*/blobServices/default' }).Count -gt 0 -or
            ([datetime]([uri]::UnescapeDataString($Uri) -replace '.*starttime=([^&]+).*', '$1')).ToUniversalTime().AddDays(30) -ne
                ([datetime]([uri]::UnescapeDataString($Uri) -replace '.*endtime=([^&]+).*', '$1')).ToUniversalTime()
        }
    }

    It 'Separates subscriptions and regions and handles singleton accounts' {
        $script:fixtureAccounts = @($script:fixtureAccounts | Select-Object -First 7)
        $script:fixtureAccounts[2].subscriptionId = '22222222-2222-2222-2222-222222222222'
        $script:fixtureAccounts[3].subscriptionId = '22222222-2222-2222-2222-222222222222'
        $script:fixtureAccounts[4].location = 'westeurope'
        $script:fixtureAccounts[5].location = 'westeurope'
        $script:fixtureAccounts[6].location = 'northeurope'
        $result = Get-StorageTierAdvice -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }, [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222' })
        $result.EvaluatedAccounts | Should -Be 7
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 3 -Exactly -ParameterFilter { $Method -eq 'Post' }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 2 -Exactly -ParameterFilter { $Method -eq 'Get' -and $Uri -like '*/storage7/*' }
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 0 -Exactly -ParameterFilter {
            $Method -eq 'Post' -and (
                @((($Body | ConvertFrom-Json).resourceids) | ForEach-Object { ($_ -split '/')[2] } | Select-Object -Unique).Count -ne 1 -or
                ($Uri -like '*eastus*' -and ($Body -match '/storage[56]/'))
            )
        }
    }

    It 'Matches metric names independently of response order' {
        $script:fixtureAccounts = @($script:fixtureAccounts | Select-Object -First 2)
        Mock Invoke-WebRequest -ModuleName FinOpsMultitool {
            $items = @(foreach ($id in ($Body | ConvertFrom-Json).resourceids) {
                @{
                    resourceid = $id
                    value = @(
                        @{ name = @{ value = 'BlobCapacity' }; timeseries = @(@{ data = @(@{ average = 10GB }) }) }
                        @{ name = @{ value = 'Transactions' }; timeseries = @(@{ data = @(@{ total = 500 }) }) }
                    )
                }
            })
            [pscustomobject]@{ Content = (@{ values = $items } | ConvertTo-Json -Depth 10) }
        }
        $result = Get-StorageTierAdvice -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' })
        $result.EvaluatedAccounts | Should -Be 2
        $result.Recommendations[0].Recommendation | Should -Be 'Cool'
        $result.Recommendations[0].Transactions30d | Should -Be 500
        $result.Recommendations[0].CapacityGB | Should -Be 10
    }

    It 'Does not acquire a batch token or request metrics for empty inventory' {
        $script:fixtureAccounts = @()
        $result = Get-StorageTierAdvice -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' })
        $result.EvaluatedAccounts | Should -Be 0
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 0 -Exactly
        Should -Invoke Get-PlainAccessToken -ModuleName FinOpsMultitool -Times 0 -Exactly -ParameterFilter { $ResourceUrl -eq 'https://metrics.monitor.azure.com/' }
    }

    It 'Preserves <Case> recommendations and output values across batch and fallback paths' -ForEach @(
        @{ Case = 'zero activity'; Transactions = 0; Capacity = 10GB; Recommendation = 'Archive' }
        @{ Case = 'low activity'; Transactions = 99; Capacity = 10GB; Recommendation = 'Archive' }
        @{ Case = 'cool threshold'; Transactions = 100; Capacity = 10GB; Recommendation = 'Cool' }
        @{ Case = 'active'; Transactions = 1000; Capacity = 10GB; Recommendation = $null }
        @{ Case = 'empty'; Transactions = 0; Capacity = 0; Recommendation = $null }
        @{ Case = 'small capacity'; Transactions = 500; Capacity = 1GB; Recommendation = $null }
    ) {
        $script:fixtureAccounts = @($script:fixtureAccounts | Select-Object -First 2)
        $script:transactions = $Transactions
        $script:capacity = $Capacity
        $subscriptions = @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' })
        $batch = Get-StorageTierAdvice -Subscriptions $subscriptions
        Mock Get-FinOpsArmEndpoint -ModuleName FinOpsMultitool { 'https://management.usgovcloudapi.net' }
        $fallback = Get-StorageTierAdvice -Subscriptions $subscriptions
        $batch.EvaluatedAccounts | Should -Be 2
        $fallback.EvaluatedAccounts | Should -Be 2
        ($batch | ConvertTo-Json -Depth 5) | Should -Be ($fallback | ConvertTo-Json -Depth 5)
        if ($Recommendation) {
            $batch.Count | Should -Be 2
            $batch.Recommendations[0].Recommendation | Should -Be $Recommendation
            $batch.Recommendations[0].Transactions30d | Should -Be $Transactions
            $batch.Recommendations[0].CapacityGB | Should -Be ($Capacity / 1GB)
        }
        else { $batch.Count | Should -Be 0 }
    }

    It 'Warns and preserves per-account fallback for <Case>' -ForEach @(
        @{ Case = 'batch request failure' }
        @{ Case = 'batch token failure' }
        @{ Case = 'duplicate resource response' }
        @{ Case = 'unexpected resource response' }
        @{ Case = 'malformed response' }
    ) {
        $script:fixtureAccounts = @($script:fixtureAccounts | Select-Object -First 2)
        $failureCase = $Case
        if ($Case -eq 'batch token failure') {
            Mock Get-PlainAccessToken -ModuleName FinOpsMultitool { throw 'Synthetic token failure.' } -ParameterFilter { $ResourceUrl -eq 'https://metrics.monitor.azure.com/' }
        }
        else {
            Mock Invoke-WebRequest -ModuleName FinOpsMultitool {
                switch ($failureCase) {
                    'batch request failure' { throw 'Synthetic batch failure.' }
                    'duplicate resource response' {
                        $id = ($Body | ConvertFrom-Json).resourceids[0]
                        [pscustomobject]@{ Content = (@{ values = @(@{ resourceid = $id }, @{ resourceid = $id }) } | ConvertTo-Json -Depth 5) }
                    }
                    'unexpected resource response' { [pscustomobject]@{ Content = '{"values":[{"resourceid":"/unexpected"}]}' } }
                    'malformed response' { [pscustomobject]@{ Content = '{}' } }
                }
            } -ParameterFilter { $Method -eq 'Post' }
        }
        $result = Get-StorageTierAdvice -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }) -WarningVariable warnings
        $result.EvaluatedAccounts | Should -Be 2
        $result.Count | Should -Be 2
        "$warnings" | Should -BeLike '*per-account requests*'
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 4 -Exactly -ParameterFilter { $Method -eq 'Get' }
    }

    It 'Leaves <Case> unevaluated without live request fan-out' -ForEach @(
        @{ Case = 'missing resource' }
        @{ Case = 'resource error' }
        @{ Case = 'metric error' }
        @{ Case = 'missing capacity' }
        @{ Case = 'duplicate metric' }
        @{ Case = 'null measurement' }
        @{ Case = 'negative transactions' }
        @{ Case = 'negative capacity' }
        @{ Case = 'invalid measurement' }
        @{ Case = 'rate limited' }
    ) {
        $script:fixtureAccounts = @($script:fixtureAccounts | Select-Object -First 2)
        $failureCase = $Case
        Mock Invoke-WebRequest -ModuleName FinOpsMultitool {
            if ($failureCase -eq 'rate limited') {
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
                throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Synthetic throttle.', $response)
            }
            $items = @(
                foreach ($id in ($Body | ConvertFrom-Json).resourceids) {
                    if ($failureCase -eq 'missing resource') { continue }
                    $metrics = @(
                        @{ name = @{ value = 'Transactions' }; timeseries = @(@{ data = @(@{ total = 0 }) }) }
                        @{ name = @{ value = 'BlobCapacity' }; timeseries = @(@{ data = @(@{ average = 10GB }) }) }
                    )
                    $item = @{ resourceid = $id; value = $metrics }
                    switch ($failureCase) {
                        'resource error' { $item.errorCode = 'Forbidden' }
                        'metric error' { $metrics[0].errorCode = 'InvalidMetric' }
                        'missing capacity' { $item.value = @($metrics[0]) }
                        'duplicate metric' { $item.value = @($metrics[0], $metrics[0], $metrics[1]) }
                        'null measurement' { $metrics[0].timeseries[0].data[0].total = $null }
                        'negative transactions' { $metrics[0].timeseries[0].data[0].total = -1 }
                        'negative capacity' { $metrics[1].timeseries[0].data[0].average = -1 }
                        'invalid measurement' { $metrics[1].timeseries[0].data[0].average = 'invalid' }
                    }
                    $item
                }
            )
            [pscustomobject]@{ Content = (@{ values = $items } | ConvertTo-Json -Depth 10) }
        }
        $result = Get-StorageTierAdvice -Subscriptions @([pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' })
        $result.EvaluatedAccounts | Should -Be 0
        $result.MetricFailures | Should -Be 2
        $result.Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -ModuleName FinOpsMultitool -Times 1 -Exactly
    }
}
