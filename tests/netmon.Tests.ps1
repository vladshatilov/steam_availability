#Requires -Version 7.4
# Pester 5: Invoke-Pester .\tests
# Скрипт подключается через dot-source: определяет функции, но ничего не запускает (см. конец netmon.ps1)

BeforeAll {
    $script:TestOut = Join-Path ([IO.Path]::GetTempPath()) ('netmon-tests-' + [guid]::NewGuid())
    . (Join-Path $PSScriptRoot '..\netmon.ps1') -OutDir $script:TestOut

    function New-TestCheck([string]$Cat, [string]$Target = 'x', [bool]$Ok = $true, [string]$Err = '') {
        [pscustomobject]@{ Cat = $Cat; Target = $Target; Ok = $Ok; Err = $(if ($Ok) { '' } elseif ($Err) { $Err } else { 'timeout' }) }
    }

    function New-HealthyChecks {
        @(
            New-TestCheck 'GW' '192.168.1.254'
            New-TestCheck 'ISP' '100.89.0.1'
            New-TestCheck 'DNS' 'ya.ru'
            New-TestCheck 'RU_PING' '77.88.8.8'
            New-TestCheck 'RU_PING' '77.88.8.1'
            New-TestCheck 'INTL_PING' '1.1.1.1'
            New-TestCheck 'INTL_PING' '8.8.8.8'
            New-TestCheck 'RU_HTTP' 'https://ya.ru/'
            New-TestCheck 'INTL_HTTP' 'https://www.google.com/generate_204'
            New-TestCheck 'CF_HTTP' 'https://www.cloudflare.com/cdn-cgi/trace'
            New-TestCheck 'CF_BIG' 'https://speed.cloudflare.com/__down?bytes=262144'
            New-TestCheck 'STEAM_HTTP' 'https://store.steampowered.com/'
            New-TestCheck 'STEAM_HTTP' 'https://api.steampowered.com/ISteamWebAPIUtil/GetServerInfo/v1/'
            New-TestCheck 'STEAM_CM' 'cmp1-sto1.steamserver.net:27022'
        )
    }

    function Set-Failed($Checks, [string]$Cat, [string]$Err = 'timeout', [string]$Target = '') {
        foreach ($chk in $Checks | Where-Object { $_.Cat -eq $Cat -and (-not $Target -or $_.Target -eq $Target) }) {
            $chk.Ok = $false
            $chk.Err = $Err
        }
        return $Checks
    }
}

AfterAll {
    Remove-Item $script:TestOut -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Get-Verdict' {
    It 'всё прошло -> OK' {
        (Get-Verdict -Checks (New-HealthyChecks)).Verdict | Should -Be 'OK'
    }

    It 'линк не Up -> LINK_DOWN' {
        (Get-Verdict -Checks (New-HealthyChecks) -Link 'Disconnected').Verdict | Should -Be 'LINK_DOWN'
    }

    It 'нет маршрута -> LINK_DOWN' {
        (Get-Verdict -Checks (New-HealthyChecks) -HasRoute $false).Verdict | Should -Be 'LINK_DOWN'
    }

    It 'роутер молчит -> LAN_ROUTER' {
        (Get-Verdict -Checks (Set-Failed (New-HealthyChecks) 'GW')).Verdict | Should -Be 'LAN_ROUTER'
    }

    It 'РФ и зарубеж лежат, хоп провайдера жив -> PROVIDER_UPSTREAM' {
        $checks = New-HealthyChecks
        foreach ($cat in 'RU_PING', 'INTL_PING', 'RU_HTTP') { $checks = Set-Failed $checks $cat }
        (Get-Verdict -Checks $checks).Verdict | Should -Be 'PROVIDER_UPSTREAM'
    }

    It 'РФ и зарубеж лежат, хоп провайдера тоже -> PROVIDER_EDGE' {
        $checks = New-HealthyChecks
        foreach ($cat in 'ISP', 'RU_PING', 'INTL_PING', 'RU_HTTP') { $checks = Set-Failed $checks $cat }
        (Get-Verdict -Checks $checks).Verdict | Should -Be 'PROVIDER_EDGE'
    }

    It 'хоп провайдера не пингуется в принципе -> PROVIDER' {
        $checks = @(New-HealthyChecks | Where-Object Cat -NE 'ISP')
        foreach ($cat in 'RU_PING', 'INTL_PING', 'RU_HTTP') { $checks = Set-Failed $checks $cat }
        (Get-Verdict -Checks $checks -IspPingable $false).Verdict | Should -Be 'PROVIDER'
    }

    It 'DNS не резолвит, ping РФ идёт -> DNS' {
        (Get-Verdict -Checks (Set-Failed (New-HealthyChecks) 'DNS' 'dns:timeout')).Verdict | Should -Be 'DNS'
    }

    It 'зарубеж лежит, РФ работает -> INTL_DOWN' {
        $checks = Set-Failed (Set-Failed (New-HealthyChecks) 'INTL_PING') 'INTL_HTTP'
        (Get-Verdict -Checks $checks).Verdict | Should -Be 'INTL_DOWN'
    }

    It 'Cloudflare не открывается -> CF_DOWN без LOSS' {
        $checks = Set-Failed (Set-Failed (New-HealthyChecks) 'CF_HTTP' 'tls_reset') 'CF_BIG' 'tls_reset'
        (Get-Verdict -Checks $checks).Verdict | Should -Be 'CF_DOWN'
    }

    It '256 КБ зависли после 16 КБ -> CF_THROTTLE' {
        (Get-Verdict -Checks (Set-Failed (New-HealthyChecks) 'CF_BIG' 'timeout@16384')).Verdict | Should -Be 'CF_THROTTLE'
    }

    It '256 КБ упали с tls (не таймаут), разово -> не CF_THROTTLE и не LOSS' {
        (Get-Verdict -Checks (Set-Failed (New-HealthyChecks) 'CF_BIG' 'tls')).Verdict | Should -Be 'OK'
    }

    It 'CM недоступны + замедление CF -> CF_THROTTLE+STEAM_CM' {
        $checks = Set-Failed (Set-Failed (New-HealthyChecks) 'CF_BIG' 'timeout@16384') 'STEAM_CM' 'reset'
        (Get-Verdict -Checks $checks).Verdict | Should -Be 'CF_THROTTLE+STEAM_CM'
    }

    It 'весь Steam лежит -> STEAM_ALL' {
        $checks = Set-Failed (Set-Failed (New-HealthyChecks) 'STEAM_CM') 'STEAM_HTTP'
        (Get-Verdict -Checks $checks).Verdict | Should -Be 'STEAM_ALL'
    }

    It 'только web Steam -> STEAM_WEB' {
        (Get-Verdict -Checks (Set-Failed (New-HealthyChecks) 'STEAM_HTTP')).Verdict | Should -Be 'STEAM_WEB'
    }

    It 'IPv6 лежит при живом IPv4 -> IPV6' {
        $checks = @(New-HealthyChecks) + @(New-TestCheck 'IPV6' '2001:4860:4860::8888' $false)
        (Get-Verdict -Checks $checks).Verdict | Should -Be 'IPV6'
    }

    Context 'шум: LOSS' {
        It 'одиночный таймаут 8.8.8.8 -> OK, но запоминается' {
            $judged = Get-Verdict -Checks (Set-Failed (New-HealthyChecks) 'INTL_PING' 'timedout' '8.8.8.8')
            $judged.Verdict | Should -Be 'OK'
            $judged.Unexplained | Should -Be @('INTL_PING|8.8.8.8')
        }

        It 'тот же таймаут второй цикл подряд -> LOSS' {
            $checks = Set-Failed (New-HealthyChecks) 'INTL_PING' 'timedout' '8.8.8.8'
            (Get-Verdict -Checks $checks -PrevUnexplained @('INTL_PING|8.8.8.8')).Verdict | Should -Be 'LOSS'
        }

        It 'другая проверка во втором цикле -> не LOSS' {
            $checks = Set-Failed (New-HealthyChecks) 'INTL_PING' 'timedout' '8.8.8.8'
            (Get-Verdict -Checks $checks -PrevUnexplained @('INTL_PING|1.1.1.1')).Verdict | Should -Be 'OK'
        }

        It 'две разные проверки в одном цикле -> LOSS' {
            $checks = Set-Failed (Set-Failed (New-HealthyChecks) 'INTL_PING' 'timedout' '8.8.8.8') 'RU_HTTP' 'reset'
            (Get-Verdict -Checks $checks).Verdict | Should -Be 'LOSS'
        }

        It 'объяснённые флагом сбои в LOSS не идут' {
            $checks = Set-Failed (New-HealthyChecks) 'STEAM_CM' 'reset'
            $judged = Get-Verdict -Checks $checks -PrevUnexplained @('STEAM_CM|cmp1-sto1.steamserver.net:27022')
            $judged.Verdict | Should -Be 'STEAM_CM'
            $judged.Unexplained | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-ShortError' {
    It 'SocketException ConnectionReset -> reset (независимо от языка текста)' {
        Get-ShortError ([System.Net.Sockets.SocketException]::new(10054)) | Should -Be 'reset'
    }

    It 'обрыв внутри TLS-рукопожатия -> tls_reset' {
        $inner = [IO.IOException]::new('Unable to read data', [System.Net.Sockets.SocketException]::new(10054))
        $ex = [System.Net.Http.HttpRequestException]::new([System.Net.Http.HttpRequestError]::SecureConnectionError, 'SSL failed', $inner)
        Get-ShortError $ex | Should -Be 'tls_reset'
    }

    It 'ошибка сертификата без сокета -> tls' {
        $inner = [System.Security.Authentication.AuthenticationException]::new('Ошибка проверки сертификата')
        $ex = [System.Net.Http.HttpRequestException]::new([System.Net.Http.HttpRequestError]::SecureConnectionError, 'SSL failed', $inner)
        Get-ShortError $ex | Should -Be 'tls'
    }

    It 'таймаут HttpClient -> timeout' {
        $ex = [System.Threading.Tasks.TaskCanceledException]::new('canceled', [TimeoutException]::new())
        Get-ShortError $ex | Should -Be 'timeout'
    }

    It 'ConnectionRefused -> refused' {
        Get-ShortError ([System.Net.Sockets.SocketException]::new(10061)) | Should -Be 'refused'
    }

    It 'NameResolutionError -> dns' {
        $ex = [System.Net.Http.HttpRequestException]::new([System.Net.Http.HttpRequestError]::NameResolutionError, 'Этот хост неизвестен')
        Get-ShortError $ex | Should -Be 'dns'
    }

    It 'неизвестная ошибка -> тип и обрезанный текст' {
        $result = Get-ShortError ([InvalidOperationException]::new('x' * 200))
        $result | Should -BeLike 'InvalidOperationException: x*'
        $result.Length | Should -Be 80
    }
}

Describe 'Select-SteamCmEndpoints' {
    BeforeAll {
        $script:FarOnly = @(
            [pscustomobject]@{ endpoint = 'cmp1-dfw2.steamserver.net:443'; type = 'websockets'; dc = 'dfw2' }
            [pscustomobject]@{ endpoint = 'cmp2-hkg1.steamserver.net:27025'; type = 'websockets'; dc = 'hkg1' }
            [pscustomobject]@{ endpoint = '103.10.124.122:27017'; type = 'netfilter'; dc = 'sgp1' }
        )
        $script:Mixed = @(
            [pscustomobject]@{ endpoint = 'cmp1-sto1.steamserver.net:27022'; type = 'websockets'; dc = 'sto2' }
            [pscustomobject]@{ endpoint = 'cmp2-sto1.steamserver.net:27022'; type = 'websockets'; dc = 'sto2' }
            [pscustomobject]@{ endpoint = 'cmp1-fra1.steamserver.net:443'; type = 'websockets'; dc = 'fra1' }
            [pscustomobject]@{ endpoint = 'cmp1-ams1.steamserver.net:443'; type = 'websockets'; dc = 'ams1' }
            [pscustomobject]@{ endpoint = 'cmp1-lhr1.steamserver.net:443'; type = 'websockets'; dc = 'lhr1' }
            [pscustomobject]@{ endpoint = 'cmp1-dfw2.steamserver.net:443'; type = 'websockets'; dc = 'dfw2' }
            [pscustomobject]@{ endpoint = '155.133.252.40:27017'; type = 'netfilter'; dc = 'fra1' }
            [pscustomobject]@{ endpoint = '155.133.252.41:27017'; type = 'netfilter'; dc = 'fra1' }
            [pscustomobject]@{ endpoint = '155.133.252.42:27017'; type = 'netfilter'; dc = 'fra1' }
        )
    }

    It 'только дальние DC -> пусто (уйдём в кэш/fallback)' {
        @(Select-SteamCmEndpoints $script:FarOnly $Cfg.SteamCmDcs) | Should -HaveCount 0
    }

    It 'берёт до 3 websockets из разных ближних DC и до 2 netfilter' {
        $selected = Select-SteamCmEndpoints $script:Mixed $Cfg.SteamCmDcs
        $selected | Should -HaveCount 5
        @($selected | Where-Object type -EQ 'websockets' | Select-Object -ExpandProperty dc -Unique) | Should -HaveCount 3
        $selected.endpoint | Should -Not -Contain 'cmp1-dfw2.steamserver.net:443'
    }

    It 'кэш старого формата (просто строки) отбрасывается' {
        @(Select-SteamCmEndpoints @('cmp1-dfw2.steamserver.net:443') $Cfg.SteamCmDcs) | Should -HaveCount 0
    }
}

Describe 'Get-TraceTargets' {
    BeforeAll {
        $script:Ctx = [pscustomobject]@{ Gateway = '192.168.1.254' }
    }

    It 'LOSS трассирует то, что не прошло, а не 8.8.8.8' {
        $checks = Set-Failed (Set-Failed (New-HealthyChecks) 'STEAM_HTTP' 'timeout' 'https://api.steampowered.com/ISteamWebAPIUtil/GetServerInfo/v1/') 'DNS' 'dns:timeout'
        $targets = Get-TraceTargets 'LOSS' $checks $script:Ctx
        @($targets.Keys) | Should -Be @('api.steampowered.com')
    }

    It 'CF_THROTTLE -> speed.cloudflare.com' {
        $targets = Get-TraceTargets 'CF_THROTTLE' (Set-Failed (New-HealthyChecks) 'CF_BIG' 'timeout@16384') $script:Ctx
        @($targets.Keys) | Should -Be @('speed.cloudflare.com')
    }

    It 'STEAM_CM -> хост CM без порта' {
        $targets = Get-TraceTargets 'STEAM_CM' (Set-Failed (New-HealthyChecks) 'STEAM_CM' 'reset') $script:Ctx
        @($targets.Keys) | Should -Be @('cmp1-sto1.steamserver.net')
    }

    It 'не больше TracesPerFlag целей на флаг' {
        $checks = Set-Failed (Set-Failed (New-HealthyChecks) 'STEAM_HTTP') 'STEAM_CM'
        $checks += New-TestCheck 'STEAM_HTTP' 'https://steamcommunity.com/' $false
        @((Get-TraceTargets 'STEAM_ALL' $checks $script:Ctx).Keys) | Should -HaveCount $Cfg.TracesPerFlag
    }

    It 'LAN_ROUTER -> шлюз, PROVIDER -> 77.88.8.8' {
        @((Get-TraceTargets 'LAN_ROUTER' @() $script:Ctx).Keys) | Should -Be @('192.168.1.254')
        @((Get-TraceTargets 'PROVIDER_EDGE' @() $script:Ctx).Keys) | Should -Be @('77.88.8.8')
    }
}

Describe 'Get-Incidents' {
    BeforeAll {
        function New-TestRow([string]$Time, [string]$Verdict) {
            [pscustomobject]@{ Ts = [datetime]::ParseExact($Time, 'HH:mm:ss', $null); Verdict = $Verdict; Fails = '' }
        }
    }

    It 'инцидент, прерванный дырой в данных, получает конец (не отрицательную длительность)' {
        $rows = @(
            New-TestRow '10:00:00' 'OK'
            New-TestRow '10:00:15' 'STEAM_CM'
            New-TestRow '10:00:30' 'STEAM_CM'
            New-TestRow '10:30:00' 'OK'
        )
        $incidents = Get-Incidents $rows 60
        $incidents | Should -HaveCount 2
        $incidents[0].Verdict | Should -Be 'STEAM_CM'
        $incidents[0].End | Should -Be $rows[2].Ts
        $incidents[0].Cycles | Should -Be 2
        $incidents[1].Verdict | Should -Be 'NO_DATA'
        foreach ($incident in $incidents) { ($incident.End - $incident.Start).TotalSeconds | Should -BeGreaterOrEqual 0 }
    }

    It 'смена вердикта закрывает предыдущий инцидент' {
        $rows = @(
            New-TestRow '10:00:00' 'CF_THROTTLE'
            New-TestRow '10:00:15' 'CF_THROTTLE+STEAM_CM'
            New-TestRow '10:00:30' 'OK'
        )
        $incidents = Get-Incidents $rows 60
        $incidents.Verdict | Should -Be @('CF_THROTTLE', 'CF_THROTTLE+STEAM_CM')
        $incidents[0].End | Should -Be $rows[1].Ts
        $incidents[1].End | Should -Be $rows[2].Ts
    }

    It 'незакрытый инцидент в конце заканчивается последним циклом' {
        $rows = @(New-TestRow '10:00:00' 'LOSS'; New-TestRow '10:00:15' 'LOSS')
        $incidents = Get-Incidents $rows 60
        $incidents | Should -HaveCount 1
        $incidents[0].End | Should -Be $rows[1].Ts
    }
}

Describe 'Test-RouteChanged' {
    It 'тот же адаптер и шлюз -> false' {
        $ctx = [pscustomobject]@{ IfIndex = 20; Gateway = '192.168.1.254' }
        Test-RouteChanged $ctx ([pscustomobject]@{ IfIndex = 20; Gateway = '192.168.1.254' }) | Should -BeFalse
    }

    It 'другой адаптер -> true' {
        $ctx = [pscustomobject]@{ IfIndex = 20; Gateway = '192.168.1.254' }
        Test-RouteChanged $ctx ([pscustomobject]@{ IfIndex = 7; Gateway = '192.168.1.254' }) | Should -BeTrue
    }

    It 'маршрута нет -> false (это LINK_DOWN, а не смена маршрута)' {
        Test-RouteChanged ([pscustomobject]@{ IfIndex = 20; Gateway = 'x' }) $null | Should -BeFalse
    }
}

Describe 'Save-CycleRow' {
    It 'при смене набора колонок откладывает старый файл, а не падает' {
        $csv = Join-Path $script:TestOut 'cycles_20261126.csv'
        Set-Content $csv '"Time","Verdict"' -Encoding utf8
        $row = [pscustomobject]@{ Time = '2026-11-26 12:00:00'; Verdict = 'OK'; IPV6 = '-' }
        Save-CycleRow $row
        (Get-Content $csv -TotalCount 1) | Should -Be '"Time","Verdict","IPV6"'
        @(Get-ChildItem $script:TestOut -Filter 'cycles_20261126_old_*.csv') | Should -HaveCount 1
    }
}
