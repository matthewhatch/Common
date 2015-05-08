Import-Module fmg.powershell.common -Force
$cred = Get-Credential



Describe 'Get-ExpiringCertificate' {
    BeforeEach{
        Mock -ModuleName fmg.powershell.common Get-Certificate {
            $properties = @{
                Subject = 'CN=tokenencryption.svcsdev02.fmglobal.com, OU=IS, O=Factory Mutual, L=Johnston, S=RI, C=US'
                Thumbprint = '1607A73D50F98D0C506A2E5AB6488B5958D54A86'
                NotBefore = (Get-Date).AddYears(-2)
                NotAfter = (Get-Date).AddDays(60)
            }
            
            return (New-Object -TypeName PSObject -Property $properties)

        }   
    }
    
    It 'returns an object with the property certs' {
        (Get-Member -InputObject (Get-ExpiringCertificate)).Name -contains 'Certs' | Should Be $true
    }

    It 'returns an object with the property Count' {
        (Get-Member -InputObject (Get-ExpiringCertificate)).Name -contains 'Count' | Should Be $true   
    }

    It 'returns an object with an array of cert subjects' {
        (Get-ExpiringCertificate).Certs -contains 'CN=tokenencryption.svcsdev02.fmglobal.com, OU=IS, O=Factory Mutual, L=Johnston, S=RI, C=US' | Should Be $true
    }

    It 'returns one expiring cert' {
        (Get-ExpiringCertificate).Count | Should Be 1
    }

}

Describe 'Get-AccountFromSID' {
    It 'Converts a SID to an account' {
        $hatchm = Get-ADUser -Filter {Name -eq 'hatchm'}
        Get-AccountFromSID -SID $hatchm.SID | Should be 'Corp\hatchm'    
    }
}

Describe 'Get-CacheList' {
    $Parameters = (Get-Command Get-CacheList).Parameters
    
    $caches = Get-CacheList -ComputerName johncachd01 -Credential $Cred
    It 'Accepts ComputerName as a parameter' {
        $Parameters.ContainsKey('ComputerName') | Should Be $true
    }

    It 'Accepts Credential as Parameter'{
        $Parameters.ContainsKey('Credential') | Should Be $true
    }

    It 'returns a string object'{
        $caches.GetType().Name | Should Be 'Object[]'
    }

    It 'Returns at least one object with the name of the cache'{
        [String]::IsNullOrEmpty($caches) | Should Be $false
    }
}

Describe 'Get-MaintResp' {
    
    Mock -CommandName Invoke-Command -ModuleName fmg.powershell.common{
        $properties = @{
            MaintResp = 'carrolljem'
        }
        Write-Output (New-Object -TypeName PSObject -Property $properties)
    }

    It 'Accepts ComputerName as parameter'{
        $parameters = (Get-Command Get-MaintResp).Parameters
        $parameters.ContainsKey('ComputerName') | Should Be $true
    }

    It 'Returns carroljem as maintResp' {
        (Get-MaintResp -ComputerName 'someserver').MaintResp | Should Be 'carrolljem'
    }

    It 'Calls Invoke-Command once' {
        Assert-MockCalled -CommandName Invoke-Command -ModuleName fmg.powershell.common -Exactly 1
    }
}

Describe 'Get-EnvironmentSetting'{
    
    Mock -ModuleName fmg.powershell.common Invoke-Command{
        [xml]$xml = '<?xml version="1.0" encoding="utf-8"?><EnvironmentSettings><Tokens><Token name="TestToken" Value="TestValue"></Token></Tokens></EnvironmentSettings>'
        return $xml
    }

    $result = Get-EnvironmentSetting -ComputerName 'johnsvcsd01' -Credential $Cred
    $parameters = (Get-Command Get-EnvironmentSetting).Parameters

    It 'should return Custom Object'{
        $result.GetType().Name | Should Be 'PSCustomObject'
    } 

    It 'Should Accept Credential as a parameter'{
        $parameters.ContainsKey('Credential') | Should Be $true   
    }

    It 'Should Accept ComputerName as a parameter'{
        $parameters.ContainsKey('ComputerName') | Should Be $true
    }

    It 'Should Accept Key as parameter'{
        $parameters.ContainsKey('Key') | Should Be $true
    }
    
    It 'Should Accept Value as Parameter'{
        $parameters.ContainsKey('Value') | Should Be $true
    }

    It 'Should accept Framework as parameter'{
        $parameters.ContainsKey('Framework') | Should Be $true
    }

    It 'Should accept FileName as a parameter'{
        $parameters.ContainsKey('FileName') | Should Be $true
    }

    It 'Calls Invoke Command once'{
        Assert-MockCalled -ModuleName fmg.powershell.common Invoke-Command -Exactly 1
    }
    
    It 'Should return a name that is TestToken'{
        $result.Name | Should Be 'TestToken'
    }

    It 'should return a value with TestValue'{
        $result.Value | Should Be 'testValue'
    }
}

Describe 'Set-EnvironmentSetting'{
    $params = (Get-Command Set-EnvironmentSetting).Parameters

    It 'Should accept Value as parameter'{
        $params.ContainsKey('Value') | Should Be $true
    }

    It 'Should accept key as a parameter'{
        $params.ContainsKey('key') | Should Be $true
    }

    It 'Should accept FrameworkFolder as a parameter'{
        $params.ContainsKey('FrameworkFolder') | Should Be $true
    }

    It 'Should accept FileName as a parameter'{
        $params.ContainsKey('FileName') | Should Be $true
    }

    It 'Should accept computername as a parameter'{
        $params.ContainsKey('ComputerName') | Should Be $true
    }

    It 'should accept credential as a parameter'{
        $params.ContainsKey('Credential') | Should Be $true
    }

    Context 'Local Test'{
        $BackupPath = 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\CONFIG\EnvironmentSettings_backup.xml'
        $RestorePath = 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\CONFIG\EnvironmentSettings.xml'
        Set-EnvironmentSetting -Key 'Eng.Data.ServiceURL.SecurityService' -value 'sometest' -FrameworkFolder 'v2' -FileName 'EnvironmentSettings.xml'

        It 'Should update EnvironmentSettings.xml file with new value'{
            (Get-EnvironmentSetting -Key 'Eng.Data.ServiceURL.SecurityService').Value | Should Be 'sometest'
        } 
        
        It 'Should work with $ in the key' {
            Set-EnvironmentSetting -Key '$Eng.Data.ServiceURL.SecurityService$' -value 'DollarSignTest' -FrameworkFolder 'v2' -FileName 'EnvironmentSettings.xml'    
            (Get-EnvironmentSetting -Key '$Eng.Data.ServiceURL.SecurityService$').Value | Should Be 'DollarSignTest'
        }

        It 'Should create a backup file' {
            $backup = Get-Item $BackupPath -ErrorAction SilentlyContinue
            $backup | should not be $null
        } 

        #Restore
        Copy-Item $BackupPath $RestorePath | Out-Null
    }

    Context 'Remote Test'{
        Mock Invoke-Command -ModuleName fmg.powershell.common {
            return 'Updated remote environment settings'
        }

        Set-EnvironmentSetting -Computername 'johndscx04' -Key 'Eng.Data.ServiceURL.SecurityService'`
         -value 'sometest'`
         -FrameworkFolder 'v2'`
         -FileName 'EnvironmentSettings.xml'`
         -Credential $cred   
         
         It 'should call Invoke-Command'{
            Assert-MockCalled Invoke-Command -ModuleName fmg.powershell.common -Exactly 1   
         }     
    }
}

Describe 'Restore-EnvironmentSetting'{
    $params = (Get-Command -Name Restore-EnvironmentSetting).Parameters

    It 'accepts parameter FrameworkFolder'{
        $params.ContainsKey('FrameworkFolder') | Should Be $true
    }

    It 'accepts parameter FileName'{
        $params.ContainsKey('FileName') | Should Be $true
    }

    It 'Accepts ComputerName as a parameter'{
        $params.ContainsKey('ComputerName') | Should Be $true
    }

    It 'Accepts Credential as a parameter' {
        $params.ContainsKey('Credential') | Should Be $true
    }

    Context 'Local Restore'{
        It 'Should Restore Environment Settings from backup'{
            $originalSetting = (Get-EnvironmentSetting -Key 'Eng.Data.ServiceURL.SecurityService').Value
            Set-EnvironmentSetting -Key 'Eng.Data.ServiceURL.SecurityService' -Value 'Test'
            Restore-EnvironmentSetting
            (Get-EnvironmentSetting -key 'Eng.Data.ServiceURL.SecurityService').Value | Should Be $originalSetting
        }
    }

    Context 'Remote Restore'{
        Mock Invoke-Command -ModuleName fmg.powershell.common {
            return 'called invoke command'
        }

        Restore-EnvironmentSetting -ComputerName 'johndscx04' -Credential $cred

        It 'Should call Invoke-Command'{
            Assert-MockCalled Invoke-Command -ModuleName fmg.powershell.common -Exactly 1
        }
    }
}

Describe 'Get-MaintenanceMode'{

}