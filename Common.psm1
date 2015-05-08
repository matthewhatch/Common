<#
    .Synopsis 
        Gets Environment Settings
    
    .Description
        Gets the Environment Tokens from the EnvrinmentSettings.xml file
        The Default location is c:\windows\Microsoft.Net\v2.0.50727.
        This can be overridden using parameter set by passing in the FRamework Version, and the name of the settings file

    .Parameter ComputerName
        Name of the target server

    .Parameter FrameworkFolder
        The Framework folder that should be part of the path to the Configuration file
        This defaults to v2.0.50727

    .Parameter FileName
        The Name of the configuration file.
        this defaults to EnvironmentSettings.xml

    .Parameter Credential
        The Credential of the user making the request

    .Parameter Key
        Key to search for in the settings file... this can match multiple values returned
    
    .Parameter Value
        Value to search for in the settings file... uses the match operator so mutiple results can be returned

#>
function Get-EnvironmentSetting{
    [CmdletBinding()]
    param(
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [PSCredential]$Credential,

        [ValidateSet('v2','v4')]
        [string]$Framework = 'v2',

        [string]$Key,

        [string]$Value,

        [string]$FileName = 'EnvironmentSettings.xml'
    )

    #Map Version to folder name
    switch($Framework){
        'v2'{
            $FrameworkFolder = 'v2.0.50727'
            break
        }
        'v4'{
            $FrameworkFolder = 'v4.0.30319'
            break
        }
    }

    #replace $ in tokens
    $Key = $key.Replace('$','')

    $GetContentBlock = {
        param(
            $FrameworkFolder,
            $FileName
        )
        Get-Content "C:\Windows\Microsoft.NET\Framework\$FrameworkFolder\CONFIG\$FileName"   
    }

    foreach($Computer in $ComputerName){        

        if($Computer -eq $env:COMPUTERNAME){
            [xml]$Content = Get-Content "C:\Windows\Microsoft.NET\Framework\$FrameworkFolder\CONFIG\$FileName"     
        }
        else{
            if(-not($PSBoundParameters.ContainsKey('Credential')) -and ($null -eq $Credential)){$Credential = Get-Credential}
            Write-Verbose "Connecting to $Computer"
            [xml]$Content = Invoke-Command -Credential $Credential -ComputerName $Computer -ScriptBlock $GetContentBlock -ArgumentList $FrameworkFolder,$FileName
        }

        $results = $Content.EnvironmentSettings.Tokens.Token
        
        if($PSBoundParameters.ContainsKey('Key')){
            $results = $results | Where-Object {$_.name -match $key}
        }

        if($PSBoundParameters.ContainsKey('Value')){
            $results = $results | Where-Object {$_.value -match $Value}
        }
            
        Write-Output $results | Select-Object Name,Value,@{Name='ConfigurationFile';Expression={$FileName}},@{Name='Computername';expression={$Computer}}
    }       
}

<#
    .Synopsis
        Updates Environment Settings
    .Description
        Updates a Token in an environment settings file
    .PARAMETER Key
        Token to replace
    .PARAMETER Value
       Updated Value
    .PARAMETER FrameWorkFolder
        Version of the frame work, this is used to determine the path.
        Default Value is v2, whic maps to v2.0.50727
    .PARAMETER FileName
        Environment Settings file name, defaults to EnvironmentSettings.xml. 

#>
Function Set-EnvironmentSetting{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,

        [PSCredential]$Credential,

        [Parameter(Mandatory=$true)]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [string]$Value,

        [ValidateSet('v2','v4')]
        [string]$FrameworkFolder = 'v2',

        [string]$FileName = 'EnvironmentSettings.xml'
    )  
    
    #Map the Framework Version to the folder name
    Switch($FrameworkFolder){
        'v2'{
            $Version = 'v2.0.50727'
            break
        }
        'v4'{
            $Version = 'v4.0.30319'
            break
        }
    }
    
    $SKey = $Key.Replace('$','')
    $Path = "C:\Windows\Microsoft.NET\Framework\$Version\CONFIG\$FileName"
    $BackupFileName = $FileName.Insert($FileName.IndexOf('.'),'_backup')
    $BackupPath = "C:\Windows\Microsoft.NET\Framework\$Version\CONFIG\$BackupFileName"

    if($ComputerName -eq $env:COMPUTERNAME){
       
        Copy-Item $path $BackupPath | Out-Null
        try{       
            [xml]$Settings = Get-Content $Path

            $Token = $Settings.EnvironmentSettings.Tokens.Token | where-object {$_.Name -match $SKey}

            if($PSCmdlet.ShouldProcess("$Key to $Value")){
                $Token.value = $Value
                $settings.Save($Path)
            }
        }
        catch{
            Write-Warning "There was an issue updating $Key to $Value in $FileName on $ComputerName"
        }
    }
    else{
        if(-not($PSBoundParameters.ContainsKey('Credential'))){$Credential = Get-Credential}

        $UpdateBlock = {
            param(
                $path,$backuppath,$skey,$value
            )

            Copy-Item $path $BackupPath | Out-Null
 
            [xml]$Settings = Get-Content $Path
            $Token = $Settings.EnvironmentSettings.Tokens.Token | where-object {$_.Name -match $SKey}
            $Token.Value = $Value
            $settings.Save($Path)
        }
        try{
            if($PSCmdlet.ShouldProcess("$key to $Value")){
                Invoke-Command -ComputerName $ComputerName -ScriptBlock $UpdateBlock -Credential $Credential -ArgumentList $Path,$BackupPath,$sKey,$Value
            }
        }
        catch{
            Write-Warning "there was an issue updating $key to $Value in $FileName on $ComputerName"
        }
    }
}

<#
    .Synopsis
        Restore Environment Settings from the last update
    .Description
        Restores the environment settings from the EnvironmentSettings_backup.xml file by default.
        If a custom EnvironmentSettings file is input then the value is restored from that file.
    .Parameter ComputerName
        The target node
    .Parameter FrameworkFolder
        The version of the .NET framework that corresponds to where the Configuration file is stored in
        c:\Windows\Microsoft.NET\Framework.  
    .Parameter FileName
        The Environment Settings configuration file to be restored to. The default value is EnvironmentSettings.xml
        The file that will be used to get the previous backups will have _backups appended to the name of the file
        So by default the restore file is EnvironmentSettings_backup.xml.  If the FileName parameter is used, the restore file will be 
        $filname_backup.xml
    .Example
        Restore-EnvironmentSetting -ComputerName Server01
    .Example
        $Cred = Get-Credential
        c:\PS>Restore-EnvironmentSetting -ComputerName Server01 -Credential $Cred
    .Example
        $Cred = Get-Credential
        c:\PS>Restore-EnvironmentSetting -ComputerName Server01,Server02 -Credential $Cred
    .Example
        
        $cred = Get-Credential
        c:\PS>Restore-EnvironmentSetting -ComputerName Server01 -Credential $Cred -FileName 'EnvrionmentSettings00001.xml'

        To restore Settings from EnvironmentSettings00001_backup.xml to EnvironmentSettings00001.xml
        
#>
Function Restore-EnvironmentSetting{
    [CmdletBinding()]
    param(
        [string]$ComputerName,

        [PSCredential]$Credential,

        [ValidateSet('v2','v4')]
        [string]$FrameworkFolder = 'v2',

        [string]$FileName = 'EnvironmentSettings.xml'
    )
    
    #Map the Framework Version to the folder name
    Switch($FrameworkFolder){
        'v2'{
            $Version = 'v2.0.50727'
            break
        }
        'v4'{
            $Version = 'v4.0.30319'
            break
        }
    }
    
    $BackUpFile = $FileName.Insert($FileName.IndexOf('.'),'_backup')
    $Path = "C:\Windows\Microsoft.NET\Framework\$Version\CONFIG\$FileName"
    $BackUp = "C:\Windows\Microsoft.NET\Framework\$Version\CONFIG\$BackUpFile"
    
    if($PSBoundParameters.ContainsKey('ComputerName')){
        $CopyBlock = {
            param($BackUp,$Path)
            Copy-Item -Path $BackUp -Destination $Path
        }

        if(-not($PSBoundParameters.ContainsKey('Credential'))){$Credential = Get-Credential}
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $CopyBlock -ArgumentList $BackUp,$Path

    }
    else{
        Copy-Item -Path $BackUp -Destination $Path
    }    
}

<#
    .SYNOPSIS
    Retrieve all Certificates expiring within 60 days

    .DESCRIPTION
    Retreives all Certificates from the localmachine personal store that are
    Expiring in the next 60 days by default

#>
function Get-ExpiringCertificate {
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )
    BEGIN{}
    PROCESS{
        $ExpiringCertificates = Get-Certificate | Where-Object {(Get-Date) -ge ($_.NotAfter).AddDays(-60)} #Get Certificates that are expiring in the next 60 days
    
        $Certs = @()
        Foreach($cert in $ExpiringCertificates){
            $Certs += $cert.subject
        }
    
        $properties = @{
            Certs = $Certs
            Count = $Certs.Count
        }

        New-Object -TypeName PSObject -Property $properties
    }
    END{}
}

<#
    .SYNOPSIS
    Retrieve Account associated with SID

    .DESCRITPION 
    Retrieve AD account associated with SID. This is helpful when there are unresolved SIDs

    .PARAMETER SID

    .EXAMPLE

    Get-AccountFromSID -SID S-1-5-21-1923829527-1199921263-570957409-79149
#>
function Get-AccountFromSID{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    try{
        $objSID = New-Object System.Security.Principal.SecurityIdentifier ($SID)
        $User = $objSID.Translate( [System.Security.Principal.NTAccount])
        Write-Output $User
    }
    catch{
        Write-Warning "There was a problem retrieving the account associated with $SID, it may not be in Active Directory"
    }

}

function Get-CacheList{
    <#
        .SYNOPSIS
        Return the list of caches from remote server

        .DESCRIPTION
        Return the list of ncache caches from a remote server.

        .PARAMETER ComputerName
        The name of the server to retrieve the cache information from
            
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,

        [PSCredential]$Credential
    )

    $ListCacheBlock = {
        $results = & listcaches /a
        Write-Output $results
    }

    foreach ($Computer in $ComputerName){
        $CacheList = [string]::Empty
        $Properties = @{
            ComputerName = $Computer
            ScriptBlock = $ListCacheBlock
            ErrorAction = 'Stop'    
        }

        If($PSBoundParameters.ContainsKey('Credential')){
            $Properties.Add('Credential',$Credential)
        }
        Write-Verbose "retrieving cache details from $computer"
        try{
            $CacheList = Invoke-Command @Properties
        }
        catch {
            Write-Warning "There was an issue connecting to $Computer, check to see of PSRemoting is enabled"
            Write-Warning $Error[0]
        }
        
        Write-Output $CacheList
    }

}

function Get-EventTail{
    <#
        .Synopsis
        Displays the latest events in the event log
        
        .Description
        Display the latest Event in the Event Log and Continuously checks for the any new events.
        When looping through we get the newest 20 events, but only displays any event that happened since the
        last one displayed. This handles if there are a bunch of events added before the next time events
        are fetched, all events that happen will be displayed, not just the latest.

        .PARAMETER ComputerName
        The name of the computer whose logs you want to tail
        
        .PARAMETER Log
        The name of the log to display
        
        .PARAMETER Newest
        The number of newest events to display
        
        .EXAMPLE
        Get-EventTail 
        
        .EXAMPLE
        Get-EventTail -Log Application -Newest 10
            

    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Application','Security','System','FMGlobalLog','DSC')]
        [string]$Log = 'Application',

        [string]$ComputerName = 'localhost',

        [System.Int16]$Newest = 1
    )

    Write-Verbose "Converting Log Name $Log"
    if($Log -eq 'DSC'){$__log = 'Microsoft-Windows-Dsc/Operational'}
    else{$__log = $log}
	
    Write-Verbose "Log Name is now $__log"
	
    try{
        
        $LatestEvent = Get-WinEvent -LogName $__log -Maxevent 1 -ComputerName $ComputerName -ErrorAction Stop
        Write-Verbose "Retrieved event with message: $($LatestEvent.Message)"
        __display-event -event $LatestEvent
        Start-Sleep 1
    }
    catch [System.Management.Automation.ParseException]{
        Write-Error "There may not be a log named $__log"
        Throw $Error[0]
    }

    While ($true)
    {
        Write-Verbose "Getting Events newer than $($LatestEvent.TimeCreated)"
        
        try{
            $events = Get-WinEvent -LogName $__log -ComputerName $ComputerName -ErrorAction Stop | where {$_.TimeCreated -gt $LatestEvent.TimeCreated}
            foreach($event in $events)
            {
                __display-Event -event $event
                $LatestEvent = $event
            }
        }
        catch{

            Write-Warning "There was an issue getting new events from $__log log"
        }

        Start-Sleep -Seconds 5
    }
}

Function Get-WebSiteRedirects{
    <#
        .SYNOPSIS
        Returns all Redirects configured Via IIS

        .DESCRIPTION
        Returns redirects configured via IIS for all sites, Apps, Virtual Directories and Directories

        .PARAMETER SiteName
        The name of the site you want to check, if you want to check all sites, don't pass this parameter
        it is optional

        .EXAMPLE
        Get-webSiteRedirects -SiteName "Default Web Site"

        Returns all the redirects for the site "Default Web Site" and all its Children (Apps, Virtual Directories and Directories)

        .Example
        Get-WebSiteRedirects

        Returns all sites and their Children
            
    #>
    [CmdletBinding()]
    param(
        [ValidateScript({__validate-WebSite $_})]
        [string]$SiteName
    )
    __check-module -moduleName WebAdministration
    Import-Module WebAdministration
    $RootIISPath = 'IIS:\Sites'

    if($PSBoundParameters.ContainsKey('SiteName')){
        $Sites = Get-ChildItem IIS:\Sites | where {$_.Name -eq $SiteName} | Select Name
    }
    else{
        $Sites = Get-ChildItem IIS:\Sites | Select Name
    }
     
    Foreach ($site in $sites){
    
        $SitePath = Join-path -Path $RootIISPath -ChildPath $site.name 
        __get-Redirect -site $site.name -sitePath $SitePath -Type Site

        $VirtualDirectories = Get-WebVirtualDirectory -Site $site.name | select path
        foreach($dir in $VirtualDirectories){
            Write-Verbose "Getting redirects for $($dir.path)"
            $dirPath = Join-Path -Path $SitePath -ChildPath $dir.path
            __get-Redirect -site $dir.path -sitePath $dirPath -Type VirtualDirectory
        }

        $Apps = Get-WebApplication -Site $site.name | select 
    
        foreach ($app in $Apps){
            $appPath = Join-Path -Path $SitePath -ChildPath $app.path
            __get-Redirect -site $app.path -sitePath $appPath -Type Application
        }

        #Get All Sub folders that are virtual directories
        $directories = Get-ChildItem $SitePath | where {$_.NodeType -eq 'directory'}
        
        foreach($directory in $directories){
            $directoryPath = Join-path -Path $SitePath -ChildPath $directory.Name
            __get-Redirect -site $Site.name -sitePath $directoryPath -Type Directory     
        }
    }

}

function Get-Certificate{
    <#
        .SYNOPIS 
        Returns Certificate in LOCALMACHINE\MY by default

        .DESCRIPTION
        Returns Certificates in the LOCALMACHINE\MY certificate store. Use the CertStoreRoot and CertStore to override.
        Also, the thumbprint parameter can be used to retrieve a specific Cert by thumbprint. Or the CommonName parameter
        Can be used to retrieve a specific certificate by Common Name

        .PARAMETER Thumbprint
        The thumbprint of the certificate you would like to retrieve

        .PARAMETER CommonName
        The CommonName of the certificate you would like to retrieve

        .PARAMETER CertStoreRoot
        The Root Certificate Store, Valid options are LocalMachine and CurrentUser

        .PARAMETER CertStore
        The Certificate store that is a child of the roors store.  The most common option is MY
            
    #>
    [CmdletBinding()]
    param(
       
        [string]$ComputerName,

        [string]$Thumbprint,

        [string]$CommonName,

        [string]$CertStoreRoot = 'LOCALMACHINE',

        [string]$CertStore = 'MY'
    )

    BEGIN{}

    PROCESS{
       
        if($PSBoundParameters.ContainsKey('Thumbprint')){
            $certificates = Get-ChildItem cert:\$CertStoreRoot\$CertStore | where {$_.thumbprint -eq $Thumbprint}
        }
        elseif($PSBoundParameters.ContainsKey('CommonName')){
            $certificates = Get-ChildItem cert:\$CertStoreRoot\$CertStore | where {$_.Subject -match $CommonName}
        }
        else{
          
            $certificates = Get-ChildItem cert:\$CertStoreRoot\$CertStore
        }
        _display-Certificates -Certificates $certificates
    }

    END{}
}

function Remove-Certificate{
    <#
        .SYNOPSIS
        Removes Certificate from Certificate Store

        .DESCRIPTION
        Removes the Certificate associated with the Thumbprint passed in from the LocalMachine\My
        Certificate Store.  The Certificate store defaults to LocalMachine\My but can be overidden
        by passing values to RootStore (LocalMachinem or CurrentUser) and the Store parameters.

        .PARAMETER Thumbprint
        Thumbprint of the Certificate you want to remove

        .PARAMETER RootStore
        The RootCertificate Store, Valid values are LocalMachine and CurrentUser.  The default value is LocalMachine

        .PARAMETER Store
        The Certificate Store, the default value is MY

        .EXAMPLE
        Remove-Certificate -Thumbprint A801DD94CC3899764238F7A3A03089C4050E5457

        .EXAMPLE 
        Remove-Certificate -Thumbprint A801DD94CC3899764238F7A3A03089C4050E5457 -RootStore CurrentUser -Store MY

        .EXAMPLE
        Get-Certificate -CommonName tokensigning.sso1.fmglobal.com | Remove-Certificate
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$Thumbprint,

        [string]$RootStore = 'LocalMachine',

        [string]$Store = 'MY'
    )

    foreach($item in $Thumbprint){
        if($PSCmdlet.ShouldProcess("$item from $RootStore\$Store")){
            $cert = "cert:\$RootStore\$store\$item"   
            Remove-Item $cert
        }
    }

}

function Import-PublicCertificate{
    <#
        .Synopsis
        Imports the Public Certificate passed in to the LocalMachine store

        .Description
        Imports the public certificate from the file passed to the Path parameter into the
        LocalMachine/MY certificate store. A Certificate can be added to a different Certificate
        Store by passing values to the CertStoreRoot parameter and the Certstore parameter

        .PARAMETER Path
        Path to the Certificate file, this can be a path to a local drive or a network share
        This can be an array of paths.

        .PARAMETER CertStoreRoot
        The Root Certificate Store, Valid values are LocalMachine and CurrentUser
        The default value is Localhost
                      
        .PARAMETER CertStore
        The Certificate Store under the root store. The most common value is MY.
        The default value is MY

        .PARAMETER ComputerName
        Computer name or list of computer names to install the certificate on

        .PARAMETER Credential
        Credential to use if connecting to remote server

        .EXAMPLE
        Import-PublicCertificate -Path c:\MyCert.cer

        This will Import the Public cert into localhost\MY Certificate store

        .EXAMPLE 
        Import-PublicCertificate -Path c:\MyCert.cer -CertStoreRoot CurrentUser -CertStore MY

        This will import the public key into the CurrentUser\MY Certificate store

        .EXAMPLE 
        $Certs = @('c:\cert1.cer','c:\cert2')
        Import-PublicCertificate -Path $Certs

        This will import all certificate in the array Certs
        
        .EXAMPLE
        (Get-ChildItem c:\AllMyPublicCerts).FullName | Import-PublicCertificate

        This will get try to import all files in the c:\AllMyPublicCerts Directory
        into the Localhost\My directory
    #>
    [CmdletBinding()]
    param(
        [string[]]
        $ComputerName = $env:COMPUTERNAME,

        [PSCredential]
        $Credential,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$Path,

        [ValidateSet('LOCALMACHINE','CURRENTUSER')]
        [string]$CertStoreRoot = 'LOCALMACHINE',

        [string]$CertStore = 'MY'
    )
	
    BEGIN{
        
        $ImportBlock = {
            [CmdletBinding()]
            param(
                [string]
                $item,
                
                [string]
                $CertStoreRoot,
                
                [string]
                $CertStore
            )
            
            $VerbosePreference='Continue'
            
            Write-Verbose "Importing $item to $CertStoreRoot\$CertStore"
            
            try{
                Write-Verbose "Creating Cert Store Object"
                $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store($CertStore, $CertStoreRoot) -ErrorAction Stop
            }
            catch{
                throw
            }

            try{
                Write-Verbose "Creating new Certificate Object $item"
                $ImportCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $item -ErrorAction Stop
            }
            catch{
                throw
            }
            
            try{
                Write-Verbose "Opening Cert Store"
                $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            }
            catch{
                throw
            }
            try {
                 Write-Verbose "Adding $($ImportCert.Thumbprint) to $CertStoreRoot\$CertStore"
                 $Store.Add($ImportCert)
                 Write-Verbose "$($ImportCert.Thumbprint) Added to $CertStoreRoot\$CertStore"
            }
            catch{
                throw    
            }
            finally{
                $Store.Close()
            }
        }
    }
    
    PROCESS{    
	    $ComputerName | Foreach {
            foreach($item in $Path){
                if($_ -eq $env:COMPUTERNAME){
                   & $ImportBlock -item $item -CertStoreRoot $CertStoreRoot -CertStore $CertStore
                }
                else{
                    
                    $RemoteDestination = "d:\_certs\$(Split-Path -Path $item -Leaf)"
                    
                    #Copy from local to remote machine
                    Write-Verbose "Creating new Drive TempCert to map to \\$_\d`$"
                    New-PSDrive -Name TempCert -PSProvider FileSystem -Root \\$_\d$ -Credential $Credential | Out-Null
                    
                    if(-not(Test-Path TempCert:\_certs)){
                        Write-Verbose 'Creating new _certs directory'
                        New-Item -ItemType Directory -Path TempCert:\_certs | Out-Null
                    }

                    Write-Verbose "Copying $item to $_"
                    Copy-Item $Item TempCert:\_certs
                    
                    Write-Verbose 'Removing TempCert Drive'
                    Remove-PSDrive -Name TempCert
                    Invoke-Command -ComputerName $_ -Credential $Credential -ScriptBlock $ImportBlock -ArgumentList $RemoteDestination,$CertStoreRoot,$CertStore  
                }
            }
        }
    }

    END{}
}

Function Import-PrivateCertificate{
    <#
        .SYNOPSIS
        Imports Public/Private key pair

        .DESCRIPTION
        Imports the public/private key pair into the LocalMachine\My certificate store. The Certificate Store
        can be changed by passing values to the CertStoreRoot and CertStore parameters.

        .PARAMETER Path
        Path to the Certificate file, this can be a path to a local drive or a network share
        This can be an array of paths.

        .PARAMETER CertStoreRoot
        The Root Certificate Store, Valid values are LocalMachine and CurrentUser
        The default value is Localhost
                      
        .PARAMETER CertStore
        The Certificate Store under the root store. The most common value is MY.
        The default value is MY

        .PARAMETER Password
        The password assigned to the pfx file
        

    #>
    [CmdletBinding()]
    param(
        [System.String[]]
        $ComputerName = $env:COMPUTERNAME,

        [PSCredential]
        $Credential,

        [ValidateSet('Kerberos','CredSSP')]
        [System.String]
        $Authentication = 'Kerberos',
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateScript({$_ -match '.pfx'})]
        [string[]]$Path,

        [ValidateSet('LOCALMACHINE','CURRENTUSER')]
        [string]$CertStoreRoot = 'LOCALMACHINE',

        [string]$CertStore = 'MY',

        [Parameter(Mandatory=$true)]
        [string]$Password
    )

    BEGIN{
        
        $ImportBlock = {
            [CmdletBinding()]
            param(
                [string]$item,

                [string]$Password,

                [string]$CertStoreRoot,

                [string]$CertStore,

                [boolean]$SetVerbose
            )
            

            $VerbosePreference='Continue'
            Write-Verbose "Startinng the Import of $item to $env:COMPUTERNAME"
            
            try{
                $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store($CertStore, $CertStoreRoot)
            }
            catch{
                throw
            }

            try{
                $ImportCert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 
            }
            catch{
                throw
            }
                
            try{   
                Write-Verbose "importing $($ImportCert.Thumbprint) to $CertStoreRoot\$CertStore on $env:COMPUTERNAME"
                $ImportCert.import($item,$Password,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            }
            catch{
                throw
            } 
                
            try{    
                Write-Verbose "Opening Cert store $CertStoreRoot\$CertStore"
                $store.open('MaxAllowed') 
                
                Write-Verbose "Adding the Certificate $($ImportCert.Thumbprint) to $CertStoreRoot\$CertStore on $env:COMPUTERNAME"
                $store.add($ImportCert)
                Write-Verbose "$($ImportCert.Thumbprint) added to $CertStoreRoot\$CertStore on $env:COMPUTERNAME"   
                $Store.Close()         
            }
            catch{
                
                Write-Warning "There was an issue importing $item, check if it is a valid certificate or you supplied a valid password"
                throw
            }
            finally{
                $Store.Close()
            }
        }

        
    }

    PROCESS{
        
        $ComputerName | Foreach{
            foreach($item in $path){
                Write-Verbose "Importing from $item to $_"
                if($_ -eq $env:COMPUTERNAME){
                    & $ImportBlock -item $item -Password $Password -Certstore $CertStore -CertStoreRoot $CertStoreRoot -SetVerbose:$VerbosePreference
                }
                else{
                   
                    $RemoteDestination = "d:\_certs\$(Split-Path -Path $item -Leaf)"
                    
                    #Copy from local to remote machine
                    Write-Verbose "Creating new Drive TempCert to map to \\$_\d`$"
                    New-PSDrive -Name TempCert -PSProvider FileSystem -Root \\$_\d$ -Credential $Credential | Out-Null
                    
                    if(-not(Test-Path TempCert:\_certs)){
                        Write-Verbose 'Creating new _certs directory'
                        New-Item -ItemType Directory -Path TempCert:\_certs | Out-Null
                    }

                    Write-Verbose "Copying $item to $_"
                    Copy-Item $Item TempCert:\_certs
                    
                    Write-Verbose 'Removing TempCert Drive'
                    Remove-PSDrive -Name TempCert
                    
                    Invoke-Command -ComputerName $_ `
                        -Credential $Credential `
                        -ScriptBlock $ImportBlock `
                        -ArgumentList $RemoteDestination,$Password,$CertStoreRoot,$CertStore,$VerbosePreference `
                        -Authentication $Authentication
                }    
            }
        }
        
    }

    END{
   
    }
}

function Update-SSLBinding{
    <#
        .SYNOPSIS
        Update the Certificate Bound to an SSL Web Site
        
        .DESCRIPTION
        Updates the Certificate Bound to an SSL site that corresponds to the IP address and
        Port passed.  

        .PARAMETER IPAddress
        IP Address Certificate Should be bound to
        
        .PARAMETER Port
        Port the Certificate is bound to

        .PARAMETER CertificateThumbprint
        Thumbprint of the Certificate to bind

        .Example
        Update-SSLBinding -IPAddress 10.2.1.78 -Port 443 -Thumbprint SDF8989ASD9JJASDFJMASDFASD
        
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,

        [Parameter(Mandatory=$true)]
        [string]$Port = '443',

        [Parameter(Mandatory=$true)]
        [ValidateScript({__validatecertificate $_})]
        [string]$CertificateThumbprint
    )

    if($PSCmdlet.ShouldProcess("Updating $IPAddress`:$Port with $CertificateThumbprint")){
        Set-ItemProperty IIS:\SslBindings\$IPaddress!$Port -Name 'Thumbprint' -Value $CertificateThumbprint
    }

}

<#
    .Synopsis
    Gets the maintenance responsible person for a defined server or servers by James Arruda. 
    .DESCRIPTION
    The "Get-MaintResp" cmdlet gets the "maintresp" object from the registry in the path of "HKLM:\Software\fmglobalsrv" and returns
    the results with the user assigned to the server along with the servername.
    .EXAMPLE
    Example of how to use this cmdlet to collect maintenance responsibility on local server.

    Get-MaintResp -Computername localhost
    .EXAMPLE
    Example of how to obtain maintenace responsibility on remote servers.

    Get-MaintResp -Computername <Remoteserver>

    .EXAMPLE
    Exmaple of how to check maintenace responsibilty on multiple servers.

    Get-MaintResp -Computername <Server1,Server2,Server3>
    .INPUTS
    Inputs to this cmdlet (if any)
    .OUTPUTS
    System.M<nagement.Automation.PSCustomObject
#>
function Get-MaintResp{
    [CmdletBinding()]
    
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string[]]$computername
                   
    )

    Begin{}

    Process{
        
        foreach($computer in $computername){
            if($computer -eq $env:COMPUTERNAME -or $computer -eq 'localhost'){
     
                try{
                    $maint=Get-ItemProperty -Path hklm:\software\fmglobalsrv -ErrorAction stop | 
                    Select-Object maintresp -ErrorAction stop
                }    

                catch{
                    Write-error "Registry Key or path does not exist on specified server $computer"
                }
            
            }
            else{
                try{
                
                    $maint=Invoke-Command -ComputerName $computer -ErrorAction stop {Get-ItemProperty -Path hklm:\software\fmglobalsrv | 
                    Select-Object maintresp}
                }
                catch{
                    Write-Error "$Computer may be offline or no longer exists, but also make sure that PSRemoting is enabled on $computer if you know it is online."
                }
            }
    
            $props=@{
                'MaintResp' = $maint.Maintresp;
                'Computername' = $maint.pscomputername;
            }

            $obj=New-Object -TypeName PSobject -Property $props

            if($maint -ne $null){
                Remove-Variable -Name maint
            }
            
            Write-output $obj
        }
    }

    End{}
}

function __validateCertificate{
    param(
        [string]$Thumbprint
       
    )

    $cert = Get-ChildItem Cert:\LocalMachine\my\$Thumbprint | where {$_.hasprivatekey -eq $true}
    return !([string]::IsNullOrEmpty($Cert))
}

function __get-Redirect{
    <#
        .SYNOPSIS
        Gets redirect information
       
        .DESCRIPTION
        Gets redirect information for All Virtual Directories, Applications, and Web Sites in a Server
       
        .PARAMETER site
        the name of the site, virtual directory, or application
        
        .PARAMETER SitePath 
        the path in the IIS PSDrive to the Web Configuration file
    #>
    [CmdletBinding()]
    param(
        [string]$site,

        [string]$sitePath,

        [ValidateSet('Site','Application','VirtualDirectory','Directory')]
        [string]$Type
    )
   
    try{
        $properties = @{
            Name = $site
            Type = $Type
            Path = $sitePath
            RedirectDestination = (Get-WebConfigurationProperty -filter /system.webserver/httpRedirect -PSPath $sitePath -name destination).value
            RedirectEnabled = (Get-WebConfigurationProperty -filter /system.webserver/httpRedirect -PSPath $sitePath -name enabled).value
            
        }

        $siteObject = New-Object -TypeName psobject -Property $properties
        Write-Output $siteObject
    }
    catch{
        Write-Warning "There was an issue retrieving redirect info for $site"
    }
}

Function __display-Event{
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$event
    )
    
    $display = $event | Select-Object @{Name='Time';Expression={$_.TimeCreated}},` 
    Message,`
    MachineName,`
    @{n='EventID';e={$_.ID}}

    Write-Output $display
}

function __validate-WebSite{
    param(
        [string]$sitename
    )
   
    $Valid = $true
    $site = Get-Website | where {$_.Name -eq $sitename}
   
    if([string]::IsNullOrEmpty($site.name)){
        $Valid = $false
    }
   
    Write-Output $Valid
}

Function __check-module{
    param(
        [string]$moduleName
    )
    
    if(!(Get-Module -ListAvailable -Name $moduleName))
    {
        Throw "Please ensure that $moduleName module is installed."
    }
}

function _display-Certificates{
    <#
        Private Function to displat Certificates
    #>
    [CmdletBinding()]
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        $Certificates
    )

    foreach($cert in $certificates){
        Write-Verbose "retrieved $($cert.Thumbprint)"
        $properties = @{
            Thumbprint = $cert.Thumbprint
            Subject = $cert.Subject
            NotAfter = $cert.NotAfter
            NotBefore = $cert.NotBefore
            HasPrivateKey = $cert.HasPrivateKey   
        }
        $CertObject = New-Object -TypeName PSObject -Property $properties
        Write-Output $CertObject
    }
}

Export-ModuleMember -Function Get-EventTail
Export-ModuleMember -Function Get-FMWebAppInfo
Export-ModuleMember -Function Get-WebSiteredirects
Export-ModuleMember -Function Import-PublicCertificate
Export-ModuleMember -Function Import-PrivateCertificate
Export-ModuleMember -Function Get-Certificate
Export-ModuleMember -Function Get-CacheList
Export-ModuleMember -Function Get-CacheCount
Export-ModuleMember -Function Remove-Certificate
Export-ModuleMember -Function Update-SSLBinding
Export-ModuleMember -Function Get-CacheDetails
Export-ModuleMember -Function Get-AccountFromSID
Export-ModuleMember -Function Get-ExpiringCertificate
Export-ModuleMember -Function Get-MaintResp
Export-ModuleMember -Function *-EnvironmentSetting
Export-ModuleMember -Function *-MaintenanceMode