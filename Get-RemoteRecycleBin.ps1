function Get-RemoteRecycleBin {
    <#
    .SYNOPSIS
        Connects to a remote machine and pulls back the $Recyle.Bin contents
    .DESCRIPTION
        Provides file names that are not the original file names, but can be used to help ascertain which files might be deleted by size, filetype and date,
        so that files detected by SEP or HX can be removed with Remove-RemoteRecycleBinItem
    .PARAMETER user
        The SamAccountName of the users recycle bin that you are trying to retrieve
    .PARAMETER computer
        The host name of the computer that holds the recycele bin that you are trying to retrieve
    .NOTES
        Author: Joel Ashman
        v0.1 - (2021-08-31) Initial version
        To do - Can possibly iterate through each item, and do a Get-Content or similar on each to determine original filename.  TBC
    .EXAMPLE
        . .\Get-RemoteRecycleBin
        Get-RemoteRecycleBin -user ashmanj -computer AUBNE1LT4088
    #>
    #requires -version 5
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$user,
        [Parameter(Mandatory)]
        [string]$computer
    )
    $adModuleCheck = (Get-Module -ListAvailable | Where-Object { $_.Name -eq "ActiveDirectory"}).Name # Check if the AD module is loaded
    if ($adModuleCheck -eq "ActiveDirectory"){}
    else{ # Try to load the AD Powershell module if it isn't loaded
        Write-Warning "`n[!] The ActiveDirectory module is missing, trying to load it."
        try{Import-Module ActiveDirectory}
        catch{Write-Warning "`n[!] Problem with importing the ActiveDirectory module. $($Error[0])`nYou may need to install it with the following powershell one liner:`n`nGet-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online"}
    }
    # Get a Global Catalog for running AD queries
    $localSite = (Get-ADDomainController -Discover).Site;$newTargetGC = Get-ADDomainController -Discover -Service 2 -SiteName $localSite
    if (!$newTargetGC) {$newTargetGC = Get-ADDomainController -Discover -Service 2 -NextClosestSite};$localGC = "$($newTargetGC.HostName)" + ":3268"
    $sid = (Get-ADUser -filter "SamAccountName -eq '$user'" -server $localGC).SID.Value # Get the users SID for connecting to their recycle bin  
    Invoke-Command -scriptblock { # Connect to the remote host, pull back the recycle bin contents
        $sid = $Using:sid # We need this as Using: only works one layer deep - it wouldn;t work if we used using:sid in the for loop below 
        $list = get-childitem -Path c:\`$Recycle.Bin\$sid; $resultArray = @()
        foreach ($file in $list) {
            $file = "c:\`$Recycle.Bin\$($sid)\$($file.name)"
            $result = Get-ChildItem -Path $file |  select Name, Mode, Extension,@{N='KbSize';E={[int]($_.length / 1kb)}},IsReadOnly, Exists,@{N='CreateUTC';E={$_.CreationTimeUtc}},@{N='LastWriteUTC';E={$_.LastWriteTimeUTC}} # Pull the details for each file that we need for IR
            $resultArray += $result # add result to array
        }  
        $resultArray | format-table -AutoSize # Display the results
    } -computername $computer # List the files in the recycle bin 
}
