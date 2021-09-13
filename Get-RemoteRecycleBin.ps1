function Get-RemoteRecycleBin {
    <#
    .SYNOPSIS
        Connects to a remote machine and pulls back the $Recyle.Bin contents
    .DESCRIPTION
        Parses a remote recycle bin to retrieve the files, and meta data regarding where they originally resided and the time they were deleted.
        Can traget the recycle bin locations on all connected drives.
        This script needs to be run with administrative rights on the remote host, no verification is done to confirm this.
    .PARAMETER username
        The SamAccountName of the users recycle bin that you are trying to retrieve. This is optional, if not 
        specified the script will return for all users of the remote system.
    .PARAMETER computername
        The host name of the computer that holds the recycele bin that you are trying to retrieve. This is optional, if not
        specified it will return the results from the local computer.
    .PARAMETER showDetails
        Shows details of all the user accounts on the host being queried and the locations of each recycle bin for each user on that host.
    .NOTES
        Author: Ian Hutchison
        v0.1 - (2021-09-07) Removed reliance of the AD lookup and instead searches the local system to resolve the username to SID  
    .EXAMPLE
        Get-RemoteRecycleBin -user john.smith -computer computer1
    .EXAMPLE
        Get-RemoteRecycleBin -computer computer1 -showDetails
    #>

    #requires -version 5
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][string]$computername = $env:COMPUTERNAME,
        [Parameter(Mandatory=$false)][string]$username = $null,
        [Parameter(Mandatory=$false)][switch]$showDetails
    )

    $InformationPreference = "Continue"    

    #region first scriptblock for running remotely - get all users and associated recycle bins
    $GetAllUsersAndBins = {
        function Get-DriveInfo {      
            param ($ComputerName = $env:COMPUTERNAME)
            Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName `
                | Select-Object SystemName, DeviceID, VolumeName, Description,`
                FileSystem, @{Name='Size'; Expression={ "{0:F2} GB" -f ($_.Size / 1gb) } },`
                @{Name='FreeSpace'; Expression={ "{0:F2} GB" -f ($_.FreeSpace / 1gb) } }  
        }

        function Get-UsersAndBins {
            $users = Get-WmiObject win32_userprofile | Where-Object {$_.sid.length -gt 8} | Select-Object localpath, sid, @{n="Username";e={$_.localpath.split("\")[-1]}}
            # test for a recycle bin folder on each drive for each user
            foreach ($user in $users) {
                $RecycleBinPaths = [System.Collections.ArrayList]@()
 
                foreach ($drive in (Get-DriveInfo).DeviceID) {
                    $binPath = "$drive\`$Recycle.Bin\$($user.sid)"
                    if (Test-Path -Path $binPath) { $RecycleBinPaths.Add($binPath) | Out-Null }
                }
                
                $user | Add-Member -MemberType NoteProperty -Name BinPaths -Value $RecycleBinPaths
                if ($RecycleBinPaths.count -eq 0) { $recycleBinPathsExist = $false } else { $recycleBinPathsExist = $true }
                $user | Add-Member -MemberType NoteProperty -Name BinPathExists -Value $recycleBinPathsExist  
            }
                $users
        }
    
        Get-UsersAndBins    
    }
    #endregion first scriptblock for running remotely - get all users and associated recycle bins
    
    #region second scriptblock for running remotely - parse all the recycle bins
    $GetParsedRecycleBinContents = {
        function Get-RecycleBinContentsList {
            param (
                [array]$binPaths
            )
          
            # create an array to return the objects in
            $RecycleBinFiles = [System.Collections.ArrayList]@()

            function Invoke-ParseDollarIFile {
                param(
                    $file
                )
            
                # get the file info
                $filename = (Get-Item $file).Name
                $directoryName = (Get-Item $file).DirectoryName
                $fullname = (Get-Item $file).FullName
                $filesize = [System.BitConverter]::ToInt64((Get-Content -Encoding Byte -path $file)[8 .. 15],0)
                $header = Get-Content -Encoding Byte -path $file -totalcount 8
                $headerString = [System.BitConverter]::ToString($header)
                switch ($headerString) {
                    "01-00-00-00-00-00-00-00" { $os = 'Win7/8'; $originalPathRaw = (Get-Content -Encoding Byte -path $file)[24 .. (Get-Item $file).Length] }
                    "02-00-00-00-00-00-00-00" { $os = 'Win10'; $originalPathRaw = (Get-Content -Encoding Byte -path $file)[28 .. (Get-Item $file).Length] }
                }
                $originalPath = [System.Text.Encoding]::Ascii.GetString($originalPathRaw) -replace "\x00"
            
                $deletedTimeRaw = (Get-Content -Encoding Byte -path $file)[16 .. 23]
                $deletedTimeRawAsInt = [System.BitConverter]::ToInt64($deletedTimeRaw,0)
                $deletedTimeUtc = [DateTime]::FromFileTime($deletedTimeRawAsInt).ToUniversalTime()
            
                # create an object to return
                $deletedFileObject = [PSCustomObject]@{
            
                    'Operating System'       = $os
                    'Filename' = $filename
                    'DirectoryName' = $directoryName
                    'Fullname' = $fullname
                    'FileSize (bytes)' = $filesize
                    'Original Path' = $originalPath
                    'Time Deleted (UTC)' = $deletedTimeUtc
                }
                
                return $deletedFileObject	
            }

            foreach ($binPath in $binPaths) {

                $binContentsInRoot = Get-ChildItem $binPath -Force -Filter "`$R*"
                foreach ($item in $binContentsInRoot){
                    # create a hashtable to store the properties that we want to return
                    [hashtable]$deletedFileInfo = @{}
                    $dollarRFilePath = $item.FullName
                    $dollarRFileName = $item.Name
                    $deletedFileInfo.Add('DollarR Fullname', $dollarRFilePath)

                    # calculate the full path for the $I file and test if the file exists. Note we cant use the .DirectoryName property as that only exists for files, not directories
                    $dollarIFilePath = Join-Path -Path ($item.Fullname.Substring(0, $dollarRFilePath.lastIndexOf('\'))) -ChildPath ($dollarRFileName.replace('$R', '$I'))
                    $deletedFileInfo.Add('DollarI Fullname',$dollarIFilePath)
                    $dollarIFileExists = Test-Path -Path $dollarIFilePath
                    $deletedFileInfo.Add('DollarI File Exists',$dollarIFileExists)

                    # if the $I file exists, parse it and add the relevant properties to the hash table
                    if ($dollarIFileExists) {
                        $ParsedDollarIFile = Invoke-ParseDollarIFile -file $dollarIFilePath
                        $deletedFileInfo.Add('Operating System', $ParsedDollarIFile.'Operating System')
                        $deletedFileInfo.Add('Time Deleted (UTC)', $ParsedDollarIFile.'Time Deleted (UTC)')
                        $deletedFileInfo.Add('FileSize form metadata (bytes)', $ParsedDollarIFile.'FileSize (bytes)')
                    }

                    # if the $R item is a file
                    if ((Get-Item -Path $dollarRFilePath).PSIsContainer -eq $false) {
                        $deletedFileInfo.Add('Original Path', $ParsedDollarIFile.'Original Path')
                        $deletedFileInfo.Add('File Size (bytes)', (Get-Item $dollarRFilePath).Length)
                        $deletedFileInfo.Add('MD5 Hash', (Get-FileHash -Algorithm MD5 -Path $dollarRFilePath).hash)
                        $deletedFileInfo.Add('SHA1 Hash', (Get-FileHash -Algorithm SHA1 -Path $dollarRFilePath).hash)

                        # $using: is used as the variable $computername is not defined on the remote host that will be running this scriptblock
                        $uncPathToDelete = ("\\$using:computername\$dollarIFilePath").replace(':','$').replace('$I','$?')
                        $deletedFileInfo.Add('UNC Path to Delete', $uncPathToDelete)

                        # convert the hash table to a PSObject, then dispose of it so it doesnt affect other instances
                        $deletedFileObject = New-Object -TypeName psobject -Property $deletedFileInfo
                        $deletedFileInfo.Clear()

                        # add custom object to list of files in the recycle bin, then dispose of it so it doesnt affect future iterations
                        $RecycleBinFiles.Add($deletedFileObject) | Out-Null
                        $deletedFileObject = $null
                    }
                    # else if its a folder
                    else {
                        # get a list of files in the directory
                        $directoryContents = Get-ChildItem -Path $dollarRFilePath -Recurse -Force -File
                        foreach ($file in $directoryContents) {
                            # clone the hashtable so we can reuse the info in it multiple times, once for each file in the folder
                            $deletedFileInfoClone = $deletedFileInfo.Clone()
                            $deletedFileInfoClone.Add('MD5 Hash', (Get-FileHash -Algorithm MD5 -Path $file.FullName).hash)
                            $deletedFileInfoClone.Add('SHA1 Hash', (Get-FileHash -Algorithm SHA1 -Path $file.FullName).hash)
                            
                            $lengthOfRecycleBinFolderPath = $item.Fullname.Length
                            $lengthOfFilePathInsideRecycleBin = $file.Fullname.length - $lengthOfRecycleBinFolderPath
                            $originalPath = join-Path -Path ($ParsedDollarIFile.'Original Path') -ChildPath ($file.Fullname.substring($lengthOfRecycleBinFolderPath, $lengthOfFilePathInsideRecycleBin))
                            $deletedFileInfoClone.Add('Original Path', $originalPath)

                            $deletedFileInfoClone.Add('File Size (bytes)', (Get-Item $file.FullName).Length)
                            
                            # $using: is used as the variable $computername is not defined on the remote host that will be running this scriptblock
                            $uncPathToDelete = ("\\$using:computername\$($file.Fullname)").replace(':','$').replace('$I','$?')
                            $deletedFileInfoClone.Add('UNC Path to Delete', $uncPathToDelete)

                            # convert the hash table to a PSObject, then dispose of it so it doesnt affect other instances
                            $deletedFileObject = New-Object -TypeName psobject -Property $deletedFileInfoClone
                            $deletedFileInfoClone.Clear()
                            
                            # add custom object to list of files in the recycle bin, then dispose of it so it doesnt afect fulture iterations
                            $RecycleBinFiles.Add($deletedFileObject) | Out-Null
                            $deletedFileObject = $null
                        }
                    }
                }
            }
            return $RecycleBinFiles
        }
        Get-RecycleBinContentsList -binPaths $args
    }
    #endregion second scriptblock for running remotely - parse all the recycle bins
    
    
    # get a list of all the user profiles on the remote system and associated recycle bin locations
    $UsersAndBins = Invoke-Command -ComputerName $computername -ScriptBlock $GetAllUsersAndBins
    if ($showDetails.IsPresent) {
        Write-Information -MessageData "`nRecycle Bin Information for host $computername"
        $UsersAndBins | Select-Object Username, @{n="Recycle Bin Exists";e={$_.BinPathExists}}, @{n="Recycle Bin Paths";e={if ($_.BinPathExists) {$_.BinPaths} else {$null}}} | Format-Table -AutoSize
    }

    # if a username is specified
    if (-not ([string]::IsNullOrEmpty($username))) {
        # check if user specified exists in the returned data
        if (-not($username -in $UsersAndBins.username)) {
            Write-Information -MessageData "`nThe username specified, $username, was not found on remote host $computername"
        }
        else {
            Write-Information -MessageData "`nRecycle Bin Contents for user $Username ($(($UsersAndBins | Where-Object {$_.username -eq $username}).sid))"
            $argumentList = (,($UsersAndBins | Where-Object {$_.username -eq $username}).BinPaths)
            Write-Host $argumentList
            $Results = Invoke-Command -ComputerName $computername -ScriptBlock $GetParsedRecycleBinContents -ArgumentList $argumentList
            
        }
    }
    # else query for all users
    else {
        Write-Information -MessageData "`nRecycle Bin Contents for all users on for host $computername."
        $argumentList = (,$UsersAndBins.BinPaths)
        Write-Host $argumentList
        $Results = Invoke-Command -ComputerName $computername -ScriptBlock $GetParsedRecycleBinContents -ArgumentList $argumentList
    }

    $Results | Select-Object 'Original Path', 'Time Deleted (UTC)','File Size (bytes)', 'MD5 Hash', 'SHA1 Hash', 'UNC Path to Delete'
}
