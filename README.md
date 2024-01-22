# Get-RemoteRecycleBin
Powershell.  Query a remote users Recycle Bin

Parses a remote recycle bin to retrieve the files, and meta data regarding where they originally resided and the time they were deleted.

Can target the recycle bin locations on all connected drives.

This script needs to be run with administrative rights on the remote host, no verification is done to confirm this.

Shout out to Ian Hutchison for working on this with me

Updates to come that will show original filenames instead of metadata filenames

---

**Parameters**

_username_

The SamAccountName of the users recycle bin that you are trying to retrieve. If not specified the script will return for all users of the remote system.

_computername_

The host name of the computer that holds the recycle bin that you are trying to retrieve. If not specified it will return the results from the local computer.

_showDetails_

Shows details of all the user accounts on the host being queried and the locations of each recycle bin for each user on that host.

---

**Examples**

```powershell
Get-RemoteRecycleBin -user j.seinfeld -computer apartment5a
```

```powershell
Get-RemoteRecycleBin -computer apartment5a -showDetails
```
