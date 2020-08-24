#region functions
Function Write-Log
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        $File
    )
    Add-Content -Value "$(Get-Date -Format u) -- $Message" -Path $backupLogFile -PassThru
}

Function Test-RegistryValue
{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )
    try
    {
    Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
    return $true
    }
    catch
    {
    return $false
    }
}

function Select-RoboSummary {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$log,
        [parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [switch]$separateUnits
    )
    PROCESS
    {
        $cellHeaders = @("Total", "Copied", "Skipped", "Mismatch", "Failed", "Extras")
        $rowTypes    = @("Dirs", "Files", "Bytes")

        # Extract rows
        $rows = $log | Select-String -Pattern "(Dirs|Files|Bytes)\s*:(\s*([0-9]+(\.[0-9]+)?( [a-zA-Z]+)?)+)+" -AllMatches
        if ($rows.Count -eq 0)
        {
            throw "Summary table not found"
        }

        if ($rows.Matches.Count -ne $rowTypes.Count)
        {
            throw "Unexpected number of rows/ Expected {0}, found {1}" -f $rowTypes.Count, $rowsMatch.Count
        }

        # Merge each row with its corresponding row type, with property names of the cell headers
        for($x = 0; $x -lt $rows.Matches.Count; $x++)
        {
            $rowType  = $rowTypes[$x]
            $rowCells = $rows.Matches[$x].Groups[2].Captures | foreach{ $_.ToString().Trim() }

            if ($cellHeaders.Length -ne $rowCells.Count)
            {
                throw "Unexpected amount of cells in a row. Expected {0} cells (the amount of headers) but found {1}" -f $cellHeaders.Length,$rowCells.Count
            }

            $row = New-Object -TypeName PSObject
            $row | Add-Member -Type NoteProperty Type($rowType)

            for($i = 0; $i -lt $rowCells.Count; $i++)
            {
                $header = $cellHeaders[$i]
                $cell   = $rowCells[$i]

                if ($separateUnits -and ($cell -match " "))
                {
                    $cell = $cell -split " "
                }

                $row | Add-Member -Type NoteProperty -Name $header -Value $cell
            }

            $row
        }
    }
}

# function Mount-BackupDestination {

# }
#endregion functions

#region get backup log file
if (!(Test-Path -Path C:\Windows\Logs\WastelandBackup\lastBackup.log)) {
    $backupLogFile = New-Item -Path C:\Windows\Logs\WastelandBackup\lastBackup.log -ItemType File -Force
}
else {
    $backupLogFile = Get-Item -Path C:\Windows\Logs\WastelandBackup\lastBackup.log
}
#endregion backup log file

#region registry location
if (!(Test-Path HKLM:\SOFTWARE\Wasteland)) {
    New-Item -Path HKLM:\SOFTWARE -Name "Wasteland" -ErrorAction SilentlyContinue -ErrorVariable wastelandRegErr | Out-Null
    if ($wastelandRegErr) {
        $regError = $wastelandRegErr.exception
    }
}
if (!(Test-Path HKLM:\SOFTWARE\Wasteland\Backup)) {
    New-Item -Path HKLM:\SOFTWARE\Wasteland -Name "Backup" -ErrorAction SilentlyContinue -ErrorVariable wastelandBackupRegErr | Out-Null
    if ($wastelandBackupRegErr) {
        $regError = $wastelandRegErr.exception
    }
}
#endregion registry location

#backup GUID
If (-Not (Test-RegistryValue -Path 'HKLM:\Software\Wasteland\Backup' -Value 'GUID')) {
    $GUID = [GUID]::NewGuid().ToString().SubString(0,8)
    New-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name GUID -PropertyType string -Value $GUID -ErrorAction SilentlyContinue | Out-Null
}

#region event log source
If (!([System.Diagnostics.EventLog]::SourceExists("Wasteland Backup System"))) {
    New-EventLog -LogName "Application" -Source "Wasteland Backup System"
}
#endregion event log source

#begin event logging
Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventID 1450 -EntryType Information -Message "Backup task started"

#region variables
$GUID              = (Get-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name GUID).GUID
$hostname          = $ENV:COMPUTERNAME.ToUpper()
$hostnameGUID      = "$($hostname)_$($GUID)"
$backupDestination = "\\FILESERVER\Backups\$hostnameGUID"
$localLogDir       = "C:\Windows\Logs\WastelandBackup"
$downloadInProgressFlagFile = $localLogDir + "\_downloadInProgress"
$backupLogDir      = $backupDestination + "\Logs"
$appListFile       = $backupLogDir + "\AppList.xml"
$DLRFile           = $backupLogDir + "\_ROBODateLastRan"
$DLCFile           = $backupLogDir + "\_ROBODateLastComplete"
$roboSuccessFile   = $backupLogDir + "\_ROBODateLastSuccess"
$fixedDrivesFile   = $backupLogDir + "\FixedDrives.txt"
$roboCLogOnly      = $backupLogDir + "\ROBO_C_LogOnly.log"
$backupBin         = "\\FILESERVER\Backups\Bin"
$sizeFile          = $backupDestination + "\Size.txt"
$EFSFile           = $backupDestination + "\EFS.txt"
$excludedDirs      = $backupBin + "\ExcludedDirs.txt"
$excludedFiles     = $backupBin + "\ExcludedFiles.txt"
$compInfoFile      = $backupLogDir + "\compInfo.txt"
$userList          = $backupLogDir + "\userList.txt"
$appList           = $backupLogDir + "\appList.xml"
$roboDays          = (Get-Date).AddDays(-7)
$roboHours         = (get-date).AddHours(-23)
$roboLogDays       = (get-date).AddDays(-7)
$userDays          = (get-date).AddDays(-14)
$osInfo            = Get-CimInstance -ClassName Win32_OperatingSystem
$compSys           = Get-CimInstance -ClassName Win32_ComputerSystem
$chassis           = Get-CimInstance -ClassName Win32_SystemEnclosure
$compModel         = $compSys.Model
$os                = $osInfo.Caption
$osVersion         = $osInfo.Version
$netAdapters       = Get-NetIPConfiguration | Where-Object {$_.netadapter.physicalmediatype -like "*802*"}
#endregion variables

#i don't backup virtual machines...
If ($compSys.Model -eq "VMware Virtual Platform" -or $compSys.Model -eq "Parrallels Virtual Platform" -or $compSys.Model -eq "VirtualBox") {
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1461 -EntryType Information -Message "Virtual machine detected`n$($compsys.model)"
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1460 -EntryType Information -Message "Task Ended"
    Exit
}

#check if backup already in progress
if (Test-Path -Path $backupInProgress ) {
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "Backup in progress"
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1460 -EntryType Information -Message "Task Ended"
    exit
}

#check if download is in progress
if (Test-Path -Path $downloadInProgressFlagFile ) {
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1463 -EntryType Information -Message "Download in progress"
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1460 -EntryType Information -Message "Task Ended"
    exit
}

#create data directory if needed
if (!(Test-Path -Path $backupDestination)) {
    New-Item -Path $backupDestination -ItemType Directory | Out-Null
    Start-Sleep -Seconds 3
    if (!(Test-Path -Path $backupDestination)) {
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1464 -EntryType Information -Message "Failed to create backup destination: $backupDestination"
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1460 -EntryType Information -Message "Task Ended"
        exit
    }
}

#create log directory if needed
if (!(Test-Path -Path $backupLogDir)) {
    New-Item -Path $backupLogDir -ItemType Directory | Out-Null
    Start-Sleep -Seconds 2
}

#start logging
Write-Log -Message "INFO: Operating System: $($os), $($osVersion)" -File $backupLogFile
Write-Log -Message "INFO: Manufacturer: $($osInfo.Manufacturer)" -File $backupLogFile
Write-Log -Message "INFO: Model: $compModel" -File $backupLogFile
Write-Log -Message "INFO: Serial Number: $($chassis.SerialNumber)" -File $backupLogFile
Write-Log -Message "INFO: Chassis Type ID: $($chassis.ChassisTypes)" -File $backupLogFile
ForEach($adapter in $netAdapters){
    Write-Log -Message "INFO: NIC Name: $($adapter.NetAdapter.Name)" -File $backupLogFile
    Write-Log -Message "INFO: NIC Description: $($adapter.InterfaceDescription)" -File $backupLogFile
    Write-Log -Message "INFO: NIC Mac: $($adapter.NetAdapter.MacAddress)" -File $backupLogFile
    Write-Log -Message "INFO: NIC Status: $($adapter.NetAdapter.Status)" -File $backupLogFile
    if($adapter.NetAdapter.Status -eq "Up"){
        Write-Log -Message "INFO: IPv4 Address: $($adapter.IPv4Address.IPAddress)" -File $backupLogFile
    }
}
Write-Log -Message "INFO: Upload directory: $backupDestination" -File $backupLogFile

# Get logged in user 
if (Test-Path -Path $userList -ErrorAction SilentlyContinue) {
    Remove-Item -Path $userList -Force
}
Write-Log -Message "Getting logged in user" -File $backupLogFile
ForEach($userLine in @(query user) -split "\n")  {
    $parsed_User = $UserLine -split '\s+'
    If ($parsed_User -like "USERNAME*") {
    }
    ElseIf ($parsed_User -like ">*") {
        $parsed_User=$parsed_User.Replace(">","")
        $LoggedOnUser = $parsed_User[0]
        $LoggedOnUserTime = $parsed_User[5]+" " +$parsed_User[6]+" "+$parsed_User[7]
        $LoggedOnUserAppDataDir = "c:\users\" + $LoggedOnUser + "\AppData"
        Add-Content -Value "$LoggedOnUser,$LoggedOnUserTime" -Path $userList -PassThru
    }
    Else {
        $LoggedOnUser = $parsed_User[1]
        $LoggedOnUserTime = $parsed_User[6]+" " +$parsed_User[7]+" "+$parsed_User[8]
        $LoggedOnUserAppDataDir = "c:\users\" + $LoggedOnUser + "\AppData"
        Add-Content -Value "$LoggedOnUser,$LoggedOnUserTime" -Path $userList -PassThru
    }
}
If ($LoggedOnUser) {
    Write-Log -Message "INFO: Current logged on user: $LoggedOnUser" -File $backupLogFile
}
Else {
    Write-Log -Message "INFO: No users currently logged on." -File $backupLogFile 
}

#Generate Compinfo file for Client Migration Status Page
Write-Log -Message "INFO: Capturing computer info for logging..." -File $backupLogFile
$CompInfo = "$OS,$compModel" | Out-File -FilePath $CompInfoFile -Force
Start-sleep -Seconds 1

#Exit if the Wasteland registry key could not be created, or GUID is empty.  Temporary fixes for machines without GUIDs.
If (-Not (Test-Path 'HKLM:\Software\Wasteland')) {
    Write-Log -Message "INFO: Error variable: $RegError" -File $backupLogFile
    Write-Log -Message "WARNING: Wasteland reg key could not be created, exiting." -File $backupLogFile
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1477 -EntryType Information -Message "Wasteland reg key could not be created."
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1470 -EntryType Information -Message "Task Ended"
    Exit
}
If ([string]::IsNullOrEmpty($GUID)) {
    Write-Log -Message "WARNING: GUID contains no value, exiting." -File $backupLogFile
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1478 -EntryType Information -Message "GUID contains no value."
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1470 -EntryType Information -Message "Task Ended"
    Exit 
}

#Check last time upload was ran successfully
Write-Log -Message "INFO: Checking time of last completed copy..." -File $backupLogFile
If (Test-Path -Path $DLCFile) {
    $DLR = Get-Item $DLRFile -ErrorAction SilentlyContinue
    $DLC = Get-Item $DLCFile -ErrorAction SilentlyContinue
    $DLRCreationTime = $DLR.CreationTime
    $DLCCreationTime = $DLC.CreationTime
    If ($DLCCreationTime -gt $ROBODays) {
        #ElseIf ($DLCCreationTime -gt $ROBOHours) {
            Write-Log -Message "INFO: Last Robocopy completed on $DLCCreationTime , exiting." -File $backupLogFile
            Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1455 -EntryType Information -Message "Backup last completed on $DLCCreationTime"
            Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1470 -EntryType Information -Message "Task Ended"
            Exit
    }
    Else {
        Write-Log -Message "INFO: Last Robocopy completed on $DLCCreationTime , continuing..." -File $backupLogFile
    }
}
Else {
    Write-Log -Message "INFO: No last completed time found." -File $backupLogFile
    $initialUpload = $true
}

# #Create Processing File
# If (!(Test-Path -Path $processingFile)) {
#     Write-Log -Message "INFO: Creating Processing File..." -File $LogFile
#     New-Item "$processingFile" -ItemType File | Out-Null
#     Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Processing" -ErrorAction SilentlyContinue | Out-Null
# }

#Generate installed programs list
Write-Log -Message "INFO: Creating AppList xml file..." -File $backupLogFile
$applications = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion
[xml]$doc = New-Object System.Xml.XmlDocument
$dec = $Doc.CreateXmlDeclaration("1.0","UTF-8",$null)
$doc.AppendChild($dec)
$root = $doc.CreateNode("element","Applications",$null)
foreach($application in $applications){
    $appXML = $doc.CreateNode("element","Application",$null)
    "DisplayName","DisplayVersion" | ForEach-Object {
        $e = $doc.CreateElement($_)
        $e.InnerText = $application.$_
        $appXML.AppendChild($e)
    }
    $e = $doc.CreateElement("AppID")
    $appXML.AppendChild($e)
    $root.AppendChild($appXML)
}
$doc.AppendChild($root)
$doc.save("c:\windows\temp\AppList.xml")
Copy-Item "c:\windows\temp\AppList.xml" -Destination $appListFile -Force
Copy-Item "c:\windows\temp\AppList.xml" -Destination $appListFile -Force

#Generate list of volumes on fixed drives besides C: if not done yet
Write-Log -Message "INFO: Checking for additional volumes on fixed drives..." -File $backupLogFile
$otherDrives = Get-Volume | where-object {$_.DriveType -eq "Fixed" -and $_.DriveLetter -ne "C"} | Select-Object DriveLetter -ExpandProperty DriveLetter
If ($otherDrives){
    If (Test-Path -Path $fixedDrivesFile) {
        Remove-Item -Path $fixedDrivesFile -Force
        Start-Sleep -Seconds 2
    }
    ForEach ($drive in $otherDrives) {
        If ($drive -ne " ") {
            $drivesize = Get-Volume -DriveLetter $drive | Select-Object Size -ExpandProperty Size
            $drivesizeremaining = Get-Volume -DriveLetter $drive | Select-Object SizeRemaining -ExpandProperty SizeRemaining
            $drivesizeused = $drivesize - $drivesizeremaining
            $gbsizeused = [math]::round($drivesizeused / 1GB, 2)
            Write-Log -Message "INFO: Additional volume on fixed drive found: $drive, used space: $gbsizeused GB" -File $backupLogFile
            Add-Content -Value "$drive,$drivesizeused,$gbsizeused" -Path $FixedDrivesFile -PassThru
        } 
    } 
}
Else {
    Write-Log -Message "INFO: No additional volumes on fixed drives found." -File $backupLogFile
}

#// Generate list of excluded directories and files for Robocopy
$exdirs = ""
ForEach ($line in [System.IO.File]::ReadLines($excludedDirs)) {
    $exdirs = $exdirs + " $line"
}
$exfiles = ""
ForEach ($line in [System.IO.File]::ReadLines($excludedFiles)) {
    $exfiles = $exfiles + " $line"
}

#Generate new Robocopy date last ran logs
Remove-Item $DLCFile -ErrorAction SilentlyContinue
Remove-Item $DLRFile -ErrorAction SilentlyContinue
New-Item $DLRFile -ItemType File | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastRoboExitCode -Value NA -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastRoboTimeToRun -Value NA -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastRun -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null

#Verify that Robocopy is not already running
$roboCopy = Get-Process Robocopy -ErrorAction SilentlyContinue
if ($roboCopy) {
    $process = "robocopy.exe"
    $command = Get-CimInstance Win32_Process -Filter "name = '$process'" | Select-Object CommandLine
    if ($command) {
        Write-Log -Message "WARNING: Robocopy process already running." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1452 -EntryType Information -Message "Robocopy already running"
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1470 -EntryType Information -Message "Task Ended"
        Exit
    }
}

#Verifiy ROBO_C_LogOnly.log file is complete, delete if not
If (Test-Path -Path $roboCLogOnly) {
    If ((Get-Content $roboCLogOnly -tail 3) -like "*ended*") {
        Write-Log -Message "INFO: Existing Robocopy log only file contains valid summary, continuing..." -File $backupLogFile
    }
    Else {
        Write-Log -Message "INFO: Existing Robocopy log only file does not contain valid summary, deleting file..." -File $backupLogFile
        Remove-Item roboCLogOnly -Force
        Start-Sleep -Seconds 3
    }
}

#First run robocopy in logging mode only to output log file for generating upload/download progress bars
If (Test-Path -Path $roboCLogOnly){
    $ROBODLR = Get-Item $roboCLogOnly -ErrorAction SilentlyContinue
    $ROBODLRRanTime = $ROBODLR.CreationTime
    If ($ROBODLRRanTime -gt $ROBOLogDays){
        Write-Log -Message "INFO: Last Robocopy log only mode completed on $ROBODLRRanTime , bypassing." -File $backupLogFile
    }
    Else {
        Remove-Item $roboCLogOnly
        Write-Log -Message "INFO: Last Robocopy log only mode completed on $ROBODLRRanTime , now running Robocopy in log only mode..." -File $backupLogFile
        $proc = Start-Process Robocopy -ArgumentList "C:\ $UploadPath\$HostNameGUID\Clog /mir /copy:dt /mt:16 /l /is /it /w:0 /r:0 /nfl /ndl /np /njh /xj /bytes /xf$exfileslogonly /xd$exdirslogonly /LOG:$roboCLogOnly /a-:SH" -Wait -PassThru
    }
}
Else {
    Write-Log -Message "INFO: No Robocopy log only file found, now running Robocopy in log only mode..." -File $backupLogFile
    $proc = Start-Process Robocopy -ArgumentList "C:\ $backupDestination\Clog /mir /copy:dt /mt:16 /l /is /it /w:0 /r:0 /nfl /ndl /np /njh /xj /bytes /xf$exfileslogonly /xd$exdirslogonly /LOG:$LogPath\$HostNameGUID\ROBO_C_LogOnly.log /a-:SH" -Wait -PassThru
}

#Generate flat file with total data size and number of files
If (Test-Path -Path $roboCLogOnly){
    Write-Log -Message "INFO: Generating size and file count log file..." -File $backupLogFile
    Start-Sleep -s 1
    $fcount = Get-Content $roboCLogOnly -Raw | Select-RoboSummary | where{$_.Type -eq "Files"} | Select Copied -ExpandProperty Copied
    $fsize = Get-Content $roboCLogOnly -Raw | Select-RoboSummary | where{$_.Type -eq "Bytes"} | Select Copied -ExpandProperty Copied
    $x = "$fsize,$fcount"
    $x | Out-File -filepath $SizeFile -Force
    start-sleep -s 1
    Copy-Item $SizeFile -Destination "C:\windows\Temp\Size.txt" -Force
    Copy-Item $SizeFile -Destination "$backupLogDir\Size.txt" -Force
    New-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name TotalFileCount -PropertyType string -Value $fcount -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name TotalFileSize -PropertyType string -Value $fsize -Force -ErrorAction SilentlyContinue | Out-Null
}

#Create folder for Robocopy data
If (!(Test-Path -Path "$backupDestination\C")) {
    New-Item -ItemType Directory -Path "$backupDestination\C" | Out-Null
    Start-Sleep -Seconds 2
}

#Run Robocopy
Remove-Item "$UploadPath\$HostNameGUID\logs\Robo_c.log" -ErrorAction SilentlyContinue
$stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
If ($initialUpload) {
    Write-Log -Message "INFO: Initial Robocopy detected." -File $backupLogFile
    Write-Log -Message "INFO: Running RoboCopy..." -File $backupLogFile
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1464 -EntryType Information -Message "Initial file backup detected"
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1461 -EntryType Information -Message "Running file backup"
}
Else {
    Write-Log -Message "INFO: Running RoboCopy..." -File $backupLogFile
    Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1461 -EntryType Information -Message "Running file backup"
}
If ($LoggedOnUserAppDataDir) {
    $proc = Start-Process Robocopy -ArgumentList "C:\ $backupDestination\C /mir /copy:dt /mt:8 /w:0 /r:0 /tee /nfl /np /xj /xf$exfiles *.pst /xd$exdirs $LoggedOnUserAppDataDir /LOG:$backupDestination\ROBO_C.log /a-:SH" -Wait -PassThru
}
Else {
    $proc = Start-Process Robocopy -ArgumentList "C:\ $backupDestination\C /mir /copy:dt /mt:8 /w:0 /r:0 /tee /nfl /np /xj /xf$exfiles /xd$exdirs AppData /LOG:$backupDestination\ROBO_C.log /a-:SH" -Wait -PassThru
}

#Get the time to run for Robocopy
$HoursRan = [math]::Round($StopWatch.Elapsed.TotalHours,0)
$MinutesRan = [math]::Round($StopWatch.Elapsed.TotalMinutes,0)
$SecondsRan = [math]::Round($StopWatch.Elapsed.TotalSeconds,0)
$TimeToRun = "$($HoursRan):$($MinutesRan):$($SecondsRan)"
Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastRoboTimeToRun -Value $TimeToRun -ErrorAction SilentlyContinue | Out-Null

#Check Robocopy Return Code
$Result = $proc.ExitCode
Write-Log -Message "INFO: Robocopy return code: $Result" -File $backupLogFile
Write-Log -Message "INFO: Robocopy time to run: $MinutesRan mins." -File $backupLogFile

Switch ($Result) {
    0 {
        Write-Log -Message "INFO: Robocopy completed successfully, no new files copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    1 {
        Write-Log -Message "INFO: Robocopy completed successfully, new files copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    2 {
        Write-Log -Message "ERROR: Robocopy failed, extra files detected but not copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1463 -EntryType Information -Message "File backup failed"
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Failure" -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "fail"
    }
    3 {
        Write-Log -Message "INFO: Robocopy completed, additional files were present on the destination." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    4 {
        Write-Log -Message "ERROR: Robocopy failed, mismatched files detected." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1463 -EntryType Information -Message "File backup failed"
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Failure" -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "fail"
    }
    5 {
        Write-Log -Message "INFO: Robocopy completed, but some mismatched files were encountered." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    6 {
        Write-Log -Message "ERROR: Robocopy failed, additional files or mismatched files detected but not copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1463 -EntryType Information -Message "File backup failed"
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Failure" -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "fail"
    }
    7 {
        Write-Log -Message "ERROR: Robocopy completed, but file mismatch present." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    8 {
        Write-Log -Message "INFO: Robocopy failed, some files could not be copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1463 -EntryType Information -Message "File backup failed"
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Failure" -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "fail"
    }
    9 {
        Write-Log -Message "INFO: Robocopy completed, but some files could not be copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    11 {
        Write-Log -Message "INFO: Robocopy completed, but some files could not be copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    13 {
        Write-Log -Message "INFO: Robocopy completed, but some files could not be copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    15 {
        Write-Log -Message "INFO: Robocopy completed, but some files could not be copied." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1462 -EntryType Information -Message "File backup completed successfully"
        New-Item $DLCFile -ItemType File | Out-Null
        New-Item $ROBOSuccessFile -ItemType File -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Success" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name DateLastComplete -Value (Get-Date -format g) -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "success"
    }
    16 {
        Write-Log -Message "ERROR: Robocopy failed, serious error." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1463 -EntryType Information -Message "File backup failed"
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Failure" -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "fail"
    }
    default {
        Write-Log -Message "ERROR: Robocopy failed, unknown error." -File $backupLogFile
        Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1463 -EntryType Information -Message "File backup failed"
        Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastKnownState -Value "Failure" -ErrorAction SilentlyContinue | Out-Null
        $ROBOResult = "fail"
    }
}

#Check for EFS files in robo log again if robocopy failed
If ($ROBOResult -eq "fail") {
    Write-Log -Message "INFO: Checking for EFS files in Robo_C log..." -File $backupLogFile
    If (Test-Path -Path "$backupDestination\ROBO_C.log") {
        $EFSCheck = $null
        $EFSCheck = select-string -path "$backupDestination\ROBO_C.log" -pattern "The specified file could not be encrypted"
        If ($EFSCheck) {
            Write-Log -Message "WARNING: EFS files detected in Robo log." -File $backupLogFile
            $EFSCheck | Out-File -FilePath $EFSFile -Force
            Start-sleep -s 2
        }
        Else {
            Write-Log -Message "INFO: No EFS files detected." -File $backupLogFile
            If (Test-Path -path $EFSFile) {
                Write-Log -Message "INFO: Removing old EFS flag file..." -File $backupLogFile
                Remove-Item $EFSFile
            }
        }
    }
}
Else {
    If (Test-Path -path $EFSFile) {
        Write-Log -Message "INFO: Removing old EFS flag file..." -File $backupLogFile
        Remove-Item $EFSFile -ErrorAction Continue
        Remove-Item "$LogPath\$HostNameGUID\EFS.txt" -ErrorAction Continue
    }
}

#Write to registry
Set-ItemProperty -Path "HKLM:\Software\Wasteland\Backup" -Name LastRoboExitCode -Value $Result -ErrorAction SilentlyContinue | Out-Null

Write-Log -Message "INFO: Process complete, exiting." -File $backupLogFile
Write-EventLog -LogName "Application" -Source "Wasteland Backup System" -EventId 1470 -EntryType Information -Message "Task Ended"