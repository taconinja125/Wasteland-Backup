# Wasteland Backup

A robust and automated backup solution for Windows clients that provides comprehensive system backup capabilities with detailed logging and monitoring.

## Overview

Wasteland Backup is a PowerShell-based backup solution that creates systematic backups of Windows machines to a network file server. It includes features like unique machine identification, detailed logging, and intelligent backup scheduling.

## Key Features

- Unique machine identification using computer name and GUID
- Comprehensive event logging and backup status tracking
- Automatic detection and backup of fixed drives
- Robocopy-based file transfer with detailed statistics
- EFS (Encrypted File System) file detection
- Active user session monitoring
- Installed applications inventory
- System information collection
- Prevention of concurrent backup operations

## Components

### Core Script
- `Start-WastelandBackup.ps1`: Main backup script that orchestrates the entire backup process

### Registry Keys
- Location: `HKLM:\SOFTWARE\Wasteland\Backup`
- Stores: 
  - Machine GUID
  - Backup state information

### Log Files
- Windows Event Log: "Wasteland Backup System" source in Application log
- Detailed logs in `C:\Windows\Logs\WastelandBackup`
- Backup destination logs in `\\FILESERVER\Backups\[hostname]_[GUID]\Logs`

### Backup Location
- Network Path: `\\FILESERVER\Backups\[hostname]_[GUID]`
- Organized by unique machine identifier

## Process Flow

1. **Initialization**
   - Verify not running on virtual machine
   - Check for existing backup/download operations
   - Create necessary directories and log files

2. **System Information Collection**
   - Gather computer system information
   - List active users
   - Generate installed applications inventory
   - Identify fixed drives

3. **Backup Operation**
   - Execute Robocopy with detailed logging
   - Track file counts and sizes
   - Monitor for EFS files
   - Update backup completion status

4. **Logging and Status Updates**
   - Maintain detailed operation logs
   - Update Windows Event Log
   - Record backup statistics

## Requirements

- Windows operating system
- Network access to file server
- Administrative privileges for registry operations
- Robocopy (included in Windows)

## Monitoring and Maintenance

The backup system provides multiple monitoring points:
- Windows Event Log entries
- Detailed log files in both local and network locations
- Registry-based status tracking
- Backup completion indicators

## Error Handling

The script includes comprehensive error handling for:
- Network connectivity issues
- File access problems
- Concurrent operation prevention
- EFS file detection
- Robocopy operation failures

## Best Practices

1. Regular monitoring of backup logs
2. Periodic verification of backup integrity
3. Maintenance of sufficient network storage space
4. Review of excluded directories and files
