#Requires -Version 5.1
<#
.SYNOPSIS
    Tests NTFS automatic removal of purgeable Trusted Installer Kernel EAs.

.DESCRIPTION
    Appends one null byte (0x00) to an existing file and then truncates the
    file back to its original size. This intentionally generates file-data
    modifications that NTFS uses to invalidate purgeable Kernel Extended
    Attributes (EAs), including an Airlock Digital Trusted Installer EA:

        $KERNEL.PURGE.AIRLOCK.TRUSTEDINSTALLER.VALID

    WHAT ARE KERNEL EXTENDED ATTRIBUTES?
    ------------------------------------
    NTFS has supported Kernel EAs since Windows 8. EAs are metadata associated
    with files, separate from their primary contents. Names beginning with
    "$Kernel." identify Kernel EAs; user-mode callers can query them but
    cannot directly set or modify them. Kernel-mode software can use these
    attributes to cache file-validation or trust information.

    WHY DOES A FILE MODIFICATION REMOVE THIS EA?
    --------------------------------------------
    NTFS automatically deletes Kernel EAs beginning with "$Kernel.Purge."
    when the file receives any of these USN Journal reasons:

        USN_REASON_DATA_OVERWRITE
        USN_REASON_DATA_EXTEND
        USN_REASON_DATA_TRUNCATION
        USN_REASON_REPARSE_POINT_CHANGE

    This script uses DATA_EXTEND (append one byte) and DATA_TRUNCATION
    (remove that byte). NTFS, not this script, performs any EA deletion.
    Other purgeable Kernel EAs on the same file can be removed as well.

    WHY RESTORE THE ORIGINAL SIZE?
    ------------------------------
    Restoring the original size also restores the original byte sequence
    after a successful append/truncate cycle. In particular, the final file
    content hash should match its original hash, although filesystem
    metadata (including modification time and Kernel EAs) may have changed.
    This demonstrates that a file's trust metadata can be invalidated even
    when its final contents are unchanged.

    LIMITATIONS AND PRECAUTIONS
    ---------------------------
    * The target must be an existing file on NTFS and writable by the caller.
    * Do not use production-critical files. Other applications may react to
      the intermediate modification or to the invalidated trust metadata.
    * This script DOES NOT inspect EAs or verify that one was removed.
      Inspect the target's EAs before and after to confirm the result.
    * It DOES NOT restore the original last-write timestamp or trust state.
    * If an unexpected error or concurrent writer interferes, the script
      attempts to restore the original length but cannot guarantee recovery.
    * Neither an unchanged final hash nor a successful script run, by
      itself, proves that a particular EA was previously present or removed.

.NOTES
    Author: Patrick Van Zandt
    Date: 2026-10-08

.PARAMETER Path
    Path to the existing file to modify. Defaults to C:\Temp\test.exe.

.EXAMPLE
    .\Test-TrustedInstallerEARemoval.ps1 -Path 'C:\Temp\test.exe'

    Modifies the test file and restores its original length.

.REFERENCE
    Microsoft Learn: Kernel Extended Attributes
    https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/kernel-extended-attributes
    See "Auto-Deletion of Kernel Extended Attributes".
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Path = 'C:\Temp\test.exe'
)

$stream = $null
$originalLength = $null
$restored = $false

try {
    # Opening with FileShare.None reduces the risk of concurrent changes.
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )

    $originalLength = $stream.Length
    Write-Host "Target: $Path"
    Write-Host "Original size: $originalLength bytes"

    # Data extension is one of the documented NTFS purge triggers.
    [void]$stream.Seek(0, [System.IO.SeekOrigin]::End)
    $stream.WriteByte(0x00)
    $stream.Flush()
    Write-Host "Appended 0x00. Size: $($stream.Length) bytes"

    # Truncation is another documented NTFS purge trigger.
    $stream.SetLength($originalLength)
    $stream.Flush()
    $restored = $true
    Write-Host "Removed appended byte. Size: $($stream.Length) bytes"
    Write-Host 'Complete. Inspect Kernel EAs separately to confirm removal.'
}
finally {
    if ($null -ne $stream) {
        if (-not $restored -and $null -ne $originalLength) {
            try {
                $stream.SetLength($originalLength)
                $stream.Flush()
                Write-Warning 'An error occurred; attempted to restore the original file length.'
            }
            catch {
                Write-Warning "Unable to restore original file length: $($_.Exception.Message)"
            }
        }
        $stream.Dispose()
    }
}
