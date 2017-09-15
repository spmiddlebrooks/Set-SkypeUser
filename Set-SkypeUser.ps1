<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.NOTES
	Version: 1.0
	Updated: 9/15/2017 1814
	Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
.LINK
	https://github.com/spmiddlebrooks
#>
#Requires -Version 3.0
#Requires -Modules Lync

[CmdletBinding(SupportsShouldProcess=$true)]
param( 
	[Parameter(Mandatory=$True,Position=0)]
		[ValidateScript({
			if ( Test-Path $_ ) {$True}
			else {Throw "FilePath $_ not found"}
		})]	
		[string] $FilePath,
	[Parameter(Mandatory=$False)]
		[switch] $ShowCommands
)


function Test-CsvFormat {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .NOTES
	    Version: 1.0
	    Updated: 9/15/2017 0753
	    Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
    .LINK
	    https://github.com/spmiddlebrooks
    #>
	param (
		[string] $CsvFilePath
	)
	$Csv = Import-CSV $CsvFilePath

	## List all columns that MUST be in the csv:
	$ColumnsExpected = @(
		'userPrincipalName'
	)

	## Verify that all expected columns are there (additional columns in the csv will be ignored)
	$ColumnsOK = $True
	$ColumnsCsv = $Csv | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
	
	$ColumnsExpected | ForEach-Object {
		If ($ColumnsCsv -notcontains $_) {
			$ColumnsOK = $False
			"Expected column not found: '$($_)'" | Write-Host -ForegroundColor Red
		}
	}
	
	If ($ColumnsOK) {
		return $Csv,$ColumnsCsv
	}
	else {
		Throw "The csv format is incorrect!"
	}
}
# End function Test-CsvFormat

function Invoke-CommandLine {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .NOTES
	    Version: 1.0
	    Updated: 9/15/2017 0753
	    Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
    .LINK
	    https://github.com/spmiddlebrooks
    #>
	[CmdletBinding(SupportsShouldProcess=$true)]
	param (
		[string] $userPrincipalName,
		[string] $Command
	)
    # $PSCmdlet.ShouldProcess("Target", "Action")
	if ( $PSCmdlet.ShouldProcess($userPrincipalName,$Command) ) {
		if ($ShowCommands) { Write-Color -Text 'Show Command: ', $Command -Color Cyan, Green }
		Invoke-Expression $Command
	}
}
# End function Invoke-CommandLine

function Write-Color {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .NOTES
	    Version: 1.0
	    Updated: 9/15/2017 1041
	    Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
    .LINK
	    https://github.com/spmiddlebrooks
    #>
	param (
		[String[]] $Text, 
		[ConsoleColor[]] $Color = "White", 
		[int] $StartTab = 0, 
		[int] $LinesBefore = 0,
		[int] $LinesAfter = 0,
		[string] $LogFile = "",
		$TimeFormat = "yyyy-MM-dd HH:mm:ss"
	)
    # [enum]::GetValues([System.ConsoleColor]) | Foreach-Object {Write-Host $_ -ForegroundColor $_ }
 
    $DefaultColor = $Color[0]
    if ($LinesBefore -ne 0) {  for ($i = 0; $i -lt $LinesBefore; $i++) { Write-Host "`n" -NoNewline } } # Add empty line before
    if ($StartTab -ne 0) {  for ($i = 0; $i -lt $StartTab; $i++) { Write-Host "`t" -NoNewLine } }  # Add TABS before text
    if ($Color.Count -ge $Text.Count) {
        for ($i = 0; $i -lt $Text.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine } 
    } else {
        for ($i = 0; $i -lt $Color.Length ; $i++) { Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine }
        for ($i = $Color.Length; $i -lt $Text.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $DefaultColor -NoNewLine }
    }
    Write-Host
    if ($LinesAfter -ne 0) {  for ($i = 0; $i -lt $LinesAfter; $i++) { Write-Host "`n" } }  # Add empty line after
    if ($LogFile -ne "") {
        $TextToFile = ""
        for ($i = 0; $i -lt $Text.Length; $i++) {
            $TextToFile += $Text[$i]
        }
        Write-Output "[$([datetime]::Now.ToString($TimeFormat))]$TextToFile" | Out-File $LogFile -Encoding unicode -Append
    }
}
# End function Start-Command


############################################################################
$RowNumber = 1
$E164RegEx = '^tel:\+\d{7,15}(;ext=\d+)?$'
$SipUriRegex = '^sip:.+@.+$'
$NonSipUriRegex = '^.+@.+$'
$CsPolicyNameRegEx = '^[A-Za-z0-9\-_ ]+$'

	
If ($AllCsvUsers,$ColumnsCsv = Test-CsvFormat $FilePath) {
	
	Foreach ($CsvUser in $AllCsvUsers) {
    
		if ($AllCsvUsers.Count -le 1) { $AllCsvUsersCount = 1 }
		else { $AllCsvUsersCount = $AllCsvUsers.Count }
	
		Write-Progress -Activity "Processing Users" -Status "Processing $RowNumber of $AllCsvUsersCount" -PercentComplete (($RowNumber / $AllCsvUsersCount) * 100)
		$RowNumber += 1

		# Check to see if user is already enabled in Lync/Skype
		$CsUserObject = Get-CsUser -Identity $($CsvUser.userPrincipalName) -ErrorAction SilentlyContinue

		#### Logic for when a user is already Lync/Skype enabled
        # If a user is already enabled in Lync/Skype...
		if ( $CsUserObject ) {
			# If TargetLineUri is set and matches E164 formatting...
			if ( $($CsvUser.TargetLineUri) -match $E164RegEx ) {
                # If the user is already EV enabled, update user's Line Uri
                if ( $CsUserObject.EnterpriseVoiceEnabled ) {
				    Invoke-CommandLine $CsvUser.userPrincipalName "Set-CsUser -Identity $($CsvUser.userPrincipalName) -LineUri $($CsvUser.TargetLineUri)"
                }
                # Else if TargetEnterpriseVoiceEnabled is TRUE, then enable EV and set user's Line Uri
                elseif ( $CsvCuser.TargetEnterpriseVoiceEnabled ) {
                    Invoke-CommandLine $CsvUser.userPrincipalName "Set-CsUser -Identity $($CsvUser.userPrincipalName) -EnterpriseVoiceEnabled `$True -LineUri $($CsvUser.TargetLineUri)"
                }
			}
			# Else if TargetEnterpriseVoiceEnabled is set to $False, disable EV for user and set LineUri to $null
			elseif ( $($CsvUser.TargetEnterpriseVoiceEnabled) -eq $False ) {
				Invoke-CommandLine $CsvUser.userPrincipalName "Set-CsUser -Identity $($CsvUser.userPrincipalName) -EnterpriseVoiceEnabled `$False -LineUri `$null"
			}


			# If TargetRegistrarPool is set AND TargetRegistrarpool is not the same as the user's current RegistrarPool, move user to new pool
			if ( $($CsvUser.TargetRegistrarPool) -and $($CsvUser.TargetRegistrarPool) -ne $($CsUserObject.RegistrarPool) ) {
				Invoke-CommandLine $CsvUser.userPrincipalName "Move-CsUser -Identity $($CsvUser.userPrincipalName) -Target $($CsvUser.TargetRegistrarPool) -Confirm:`$False"
			}

            # If TargetCsEnabled is FALSE, disable the Lync/Skype user
            if ( $($CsvUser.TargetCsEnabled) -eq $False ) {
                Invoke-CommandLine $CsvUser.userPrincipalName "Revoke-CsClientCertificate -Identity $($CsvUser.userPrincipalName)"
				Invoke-CommandLine $CsvUser.userPrincipalName "Disable-CsUser -Identity $($CsvUser.userPrincipalName)"
			}
		}
		#### Logic for enabling a user
        # If TargetCsEnabled is True and the user is not enabled in Lync/Skype...
		elseif ( $($CsvUser.TargetCsEnabled) -eq $True -and -Not $CsUserObject ) {
            # Enable the user
                if ( $($CsvUser.TargetSipAddress) -match $SipUriRegex ) {
                    Invoke-CommandLine $CsvUser.userPrincipalName "Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress $($CsvUser.TargetSipAddress)"
                }
                elseif ( $($CsvUser.TargetSipAddress) -match $NonSipUriRegex ) {
                    Invoke-CommandLine $CsvUser.userPrincipalName "Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress sip:$($CsvUser.TargetSipAddress)"
                }
            # Wait for the changes to replicate
			Start-Sleep -Seconds 10
            # If TargetEnterpriseVoiceEnabled is True and TargetLineUri matches E164 formatting, EV enable the user and set LineUri
			if ( $($CsvUser.TargetEnterpriseVoiceEnabled) -eq $True -and $($CsvUser.TargetLineUri) -match $E164RegEx ) {
                    Invoke-CommandLine $CsvUser.userPrincipalName "Set-CsUser -Identity $($CsvUser.userPrincipalName) -EnterpriseVoiceEnabled `$True -LineUri $($CsvUser.TargetLineUri)"
            }
		}

		foreach ($Column in $ColumnsCsv) {
			if ( ( $CsUserObject -or $($CsvUser.TargetCsEnabled) ) -and $Column -match 'Target(DialPlan|\w+Policy)' ) {
				$Command = $null
				$GrantCsCommand = "Grant-Cs" + $Matches[1]

				if ( $($CsvUser.$Column) -eq "null" ) {
					$Command =  $GrantCsCommand + " -PolicyName `$null -Identity $($CsvUser.userPrincipalName)"
				}
				elseif ( $($CsvUser.$Column) -match $CsPolicyNameRegEx ) {
					$Command = $GrantCsCommand + " -PolicyName ""$($CsvUser.$Column)"" -Identity $($CsvUser.userPrincipalName)"
				}

				if ($Command) {
					Invoke-CommandLine $CsvUser.userPrincipalName $Command
				}
			}
		}
	}
}
