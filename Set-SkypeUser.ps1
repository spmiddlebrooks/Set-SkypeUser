<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.NOTES
	Version: 1.0
	Updated: 9/12/2017
	Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
.LINK
	https://github.com/spmiddlebrooks
#>
#Requires -Version 3.0
#Requires -Modules Lync

[CmdletBinding(SupportsShouldProcess=$true)]
param( 
	[Parameter(Mandatory=$True)]
		[ValidateScript({
			if ( Test-Path $_ ) {$True}
			else {Throw "FilePath $_ not found"}
		})]	
		[string] $FilePath
)


function Test-CsvFormat {
	param (
		[string] $CsvFilePath
	)
	$Csv = Import-CSV $CsvFilePath

	## List all columns that MUST be in the csv:
	$ColumnsExpected = @(
		'userPrincipalName',
		'TargetRegistrarPool'
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

function Start-Command {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param (
		[string] $userPrincipalName,
		[string] $Command
	)

	if ( $pscmdlet.ShouldProcess($userPrincipalName,$Command) ) {
		Invoke-Expression $Command
	}
}

############################################################################
$RowNumber = 1
	
If ($AllCsvUsers,$ColumnsCsv = Test-CsvFormat $FilePath) {
	
	Foreach ($CsvUser in $AllCsvUsers) {
    
		if ($AllCsvUsers.Count -le 1) { $AllCsvUsersCount = 1 }
		else { $AllCsvUsersCount = $AllCsvUsers.Count }
	
		Write-Progress -Activity "Processing Users" -Status "Processing $RowNumber of $AllCsvUsersCount)" -PercentComplete (($RowNumber / $AllCsvUsers.Count) * 100)
		$RowNumber += 1
		
		# Update or Move an existing user
		if ( $($CsvUser.CsEnabled -eq $True) ) {
			# Move an existing user to a new pool
			if ( $($CsvUser.TargetRegistrarPool) ) {
				Start-Command $CsvUser.userPrincipalName "Move-CsUser -Identity $($CsvUser.userPrincipalName) -Target $($CsvUser.TargetRegistrarPool)"
			}
			# If TargetEnterpriseVoiceEnabled is set to $False, disable EV for a user and set LineUri to $null
			elseif ( $($CsvUser.TargetEnterpriseVoiceEnabled) -eq $False ) {
				Start-Command $CsvUser.userPrincipalName "Set-CsUser -Identity $($CsvUser.userPrincipalName) -EnterpriseVoiceEnabled $False -LineUri `$null"
			}
			# If EnterpriseVoice is already enabled for a user and TargetLineUri is set, update user's Line Uri
			elseif ( $($CsvUser.EnterpriseVoiceEnabled) -eq $True -and $($CsvUser.TargetLineUri) -match '^tel:\+\d{7,15}(;ext=\d+)?' ) {
				Start-Command $CsvUser.userPrincipalName "Set-CsUser -Identity $($CsvUser.userPrincipalName) -LineUri $($CsvUser.TargetLineUri)"
			}
		}
		# Enable a user
		elseif ( $($CsvUser.TargetCsEnabled -eq $True) ) {
			if ( $($CsvUser.TargetEnterpriseVoiceEnabled) -eq $True -and $($CsvUser.TargetLineUri) -match '^tel:\+\d{7,15}(;ext=\d+)?' ) {
				Start-Command $CsvUser.userPrincipalName "Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress $($CsvUser.TargetSipAddress)"
				Start-Sleep -Seconds 5
				Start-Command $CsvUser.userPrincipalName "Set-CsUser -Identity $($CsvUser.userPrincipalName) -EnterpriseVoiceEnabled $True -LineUri $($CsvUser.TargetLineUri)"
			}
			else {
				Start-Command $CsvUser.userPrincipalName "Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress $($CsvUser.TargetSipAddress)"
				Start-Sleep -Seconds 5
			}
		}

		foreach ($Column in $ColumnsCsv) {
			if ($Column -match 'Target(DialPlan|\w+Policy)') {
				$GrantCsCommand = "Grant-Cs" + $Matches[1]

				if ( $($CsvUser.$Column) -eq "" ) {
					continue
				}
				elseif ( $($CsvUser.$Column) -eq "null" ) {
					$Command = $GrantCsCommand + " -PolicyName `$null -Identity $($CsvUser.userPrincipalName)"
				}
				elseif ( $($CsvUser.$Column) -match '^[A-Za-z0-9\-_ ]+$' ) {
					$Command = $GrantCsCommand + " -PolicyName ""$($CsvUser.$Column)"" -Identity $($CsvUser.userPrincipalName)"
				}
				Start-Command $CsvUser.userPrincipalName $Command
				$Matches.Clear()
			}
		}
	}
}
