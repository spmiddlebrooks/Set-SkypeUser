<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.NOTES
	Version: 1.1.2
	Updated: 10/6/2017
	Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
.LINK
	https://github.com/spmiddlebrooks
#>
#Requires -Version 3.0


[CmdletBinding(SupportsShouldProcess=$true)]
param( 
	[Parameter(Mandatory=$True,Position=0)]
		[ValidateScript({
			if ( Test-Path $_ ) {$True}
			else {Throw "FilePath $_ not found"}
		})]	
		[string] $FilePath,
	[Parameter(Mandatory=$False)]
		[string] $LogPath="",
	[Parameter(Mandatory=$False)]
		[int] $ReplicationWaitInterval=5,
	[Parameter(Mandatory=$False)]
		[int] $ReplicationWaitRepetitions=6,
	[Parameter(Mandatory=$False)]
		[switch] $ShowCommands
)

function Set-ModuleStatus { 
<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.NOTES
	Original Author: Pat Richard
.LINK
	https://www.ucunleashed.com/938
#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param	(
		[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, HelpMessage = "No module name specified!")] 
		[ValidateNotNullOrEmpty()]
		[string] $name
	)
	PROCESS{
		# Executes once for each pipeline object
		# the $_ variable represents the current input object		
		if (!(Get-Module -name "$name")) { 
			if (Get-Module -ListAvailable | Where-Object Name -eq "$name") { 
				Import-Module -Name "$name"
				# module was imported
				return $true
			} else {
				# module was not available
				return $false
			}
		} else {
			# Write-Output "$_ module already imported"
			return $true
		} 
	} # end PROCESS
} 
# End function Set-ModuleStatus

function Test-CsvFormat {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .NOTES
	    Version: 1.1
	    Updated: 9/16/2017
	    Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
    .LINK
	    https://github.com/spmiddlebrooks
    #>
	param (
		[string] $CsvFilePath
	)
    $ColumnsCsvContainsRequired = $True
    $ColumnsCsvContainsTargets = $False

	$Csv = Import-CSV $CsvFilePath


	## These columns are required be in the CSV:
	$ColumnsRequired = @(
		'userPrincipalName'
	)

    # These columns are the valid operation Target columns, at least 1 must be present in the CSV, otherwise we have nothing to do
    $ValidTargetColumns = @('TargetCsEnabled','TargetSipAddress','TargetRegistrarPool','TargetLineUri','TargetEnterpriseVoiceEnabled')
    $ValidTargetColumns += @(Get-Command -Module $UcPlatform | ForEach { if ($_.Name -match $GrantCsRegex) {'Target' + $matches[1]} })
    

	## Get a list of all the column names in the CSV
	$ColumnsCsv = $Csv | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
	
    # Check the list of CSV columns for all the required columns
	$ColumnsRequired | ForEach-Object {
		If ($ColumnsCsv -notcontains $_) {
			$ColumnsCsvContainsRequired = $False
			"Required column not found: '$($_)'" | Write-Host -ForegroundColor Magenta
		}
	}

    # Check the list of CSV columns for the operation Target columns
	$ValidTargetColumns | ForEach-Object {
		If ($ColumnsCsv -contains $_) {
			$ColumnsCsvContainsTargets = $true
		}
	}

	# If all required columns and at least 1 operation Target column are present, we are good to go
	If ($ColumnsCsvContainsRequired -and $ColumnsCsvContainsTargets) {
		return $Csv,$ColumnsCsv
	}
    # Stop the script and throw an exception if we are missing the required columns
	elseif ($ColumnsCsvContainsRequired -eq $False -and $ColumnsCsvContainsTargets) {
		Throw "The CSV does not contain the required columns"
	}
    # Stop the script and throw an exception if don't have any operation Targets
	elseif ($ColumnsCsvContainsRequired -and $ColumnsCsvContainsTargets -eq $False) {
		Throw "The CSV does not contain any Target columns"
	}
    # Stop the script and throw an exception if we are missing the required columns and operation Target columns
    elseif ($ColumnsCsvContainsRequired -eq $False -and $ColumnsCsvContainsTargets -eq $False) {
		Throw "The CSV does not contain the required columns NOR does it contain any Target columns"
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
	    Version: 1.1
	    Updated: 9/18/2017 1546
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
		try {
            Invoke-Expression $Command
		    if ($ShowCommands) {
                Write-Log -Text 'Command Successful ', $Command -Color Green, Cyan -LogPath $LogPath
            }
            else {
                Write-Log -NoConsole -Text 'Command Successful ', $Command -LogPath $LogPath
            }
        }
        catch {
            Write-Log -Text 'Command Failed ', "$Command ", $($_.Exception.Message) -Color Red, Cyan, Magenta -LogPath $LogPath
			return $false
		}
    }
}
# End function Invoke-CommandLine

function Write-Log {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .NOTES
	    Version: 1.1
	    Updated: 9/18/2017 1546
	    Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
    .LINK
	    https://github.com/spmiddlebrooks
    #>
	param (
		[string[]] $Text, 
        [switch] $NoLog = $false,
        [switch] $NoConsole = $false,
		[ConsoleColor[]] $Color = "White", 
        #[int] $StartTab = 0, 
		#[int] $LinesBefore = 0,
		#[int] $LinesAfter = 0,
		[string] $LogPath = "",
        $TimeFormat = "s"
		#$TimeFormat = "yyyy-MM-dd HH:mm:ss"
	)
    # [enum]::GetValues([System.ConsoleColor]) | Foreach-Object {Write-Host $_ -ForegroundColor $_ }
 
    $DateTime = Get-Date -Format $TimeFormat
    $DefaultColor = $Color[0]

    if ($LogPath -and ($LogFolder = Split-Path -Path $LogPath -Parent)) {
        if (-not(Test-Path -Path $LogFolder)){
            $null = New-Item -Path $LogFolder -ItemType Directory
        }
    }

    <#
     # Add empty line before
    if ($LinesBefore -ne 0) {
        for ($i = 0; $i -lt $LinesBefore; $i++) {
            Write-Host "`n" -NoNewline
        }
    }

    # Add TABS before text
    if ($StartTab -ne 0) {
        for ($i = 0; $i -lt $StartTab; $i++) {
            Write-Host "`t" -NoNewLine
        }
    }
    #>

    if ($NoConsole -eq $False) {
        if ($Color.Count -ge $Text.Count) {
            for ($i = 0; $i -lt $Text.Length; $i++) {
                Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine
            }
        } 
        else {
            for ($i = 0; $i -lt $Color.Length ; $i++) {
                Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine
            }
            for ($i = $Color.Length; $i -lt $Text.Length; $i++) {
                Write-Host $Text[$i] -ForegroundColor $DefaultColor -NoNewLine
            }
        }
    }

    Write-Host

    <#
    # Add empty line after
    if ($LinesAfter -ne 0) {
        for ($i = 0; $i -lt $LinesAfter; $i++) {
            Write-Host "`n"
        }
    }
    #>

    if ($NoLog -eq $False -and $LogPath -ne "") {
        $TextToFile = @($DateTime) + $Text
        #for ($i = 0; $i -lt $Text.Length; $i++) {
        #    $TextToFile += $Text[$i]
        #}
        Write-Output ($TextToFile -join "`t") | Out-File $LogPath -Encoding ASCII -Append
    }
}
# End function Write-Log


############################################################################
$RowNumber = 1
$E164RegEx = '^tel:\+\d{7,15}(;ext=\d+)?$'
$SipUriRegex = '^sip:.+@.+$'
$NonSipUriRegex = '^.+@.+$'
$CsPolicyNameRegEx = '^[A-Za-z0-9\-_ ]+$'
$GrantCsRegex = 'Target(DialPlan|\w+Policy)'

# Attempt to load the SkypeforBusiness module
if (Set-ModuleStatus SkypeForBusiness) {
    $UcPlatform = 'SkypeforBusiness'
}
# If the SkypeforBusiness module is not present, attempt to load the Lync module
elseif (Set-ModuleStatus Lync) {
    $UcPlatform = 'Lync'
}
# If neither module is present throw an exception to prevent further operations
else {
    throw "Cannot proceed, could not load Skype for Business or Lync PowerShell module"
}

# Load the CSV file retrieving the list of users $AllCsvUsers and a list of columns $ColumnsCsv
If ( $AllCsvUsers,$ColumnsCsv = Test-CsvFormat $FilePath ) {
	
    # Iterate through each row in the list of users from th
	Foreach ($CsvUser in $AllCsvUsers) {
        if ($AllCsvUsers.Count) {
            $AllCsvUsersCount = $AllCsvUsers.Count
        }
        else { 
            $AllCsvUsersCount = 1
        }
	
		Write-Progress -Activity "Processing Users" -Status "Processing $RowNumber of $AllCsvUsersCount" -PercentComplete (($RowNumber / $AllCsvUsersCount) * 100)
        Start-Sleep -Milliseconds 200
		$RowNumber += 1

		# Check to see if user is already enabled in Lync/Skype
        if ($($CsvUser.userPrincipalName)) {
		    $CsUserObject = Get-CsUser -Identity $($CsvUser.userPrincipalName) -ErrorAction SilentlyContinue
        }

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
			[bool] $EnableCsUserSuccess=$false
            # Enable the user
                if ( $($CsvUser.TargetSipAddress) -match $SipUriRegex ) {
		            try {
                        $Command = "Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress $($CsvUser.TargetSipAddress)"
                        Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress $($CsvUser.TargetSipAddress)
		                if ($ShowCommands) {
                            Write-Log -Text 'Command Successful ', $Command -Color Green, Cyan -LogPath $LogPath
                        }
                        else {
                            Write-Log -NoConsole -Text 'Command Successful ', $Command -LogPath $LogPath
                        }
                        $EnableCsUserSuccess=$true
                    }
                    catch {
                        Write-Log -Text 'Command Failed ', "$Command ", $($_.Exception.Message) -Color Red, Cyan, Magenta -LogPath $LogPath
		            }
                    
                    <#
                    if (Invoke-CommandLine $CsvUser.userPrincipalName "Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress $($CsvUser.TargetSipAddress)") {
					}
                    else {
                        $EnableCsUserSuccess=$false
                    }
                    #>
                }
                elseif ( $($CsvUser.TargetSipAddress) -match $NonSipUriRegex ) {
		            try {
                        $Command = "Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress sip:$($CsvUser.TargetSipAddress)"
                        Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress sip:$($CsvUser.TargetSipAddress)
		                if ($ShowCommands) {
                            Write-Log -Text 'Command Successful ', $Command -Color Green, Cyan -LogPath $LogPath
                        }
                        else {
                            Write-Log -NoConsole -Text 'Command Successful ', $Command -LogPath $LogPath
                        }
                        $EnableCsUserSuccess=$true
                    }
                    catch {
                        Write-Log -Text 'Command Failed ', "$Command ", $($_.Exception.Message) -Color Red, Cyan, Magenta -LogPath $LogPath
		            }

                    <#
                    if (Invoke-CommandLine $CsvUser.userPrincipalName "Enable-CsUser -Identity $($CsvUser.userPrincipalName) -RegistrarPool $($CsvUser.TargetRegistrarPool) -SipAddress sip:$($CsvUser.TargetSipAddress)") {
					}
                    else {
                        $EnableCsUserSuccess=$false
                    }
                    #>
                }
            # Wait for the changes to replicate
            if ( $EnableCsUserSuccess) {
                $Iteration = 1
                $TotalIterations = $ReplicationWaitRepetitions
                do {
                    Write-Log -NoLog -Text "Pass $Iteration of $ReplicationWaitRepetitions - Waiting $ReplicationWaitInterval seconds for new user to replicate" -Color Yello
                    Start-Sleep -Seconds $ReplicationWaitInterval
                    $CsUserObject = (Get-CsUser -Identity $($CsvUser.userPrincipalName) -ErrorAction SilentlyContinue)
                    $t
                }
                until ($CsUserObject -or $TotalIterations -eq 0)

                # If TargetEnterpriseVoiceEnabled is True and TargetLineUri matches E164 formatting, EV enable the user and set LineUri
	    		if ( $($CsvUser.TargetEnterpriseVoiceEnabled) -eq $True -and $($CsvUser.TargetLineUri) -match $E164RegEx ) {
                        Invoke-CommandLine $CsvUser.userPrincipalName "Set-CsUser -Identity $($CsvUser.userPrincipalName) -EnterpriseVoiceEnabled `$True -LineUri $($CsvUser.TargetLineUri)"
                }
            }
		}

		foreach ($Column in $ColumnsCsv) {
			                        #$($CsvUser.TargetCsEnabled)
            if ( ($CsUserObject -or $EnableCsUserSuccess) -and $Column -match $GrantCsRegex ) {
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
