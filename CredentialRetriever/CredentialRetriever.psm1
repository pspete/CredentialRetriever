<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.INPUTS

.OUTPUTS

.NOTES

.LINK

#>
[CmdletBinding()]
param(

	[bool]$DotSourceModule = $false

)

#Get function files
Get-ChildItem $PSScriptRoot\ -Recurse -Include "*.ps1" |

ForEach-Object {

	if ($DotSourceModule) {
		. $_.FullName
	} else {
		$ExecutionContext.InvokeCommand.InvokeScript(
			$false,
			(
				[scriptblock]::Create(
					[io.file]::ReadAllText(
						$_.FullName,
						[Text.Encoding]::UTF8
					)
				)
			),
			$null,
			$null
		)

	}

}

#Read config and make available in script scope
$ConfigFile = Join-Path -Path $HOME -ChildPath 'AIMConfiguration.xml'
If (Test-Path $ConfigFile) {
	Write-Verbose "Importing Settings: $ConfigFile"
	$config = Import-Clixml -Path $ConfigFile
	Set-Variable -Name AIM -Value $config -Scope Script
} Else {
	#Use CLIPasswordSDK default install location, if present
	$ClientPath = @(
		"$env:ProgramFiles\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe",
		'/opt/CARKaim/sdk/clipasswordsdk'
	) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
	If ($ClientPath) {
		Write-Verbose "Using CLIPasswordSDK: $ClientPath"
		Set-Variable -Name AIM -Value ([pscustomobject]@{ ClientPath = $ClientPath }) -Scope Script
	}
}