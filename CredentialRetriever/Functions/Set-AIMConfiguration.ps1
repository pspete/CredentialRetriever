Function Set-AIMConfiguration {
	<#
	.SYNOPSIS
	Sets a variable in the script scope which holds default values for CLIPasswordSDK operations.
	Must be run prior to other module functions if path to CLIPasswordSDK has not been previously set.

	.DESCRIPTION
	Sets properties on an object which is used as the value of a variable in the script scope.
	The created variable can be queried and used by other module functions to provide default values.
	Creates a file in the logged on users home folder named AIMConfiguration.xml. This file contains the variable
	used by the module, and will be imported with the module into the module's scope.

	.PARAMETER ClientPath
	The path to the CLIPasswordSDK.exe utility

	.EXAMPLE
	Set-AIMConfiguration -ClientPath D:\Path\To\CLIPasswordSDK.exe

	Sets default path to CLIPasswordSDK to D:\Path\To\CLIPasswordSDK.exe.
	This is accessed via the variable property $Script:AIM.ClientPath
	Creates C:\users\user\AIMConfiguration.xml file to hold values for persistence.

	#>
	[CmdletBinding(SupportsShouldProcess)]
	Param(
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[ValidateScript( {Test-Path $_ -PathType Leaf})]
		[ValidateNotNullOrEmpty()]
		[string]$ClientPath
	)

	Begin {

		$Defaults = [pscustomobject]@{}

	}

	Process {

		If($PSBoundParameters.Keys -contains "ClientPath") {

			$Defaults | Add-Member -MemberType NoteProperty -Name ClientPath -Value $ClientPath

		}

	}

	End {

		Set-Variable -Name AIM -Value $Defaults -Scope Script

		$Script:AIM | Select-Object -Property * | Export-Clixml -Path "$env:HOMEDRIVE$env:HomePath\AIMConfiguration.xml" -Force

	}

}