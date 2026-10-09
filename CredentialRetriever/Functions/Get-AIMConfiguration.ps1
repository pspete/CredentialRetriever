Function Get-AIMConfiguration {
	<#
	.SYNOPSIS
	Gets the configuration used for CLIPasswordSDK operations.

	.DESCRIPTION
	Outputs the configuration object used by module functions to provide default values for CLIPasswordSDK operations.
	The configuration is imported with the module from $HOME\AIMConfiguration.xml, or set via Set-AIMConfiguration.
	If no configuration file exists, and CLIPasswordSDK is installed in its default location, the default location is used.
	Outputs nothing if no configuration has been set.

	.EXAMPLE
	Get-AIMConfiguration

	Outputs the current configuration:

	ClientPath
	----------
	C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe

	#>
	[CmdletBinding()]
	Param()

	Get-Variable -Name AIM -Scope Script -ValueOnly -ErrorAction SilentlyContinue

}
