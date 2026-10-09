# .ExternalHelp CredentialRetriever-help.xml
Function Set-AIMConfiguration {
	[CmdletBinding(SupportsShouldProcess)]
	Param(
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true
		)]
		[ValidateScript( { Test-Path $_ -PathType Leaf })]
		[ValidateNotNullOrEmpty()]
		[string]$ClientPath
	)

	Process {

		$ConfigFile = Join-Path -Path $HOME -ChildPath 'AIMConfiguration.xml'

		if ($PSCmdlet.ShouldProcess($ConfigFile, "Set ClientPath to $ClientPath")) {

			Set-Variable -Name AIM -Value ([pscustomobject]@{ ClientPath = $ClientPath }) -Scope Script

			$Script:AIM | Export-Clixml -Path $ConfigFile -Force

		}

	}

}
