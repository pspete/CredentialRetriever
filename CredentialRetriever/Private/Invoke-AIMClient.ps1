Function Invoke-AIMClient {

	<#
    .SYNOPSIS
	Defines specified CLIPasswordSDK command and arguments

    .DESCRIPTION
	Defines a CLIPasswordSDK process object with arguments required for specific command.

	.PARAMETER ClientPath
	The Path to CLIPasswordSDK.exe.
	Defaults to value of $Script:AIM.ClientPath, which is set during module import or via Set-AIMConfiguration.

	.PARAMETER CommandParameters
	The CLIPasswordSDK command to execute

	.PARAMETER PAROptions
	Additional command parameters.

	.PARAMETER RemainingArgs
	A catch all parameter, accepts any remaining values from pipeline.
	Intended to suppress errors when piping in an object.

    .EXAMPLE
	Invoke-AIMClient -CommandParameters "/p AppDescs.AppID=TestApp /p RequiredProps=UserName,Address /p Query="Safe=TestSafe;Folder=Root;UserName=TestUser1" /o PassProps.UserName,PassProps.Address,Password,PasswordChangeInProcess""

	Invokes the GetPassword action using the provided arguments.

    .NOTES
    	AUTHOR: Pete Maan

    #>

	[CmdLetBinding(SupportsShouldProcess)]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "RemainingArgs", Justification = "Intentionally Unused Parameter")]
	param(

		[Parameter(
			Mandatory = $False,
			ValueFromPipelineByPropertyName = $True
		)]
		[string]$ClientPath = $Script:AIM.ClientPath,

		[Parameter(
			Mandatory = $False,
			ValueFromPipelineByPropertyName = $True
		)]
		[string]$Command = "GetPassword",

		[Parameter(
			Mandatory = $True,
			ValueFromPipelineByPropertyName = $True
		)]
		[string]$CommandParameters,

		[Parameter(Mandatory = $False,
			ValueFromPipelineByPropertyName = $True
		)]
		[string]$Options,

		[Parameter(Mandatory = $False,
			ValueFromPipelineByPropertyName = $False,
			ValueFromRemainingArguments = $true
		)]
		$RemainingArgs
	)

	Begin {

		$ErrorActionPreference = "Stop"

		Try {

			Get-Variable -Name AIM -ErrorAction Stop

			#Check we have the path to the required client executable
			if($AIM.PSObject.Properties.Name -notcontains "ClientPath") {

				Write-Error "Heads Up!" -ErrorAction Stop

			}

		} Catch {throw "CLIPasswordSDK.exe not found `nRun Set-AIMConfiguration to set path to CLIPasswordSDK"}

		#Create process
		$Process = New-Object System.Diagnostics.Process

	}

	Process {

		if ($PSCmdlet.ShouldProcess($ClientPath, "$CommandParameters")) {

			Write-Debug "Command Arguments: $Command $Options $CommandParameters"

			#Assign process parameters

			$Process.StartInfo.WorkingDirectory = "$(Split-Path $ClientPath -Parent)"
			$Process.StartInfo.Filename = $ClientPath
			$Process.StartInfo.Arguments = "$Command $Options $CommandParameters"
			$Process.StartInfo.RedirectStandardOutput = $True
			$Process.StartInfo.RedirectStandardError = $True
			$Process.StartInfo.UseShellExecute = $False
			$Process.StartInfo.CreateNoWindow = $True
			$Process.StartInfo.WindowStyle = "hidden"

			#Start Process
			$Result = Start-AIMClientProcess -Process $Process

			#Return Error or Result
			if($Result.StdErr -match '((?:^[A-Z]{5}[0-9]{3}[A-Z])|(?:ERROR \(\d+\)))(?::)? (.+)$') {

				#APPAP008E Problem occurred while trying to use user in the Vault
				Write-Debug "ErrorId: $($Matches[1])"
				Write-Debug "Message: $($Matches[2])"
				Write-Error -Message $Matches[2] -ErrorId $Matches[1]

			} Else {$Result}
		}

	}

	End {

		$Process.Dispose()

	}

}