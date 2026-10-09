Function Invoke-AIMClient {

	<#
    .SYNOPSIS
	Defines specified CLIPasswordSDK command and arguments

    .DESCRIPTION
	Defines a CLIPasswordSDK process object with arguments required for specific command.

	.PARAMETER ClientPath
	The Path to CLIPasswordSDK.exe.
	Defaults to value of $Script:AIM.ClientPath, which is set during module import or via Set-AIMConfiguration.

	.PARAMETER Command
	The CLIPasswordSDK command to execute. Defaults to GetPassword.

	.PARAMETER CommandParameters
	The CLIPasswordSDK command parameters

	.PARAMETER Options
	Additional command options.

    .EXAMPLE
	Invoke-AIMClient -CommandParameters "/p AppDescs.AppID=TestApp /p RequiredProps=UserName,Address /p Query="Safe=TestSafe;Folder=Root;UserName=TestUser1" /o PassProps.UserName,PassProps.Address,Password,PasswordChangeInProcess""

	Invokes the GetPassword action using the provided arguments.

    .NOTES
    	AUTHOR: Pete Maan

    #>

	[CmdLetBinding(SupportsShouldProcess)]
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
		[string]$Command = 'GetPassword',

		[Parameter(
			Mandatory = $True,
			ValueFromPipelineByPropertyName = $True
		)]
		[string]$CommandParameters,

		[Parameter(Mandatory = $False,
			ValueFromPipelineByPropertyName = $True
		)]
		[string]$Options
	)

	Begin {

		#Create process
		$Process = New-Object System.Diagnostics.Process

	}

	Process {

		#Check we have the path to the required client executable
		if (-not $ClientPath) {

			throw "CLIPasswordSDK path not set `nRun Set-AIMConfiguration to set path to CLIPasswordSDK"

		} elseif (-not (Test-Path -LiteralPath $ClientPath -PathType Leaf)) {

			throw "CLIPasswordSDK not found at '$ClientPath' `nRun Set-AIMConfiguration to set path to CLIPasswordSDK"

		}

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
			$Process.StartInfo.WindowStyle = 'hidden'

			#Start Process
			$Result = Start-AIMClientProcess -Process $Process -ErrorAction Stop

			#Return Error or Result
			if ($Result.StdErr -match '((?:^[A-Z]{5}[0-9]{3}[A-Z])|(?:ERROR \(\d+\)))(?::)? (.+)$') {

				#APPAP008E Problem occurred while trying to use user in the Vault
				Write-Debug "ErrorId: $($Matches[1])"
				Write-Debug "Message: $($Matches[2])"
				Write-Error -Message $Matches[2] -ErrorId $Matches[1]

			} ElseIf ($Result.ExitCode) {

				#Process failed without a recognised error message (e.g. crash or missing dependency)
				$Message = 'CLIPasswordSDK exited with code 0x{0:X8}' -f $Result.ExitCode
				if ($Result.StdErr) { $Message = "$Message`: $(([string]$Result.StdErr).Trim())" }
				Write-Error -Message $Message -ErrorId 'AIMClientExitCode'

			} Else { $Result }
		}

	}

	End {

		$Process.Dispose()

	}

}