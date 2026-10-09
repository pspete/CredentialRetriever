# .ExternalHelp CredentialRetriever-help.xml
Function Get-AIMCredential {
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Suppress alert from ToSecureString ScriptMethod')]
	[CmdletBinding(DefaultParameterSetName = 'Default')]
	Param(
		# Unique ID of the application
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true
		)]
		[string]
		$AppID,

		# Safe name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[ValidatePattern('^[^;"]*$')]
		[string]
		$Safe,

		# Folder name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[ValidatePattern('^[^;"]*$')]
		[string]
		$Folder,

		# Object name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[ValidatePattern('^[^;"]*$')]
		[string]
		$Object,

		# Search username
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[ValidatePattern('^[^;"]*$')]
		[string]
		$UserName,

		# Search address
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[ValidatePattern('^[^;"]*$')]
		[string]
		$Address,

		# Search database
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[ValidatePattern('^[^;"]*$')]
		[string]
		$Database,

		# Set PolicyID
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[ValidatePattern('^[^;"]*$')]
		[string]
		$PolicyID,

		# Free query of account properties
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[ValidatePattern('^[^"]*$')]
		[string]
		$Query,

		# Set QueryFormat
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[ValidateSet('exact', 'regexp')]
		[string]
		$QueryFormat,

		# Required Properties
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[string[]]
		$RequiredProps,

		# Reason to record in audit log
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[ValidatePattern('^[^"]*$')]
		[string]
		$Reason,

		# Port for communication with the provider
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[int]
		$Port,

		# Number of seconds to try
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[int]
		$Timeout,

		# Return an error if a password change is in progress
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[switch]
		$FailRequestOnPasswordChange,

		# Output PSCredential object
		[Parameter(Mandatory = $false)]
		[switch]
		$AsCredential,

		# Output password as SecureString
		[Parameter(Mandatory = $false)]
		[switch]
		$AsSecureString
	)

	Begin {
		#Function Parameters which will form any query string
		$QueryParameters = @(
			'Safe',
			'Folder',
			'Object',
			'UserName',
			'Address',
			'Database'
			'PolicyID'
		)

		$ConnectionParms = @(
			'Port',
			'Timeout'
		)

		#Delimiter for separating the output fields
		$Separator = '#_-_#'

		#CLIPasswordSDK argument prefix: / on Windows, - on Linux
		$Prefix = if ($IsWindows -eq $false) { '-' } else { '/' }

		if ($AsCredential -and $AsSecureString) {
			throw 'AsCredential and AsSecureString cannot be used together.'
		}

	}

	Process {

		#Array to hold the Properties to return
		[array]$ReturnProps = @()
		#Hashtable to hold the Results to Output
		[hashtable]$Output = @{ }

		#Initial Command String
		$Command = "${Prefix}p AppDescs.AppID=`"$AppID`""

		If ($PSCmdlet.ParameterSetName -eq 'Query') {

			$QueryString = $Query

		} Else {

			#Build query string from search parameters
			#"Property=Value;Property=Value;Property=Value"
			$QueryString = ($QueryParameters | Where-Object { $PSBoundParameters.ContainsKey($_) } | ForEach-Object {
					"$_=$($PSBoundParameters[$_])"
				}) -join ';'

		}

		If ($QueryString) {

			#Add Query to Command String
			$Command = "$Command ${Prefix}p Query=""$QueryString"""

		}

		#Build Command String
		switch ( $PSBoundParameters.Keys ) {

			'QueryFormat' {

				#Add QueryFormat Command String
				$Command = "$Command ${Prefix}p QueryFormat=`"$QueryFormat`""

			}

			'Reason' {

				#Add Reason to Command String
				$Command = "$Command ${Prefix}p Reason=`"$Reason`""

			}

			'FailRequestOnPasswordChange' {

				#Add FailRequestOnPasswordChange to Command String
				$Command = "$Command ${Prefix}p FailRequestOnPasswordChange=$("$($FailRequestOnPasswordChange.IsPresent)".ToLower())"

			}

			{ $ConnectionParms -contains $PSItem } {

				#Add ConnectionParms to Command String
				$Command = "$Command ${Prefix}p ConnectionParms.$_=$($PSBoundParameters[$_])"

			}

		}

		#UserName is required for PSCredential output
		$Props = @($RequiredProps | Where-Object { $_ })
		If ($AsCredential -and ($Props -notcontains 'UserName')) { $Props += 'UserName' }

		If ($Props.Count -gt 0) {

			#Add RequiredProps to Command String
			$Props | ForEach-Object {

				$ReturnProps += "PassProps.$_"
			}

			$Command = "$Command ${Prefix}p RequiredProps=$($Props -join ',')"

		}

		#Add Password & PasswordChangeInProcess to output fields
		$ReturnProps += 'Password'
		$ReturnProps += 'PasswordChangeInProcess'
		#Create Output fields string PropX,PropY,PropZ, Password, PasswordChangeInProcess
		$ReturnProps = $ReturnProps -join ','

		#Build Command String
		$Command = "$Command ${Prefix}o $ReturnProps ${Prefix}d $Separator"

		#Invoke Credential Provider
		$Result = Invoke-AIMClient -CommandParameters $Command

		#Output on StdOut
		If ($null -ne $Result.StdOut) {

			#split returned results at Separator
			$Results = ($Result.StdOut) -Split $Separator

			#use $returnProps to determine propertynames
			$ReturnProps = $ReturnProps.Split(',')

			For ($i = 0 ; $i -lt $ReturnProps.length ; $i++) {

				#PropertyName=PropertyValue
				$Value = ($Results[$i]).trim()

				#<na> (property does not exist) & <null> (property has no value) are output as $null
				If (($ReturnProps[$i] -like 'PassProps.*') -and ($Value -in '<na>', '<null>')) { $Value = $null }

				$Output[$(($ReturnProps[$i]) -replace 'PassProps.', '')] = $Value

			}

			#Create Output Object with Property Values
			$OutputObject = New-Object -TypeName PSObject -Property $Output

			#Add ScriptMethod to output object to convert password to Secure String
			$OutputObject | Add-Member -MemberType ScriptMethod -Name ToSecureString -Value {

				$this.Password | ConvertTo-SecureString -AsPlainText -Force

			} -Force

			#Add ScriptMethod to output object to convert username & password to Credential Object
			$OutputObject | Add-Member -MemberType ScriptMethod -Name ToCredential -Value {

				New-Object System.Management.Automation.PSCredential($this.UserName, $this.ToSecureString())

			} -Force

			#Return the result from AIM CP
			if ($AsCredential) {
				$OutputObject.ToCredential()
			} elseif ($AsSecureString) {
				$OutputObject.ToSecureString()
			} else {
				$OutputObject
			}

		}

	}

}