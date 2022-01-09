Function Get-AIMCredential {
	<#
	.SYNOPSIS
	Retrieves password from a local Credential Provider.

	.DESCRIPTION
	Sends a query via a local credential provider using the CLIPasswordSDK utility.
	Use the Set-AIMConfiguration function to set the path to the CLIPasswordSDK executable.

	.PARAMETER AppID
	Specifies the unique ID of the application issuing the password request.

	.PARAMETER Safe
	Specifies the name of the Safe where the password is stored.

	.PARAMETER Folder
	Specifies the name of the folder where the password is stored.

	.PARAMETER Object
	Specifies the name of the password object to retrieve.

	.PARAMETER UserName
	Defines search criteria according to the UserName account property.

	.PARAMETER Address
	Defines search criteria according to the Address account property.

	.PARAMETER Database
	Defines search criteria according to the Database account property.

	.PARAMETER PolicyID
	Defines search criteria according to the PolicyID account property.

	.PARAMETER QueryFormat
	Whether to search via "exact" or "regex" terms

	.PARAMETER RequiredProps
	Defines the names of the account properties you want to be returned in addition to the Password

	.PARAMETER Reason
	The reason for retrieving the password. This reason will be audited in the Credential Provider audit log

	.PARAMETER Port
	The port to communicate with the credential provider

	.PARAMETER Timeout
	Timeout value in seconds

	.EXAMPLE
	Get-AIMCredential -AppID YourApp -Safe YourSafe -Folder Root -UserName YourUser

	Returns the password found via the query definition:

	Password  PasswordChangeInProcess
	--------  -----------------------
	YourPass  false

	.EXAMPLE
	Get-AIMCredential -AppID YourApp -Safe YourSafe -UserName YourUser -RequiredProps Address,UserName

	Returns the password, address and username properties:

	Password   PasswordChangeInProcess UserName  Address
	--------   ----------------------- --------  -------
	YourPass   false                   YourUser DOMAIN.COM

	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Suppress alert from ToSecureString ScriptMethod')]
	[CmdletBinding()]
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
			ValueFromPipeline = $true
		)]
		[string]
		$Safe,

		# Folder name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[string]
		$Folder,

		# Object name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[string]
		$Object,

		# Search username
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[string]
		$UserName,

		# Search address
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[string]
		$Address,

		# Search database
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[string]
		$Database,

		# Set PolicyID
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true
		)]
		[string]
		$PolicyID,

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
		$Timeout
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

		#Array to hold the Properties to return
		[array]$ReturnProps = @()
		#Hashtable to hold the Results to Output
		[hashtable]$Output = @{ }
		#Delimiter for separating the output fields
		$Separator = '#_-_#'

	}

	Process {

		#Initial Command String
		$Command = "/p AppDescs.AppID=`"$AppID`""

		#Build array of query string properties
		$PSBoundParameters.Add('Query', @())
		$QueryParameters | ForEach-Object {

			If ($PSBoundParameters.ContainsKey("$_")) {


				$PSBoundParameters['Query'] += "$_=$($PSBoundParameters["$_"])"
			}

		}

		#Build Command String
		switch ( $PSBoundParameters.Keys ) {

			'Query' {

				#Add Query to Command String
				#"Property=Value;Property=Value;Property=Value"
				$Command = "$Command /p Query=""$($PSBoundParameters['Query'] -join ';')"""

			}

			'QueryFormat' {

				#Add QueryFormat Command String
				$Command = "$Command /p QueryFormat=`"$QueryFormat`""

			}

			'RequiredProps' {

				#Add RequiredProps to Command String
				$RequiredProps | ForEach-Object {

					$ReturnProps += "PassProps.$_"
				}

				$Command = "$Command /p RequiredProps=$($RequiredProps -join ',')"

			}

			'Reason' {

				#Add Reason to Command String
				$Command = "$Command /p Reason=`"$Reason`""

			}

			{ $ConnectionParms -contains $PSItem } {

				#Add ConnectionParms to Command String
				$Command = "$Command /p ConnectionParms.$_=$($PSBoundParameters[$_])"

			}

		}

		#Add Password & PasswordChangeInProcess to output fields
		$ReturnProps += 'Password'
		$ReturnProps += 'PasswordChangeInProcess'
		#Create Output fields string PropX,PropY,PropZ, Password, PasswordChangeInProcess
		$ReturnProps = $ReturnProps -join ','

		#Build Command String
		$Command = "$Command /o $ReturnProps /d $Separator"

		#Add CommandParameters to $PSBoundParameters for Splat against Invoke-AIMClient
		$PSBoundParameters.Add('CommandParameters', "$Command")

		#Invoke Credential Provider
		$Result = Invoke-AIMClient @PSBoundParameters

		#Output on StdOut
		If ($null -ne $Result.StdOut) {

			#split returned results at Separator
			$Results = ($Result.StdOut) -Split $Separator

			#use $returnProps to determine propertynames
			$ReturnProps = $ReturnProps.Split(',')

			For ($i = 0 ; $i -lt $ReturnProps.length ; $i++) {

				#PropertyName=PropertyValue
				$Output[$(($ReturnProps[$i]) -replace 'PassProps.', '')] = ($Results[$i]).trim()

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
			$OutputObject

		}

	}

}