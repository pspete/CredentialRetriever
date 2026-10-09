# .ExternalHelp CredentialRetriever-help.xml
function Get-CCPCredential {

	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Suppress alert from ToSecureString ScriptMethod')]
	[CmdletBinding(DefaultParameterSetName = 'Default')]
	Param(
		# Unique ID of the application
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[string]
		$AppID,

		# Safe name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[string]
		$Safe,

		# Folder name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[string]
		$Folder,

		# Object name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[string]
		$Object,

		# Search username
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[string]
		$UserName,

		# Search address
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[string]
		$Address,

		# Search database
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[string]
		$Database,

		# Search PolicyID
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[string]
		$PolicyID,

		# Reason to record in audit log
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[string]
		$Reason,

		# Free query of account properties
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[string]
		$Query,

		# Format of free query
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[ValidateSet('Exact', 'Regexp')]
		[string]
		$QueryFormat,

		# Number of seconds to try
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[int]
		$ConnectionTimeout,

		# Return an error if a password change is in progress
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[switch]
		$FailRequestOnPasswordChange,

		# Credentials to send in request to CCP
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[ValidateNotNullOrEmpty()]
		[PSCredential]
		$Credential,

		# Use current system credentials for request to CCP
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[Switch]
		$UseDefaultCredentials,

		# Use certificate to authenticate to CCP
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[X509Certificate]
		$Certificate,

		# Use certificate to authenticate to CCP
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[string]
		$CertificateThumbPrint,

		# Unique ID of the CCP webservice in IIS
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[string]
		$WebServiceName = 'AIMWebService',

		# CCP URL
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[string]
		$URL,

		[parameter(
			Mandatory = $false,
			ValueFromPipeline = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipeline = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Query'
		)]
		[switch]
		$SkipCertificateCheck,

		# HTTP method for request to CCP
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $false,
			ParameterSetName = 'Default'
		)]
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $false,
			ParameterSetName = 'Query'
		)]
		[ValidateSet('GET', 'POST')]
		[string]
		$Method = 'GET',

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

		#Collection of parameters which are to be excluded from the request
		[array]$ExcludedParameters += [System.Management.Automation.PSCmdlet]::CommonParameters
		[array]$ExcludedParameters += [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
		[array]$ExcludedParameters += 'URL', 'WebServiceName', 'Credential', 'UseDefaultCredentials', 'CertificateThumbPrint', 'Certificate', 'SkipCertificateCheck', 'Method', 'AsCredential', 'AsSecureString'

		if ($AsCredential -and $AsSecureString) {
			throw 'AsCredential and AsSecureString cannot be used together.'
		}

		if ($PSEdition -ne 'Core') {

			#A SecurityProtocol of SystemDefault (0) lets Schannel negotiate the strongest protocol
			#both ends support, and is left untouched. Only a process pinned to explicit legacy
			#protocols needs TLS 1.2 adding, and it is combined with the protocols already permitted.
			$SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol

			if (([int]$SecurityProtocol -ne 0) -and
				([Net.SecurityProtocolType].GetEnumNames() -contains 'Tls12') -and
				(-not ($SecurityProtocol.HasFlag([Net.SecurityProtocolType]::Tls12)))) {

				Write-Verbose 'Adding TLS12 to Security Protocol'
				[Net.ServicePointManager]::SecurityProtocol = $SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

			}

		}

	}

	Process {

		#Collect bound request parameters, converting switches to boolean values
		$RequestParams = [ordered]@{ }
		$PSBoundParameters.keys | Where-Object { $ExcludedParameters -notcontains $_ } | ForEach-Object {

			$RequestParams[$_] = if ($PSBoundParameters[$_] -is [switch]) { $PSBoundParameters[$_].IsPresent } else { $PSBoundParameters[$_] }

		}

		$Request = @{
			'URI'             = "$($URL.TrimEnd('/'))/$WebServiceName/api/Accounts"
			'Method'          = $Method
			'ContentType'     = 'application/json'
			'ErrorAction'     = 'Stop'
			'UseBasicParsing' = $true
		}

		Switch ($Method) {

			'GET' {

				#Request parameters sent in URL query string
				$QueryString = ($RequestParams.Keys | ForEach-Object {
						"$_=$([System.Uri]::EscapeDataString($RequestParams[$_]))"
					}) -join '&'

				$Request['URI'] += "?$QueryString"

			}

			'POST' {

				#Request parameters sent in JSON body
				$Request['Body'] = $RequestParams | ConvertTo-Json

			}

		}

		# Add authentication parameters to request
		Switch ($($PSBoundParameters.keys)) {
			{ $PSItem -contains 'Credential' } { $Request['Credential'] = $Credential }
			{ $PSItem -contains 'UseDefaultCredentials' } { $Request['UseDefaultCredentials'] = $true }
			{ $PSItem -contains 'CertificateThumbPrint' } { $Request['CertificateThumbPrint'] = $CertificateThumbPrint }
			{ $PSItem -contains 'Certificate' } { $Request['Certificate'] = $Certificate }
		}

		$RestoreCertificatePolicy = $false

		#in PSCore use SkipCertificateCheck parameter
		if ($PSEdition -eq 'Core') {

			$Request.Add('SkipCertificateCheck', $SkipCertificateCheck.IsPresent)

		} elseif ($SkipCertificateCheck) {

			#Skip SSL Validation, saving previous certificate policy
			$CertificatePolicy = Skip-CertificateCheck
			$RestoreCertificatePolicy = $true

		}

		$result = $null

		Try {

			#send request
			$result = Invoke-RestMethod @Request

		} Catch {

			$ErrorRecord = $PSItem
			$ErrorMessage = $ErrorRecord.Exception.Message
			$ErrorID = $ErrorRecord.FullyQualifiedErrorId

			$err = $null

			#Only parse responses that look like JSON
			if ("$ErrorRecord".TrimStart().StartsWith('{')) {

				try {

					$err = $ErrorRecord | ConvertFrom-Json -ErrorAction Stop

				} catch {

					#Response is not valid JSON, keep original exception details
					$err = $null

				}

			}

			#CCP errors use ErrorMsg/ErrorCode, IIS/ASP.NET errors use Message
			if ($err.ErrorMsg) {
				$ErrorMessage = $err.ErrorMsg
				$ErrorID = $err.ErrorCode
			} elseif ($err.Message) {
				$ErrorMessage = $err.Message
			}

			#report the error and continue with any further pipeline input
			$PSCmdlet.WriteError(

				[System.Management.Automation.ErrorRecord]::new(

					$ErrorMessage,
					$ErrorID,
					[System.Management.Automation.ErrorCategory]::NotSpecified,
					$ErrorRecord

				)

			)

		} Finally {

			#Restore previous certificate policy
			if ($RestoreCertificatePolicy) {

				[System.Net.ServicePointManager]::CertificatePolicy = $CertificatePolicy

			}

		}

		if ($null -ne $result) {

			#Add ScriptMethod to output object to convert password to Secure String
			$result | Add-Member -MemberType ScriptMethod -Name ToSecureString -Value {

				$this.Content | ConvertTo-SecureString -AsPlainText -Force

			} -Force

			#Add ScriptMethod to output object to convert username & password to Credential Object
			$result | Add-Member -MemberType ScriptMethod -Name ToCredential -Value {

				New-Object System.Management.Automation.PSCredential($this.UserName, $this.ToSecureString())

			} -Force

			#Return the result from CCP
			if ($AsCredential) {
				$result.ToCredential()
			} elseif ($AsSecureString) {
				$result.ToSecureString()
			} else {
				$result
			}

		}

	}

	End { }

}
