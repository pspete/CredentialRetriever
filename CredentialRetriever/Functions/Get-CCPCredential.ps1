function Get-CCPCredential {
	<#
	.SYNOPSIS
	Use the GetPassword REST Web Service to retrieve passwords from the Central Credential Provider.

	.DESCRIPTION
	When the Central Credential Provider for Windows is published via an IIS and the Central
	Credential Provider Web Service, this function can be used to retrieve credentials.
	Passwords stored in the CyberArk Vault are retrieved to the Central Credential Provider, where
	they can be accessed by authorized remote applications/scripts using a web service call.

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
	Defines the format that will be used in the set PolicyID method.

	.PARAMETER Reason
	The reason for retrieving the password. This reason will be audited in the Credential Provider audit log

	.PARAMETER ConnectionTimeout
	The number of seconds that the Central Credential Provider will try to retrieve the password.
	The timeout is calculated when the request is sent from the web service to the Vault and returned back
	to the web service.

	.PARAMETER Credential
	Specify the credentials object if OS User authentication is required for CCP.

	.PARAMETER UseDefaultCredentials
	Use the default credentials for CCP OS User authentication.

	.PARAMETER Certificate
	A Certificate from a local store which is authorised to access the AIMWebService.

	.PARAMETER CertificateThumbPrint
	A Certificate Thumbprint authorised to access the AIMWebService.

	.PARAMETER WebServiceName
	The name the CCP WebService is configured under in IIS.
	Defaults to AIMWebService

	.PARAMETER URL
	The URL for the CCP Host

	.PARAMETER SkipCertificateCheck
	Skips certificate validation checks.

	Using this parameter is not secure and is not recommended.

	This switch is only intended to be used against known hosts using a self-signed certificate for testing purposes.

	Use at your own risk.

	.EXAMPLE
	Get-CCPCredential -AppID PSScript -Safe PSAccounts -Object PSPlatform-AccountName -URL https://cyberark.yourcompany.com

	Uses the PSScript App ID to retrieve password for the PSPlatform-AccountName object in the PSAccounts safe from the
	https://cyberark.yourcompany.com/AIMWebService CCP Web Service.

	.EXAMPLE
	Get-CCPCredential -AppID PowerShell -Safe PSAccounts -UserName svc-psProvision -WebServiceName DevAIM -URL https://cyberark-dev.yourcompany.com

	Uses the PowerShell App ID to search for and retrieve the password for the svc-psProvision account in the PSAccounts safe
	from the https://cyberark-dev.yourcompany.com/DevAIM CCP Web Service.

	.EXAMPLE
	$result = Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com

	$result.ToSecureSting()

	Returns the password retrieved from CCP as a Secure String

	.EXAMPLE
	$result = Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com

	$result.ToCredential()

	Returns the username & password retrieved from CCP as a PSCredential object

	.EXAMPLE
	Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -UseDefaultCredentials

	Calls Invoke-RestMethod with the UseDefaultCredentials switch to use OS User authentication

	.EXAMPLE
	Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -Credential $creds

	Calls Invoke-RestMethod with the supplied Credentials for OS User authentication

	.EXAMPLE
	Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -CertificateThumbPrint $Cert_ThumbPrint

	Calls Invoke-RestMethod with the supplied Certificate for Certificate authentication

	.EXAMPLE
	Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -Certificate $Cert

	Calls Invoke-RestMethod with the supplied Certificate for Certificate authentication
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Suppress alert from ToSecureString ScriptMethod')]
	[CmdletBinding(DefaultParameterSetName = 'Default')]
	Param(
		# Unique ID of the application
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$AppID,

		# Safe name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$Safe,

		# Folder name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$Folder,

		# Object name
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$Object,

		# Search username
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$UserName,

		# Search address
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$Address,

		# Search database
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$Database,

		# SetPolicyID format
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$PolicyID,

		# Reason to record in audit log
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$Reason,

		# Number of seconds to try
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[int]
		$ConnectionTimeout,

		# Credentials to send in request to CCP
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[ValidateNotNullOrEmpty()]
		[PSCredential]
		$Credential,

		# Use current system credentials for request to CCP
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[Switch]
		$UseDefaultCredentials,

		# Use certificate to authenticate to CCP
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[X509Certificate]
		$Certificate,

		# Use certificate to authenticate to CCP
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[string]
		$CertificateThumbPrint,

		# Unique ID of the CCP webservice in IIS
		[Parameter(
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[string]
		$WebServiceName = 'AIMWebService',

		# CCP URL
		[Parameter(
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = 'Default'
		)]
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $true,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
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
			ParameterSetName = 'Credential'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipeline = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'DefaultCredentials'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipeline = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'CertificateThumbPrint'
		)]
		[parameter(
			Mandatory = $false,
			ValueFromPipeline = $false,
			ValueFromPipelinebyPropertyName = $true,
			ParameterSetName = 'Certificate'
		)]
		[switch]$SkipCertificateCheck
	)

	Begin {

		#Collection of parameters which are to be excluded from the request URL
		[array]$CommonParameters += [System.Management.Automation.PSCmdlet]::CommonParameters
		[array]$CommonParameters += [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
		[array]$CommonParameters += 'URL', 'WebServiceName', 'Credential', 'UseDefaultCredentials', 'CertificateThumbPrint', 'Certificate', 'SkipCertificateCheck'

		#If Tls12 Security Protocol is available
		if (([Net.SecurityProtocolType].GetEnumNames() -contains 'Tls12') -and

			#And Tls12 is not already in use
			(-not ([System.Net.ServicePointManager]::SecurityProtocol -match 'Tls12'))) {

			#Use Tls12
			Write-Verbose 'Setting Security Protocol to TLS12'
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

		}

	}

	Process {

		[array]$QueryArgs = @()

		#Enumerate bound parameters to build query string for URL
		$PSBoundParameters.keys | Where-Object { $CommonParameters -notcontains $_ } | ForEach-Object {

			$QueryArgs += "$_=$([System.Uri]::EscapeDataString($PSBoundParameters[$_]))"

		}

		#Format URL query string
		$Query = $QueryArgs -join '&'

		#Create hashtable of request parameters
		$Request = @{
			'URI'             = "$URL/$WebServiceName/api/Accounts?$Query"
			'Method'          = 'GET'
			'ContentType'     = 'application/json'
			'ErrorAction'     = 'Stop'
			'ErrorVariable'   = 'RequestError'
			'UseBasicParsing' = $true
		}

		#Add authentication parameters to request
		Switch ($($PSCmdlet.ParameterSetName)) {
			'Credential' { $Request['Credential'] = $Credential }
			'DefaultCredentials' { $Request['UseDefaultCredentials'] = $true }
			'CertificateThumbPrint' { $Request['CertificateThumbPrint'] = $CertificateThumbPrint }
			'Certificate' { $Request['Certificate'] = $Certificate }
		}

		#in PSCore Use SslProtocol TLS1.2 & SkipCertificateCheck parameter
		if ($IsCoreCLR) {

			$Request.Add('SslProtocol', 'TLS12')
			$Request.Add('SkipCertificateCheck', $SkipCertificateCheck.IsPresent)

		} elseif ($SkipCertificateCheck) {

			#Skip SSL Validation
			Skip-CertificateCheck

		}

		Try {

			#send request
			$result = Invoke-RestMethod @Request

		} Catch {

			try {
				$err = $_ | ConvertFrom-Json -ErrorAction Stop
				Write-Error -Message $err.ErrorMsg -ErrorId $err.ErrorCode
			} catch { Write-Error -Message $RequestError.ErrorRecord.Exception -ErrorId $RequestError.ErrorRecord.FullyQualifiedErrorId -ErrorAction Stop }

		} Finally {

			if ($result) {

				#Add ScriptMethod to output object to convert password to Secure String
				$result | Add-Member -MemberType ScriptMethod -Name ToSecureString -Value {

					$this.Content | ConvertTo-SecureString -AsPlainText -Force

				}

				#Add ScriptMethod to output object to convert username & password to Credential Object
				$result | Add-Member -MemberType ScriptMethod -Name ToCredential -Value {

					New-Object System.Management.Automation.PSCredential($this.UserName, $this.ToSecureString())

				}

				#Return the result from CCP
				$result

			}

		}

	}

	End { }

}