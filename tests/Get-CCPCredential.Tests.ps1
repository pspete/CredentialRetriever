#$here = Split-Path -Parent $MyInvocation.MyCommand.Path
#$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
#. "$here\$sut"

#Get Current Directory
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

#Get Function Name
$FunctionName = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -Replace '.Tests.ps1'

#Assume ModuleName from Repository Root folder
$ModuleName = Split-Path (Split-Path $Here -Parent) -Leaf

#Resolve Path to Module Directory
$ModulePath = Resolve-Path "$Here\..\$ModuleName"

#Define Path to Module Manifest
$ManifestPath = Join-Path "$ModulePath" "$ModuleName.psd1"

if ( -not (Get-Module -Name $ModuleName -All)) {

	Import-Module -Name "$ManifestPath" -ArgumentList $true -Force -ErrorAction Stop

}
InModuleScope $ModuleName {
	Describe 'Get-CCPCredential' {

		BeforeAll {
			$RSA = [System.Security.Cryptography.RSA]::Create(2048)
			$CertificateRequest = New-Object -TypeName System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList @(
				'CN=CredentialRetriever', $RSA, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			)
			$TestCertificate = $CertificateRequest.CreateSelfSigned([DateTimeOffset]::Now, [DateTimeOffset]::Now.AddDays(1))
		}

		BeforeEach {
			Mock Invoke-RestMethod {}
			$InputObj = [pscustomobject]@{
				'AppID' = 'SomeApplication'
				'URL'   = 'https://SomeURL'
			}
		}

		It 'sends request' {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -Scope It
		}

		It 'sends request with expected method' {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Method -eq 'GET'

			} -Times 1 -Exactly -Scope It
		}

		It 'sends request with expected content-type' {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$ContentType -eq 'application/json'

			} -Times 1 -Exactly -Scope It
		}

		It 'sends request to expected URL' {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$URI -eq 'https://SomeURL/AIMWebService/api/Accounts?AppID=SomeApplication'

			} -Times 1 -Exactly -Scope It
		}

		It 'sends request with expected Query' {
			Get-CCPCredential -AppID PS -Query 'Safe=PS;Object=PSP-AccountName' -QueryFormat Exact -URL 'https://SomeURL'
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$URI -eq 'https://SomeURL/AIMWebService/api/Accounts?AppID=PS&Query=Safe%3DPS%3BObject%3DPSP-AccountName&QueryFormat=Exact'

			} -Times 1 -Exactly -Scope It
		}

		It 'sends ConnectionTimeout with Query' {
			Get-CCPCredential -AppID PS -Query 'Safe=PS' -ConnectionTimeout 45 -URL 'https://SomeURL'
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$URI -eq 'https://SomeURL/AIMWebService/api/Accounts?AppID=PS&Query=Safe%3DPS&ConnectionTimeout=45'

			} -Times 1 -Exactly -Scope It
		}

		It 'throws if Query is specified with other search criteria' {
			{ Get-CCPCredential -AppID PS -Query 'Safe=PS' -Safe PS -URL 'https://SomeURL' } | Should Throw
		}

		It 'throws if QueryFormat is specified without Query' {
			{ Get-CCPCredential -AppID PS -Safe PS -QueryFormat Exact -URL 'https://SomeURL' } | Should Throw
		}

		It 'sends FailRequestOnPasswordChange in URL' {
			Get-CCPCredential -AppID PS -Safe PS -FailRequestOnPasswordChange -URL 'https://SomeURL'
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$URI -eq 'https://SomeURL/AIMWebService/api/Accounts?AppID=PS&Safe=PS&FailRequestOnPasswordChange=True'

			} -Times 1 -Exactly -Scope It
		}

		It 'sends request to specified web service URL' {
			$InputObj | Get-CCPCredential -WebServiceName DEV
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$URI -eq 'https://SomeURL/DEV/api/Accounts?AppID=SomeApplication'

			} -Times 1 -Exactly -Scope It
		}

		It 'sends request to expected URL when URL has trailing slash' {
			Get-CCPCredential -AppID SomeApplication -URL 'https://SomeURL/'
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$URI -eq 'https://SomeURL/AIMWebService/api/Accounts?AppID=SomeApplication'

			} -Times 1 -Exactly -Scope It
		}

		Context 'Security Protocol' {

			BeforeEach {
				$SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
			}

			AfterEach {
				[System.Net.ServicePointManager]::SecurityProtocol = $SecurityProtocol
			}

			It 'adds TLS12 to explicit security protocols' -Skip:($PSVersionTable.PSEdition -eq 'Core') {
				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11
				$InputObj | Get-CCPCredential
				[System.Net.ServicePointManager]::SecurityProtocol.HasFlag([Net.SecurityProtocolType]::Tls11) | Should Be $true
				[System.Net.ServicePointManager]::SecurityProtocol.HasFlag([Net.SecurityProtocolType]::Tls12) | Should Be $true
			}

			It 'does not change SystemDefault security protocol' -Skip:($PSVersionTable.PSEdition -eq 'Core') {
				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]0
				$InputObj | Get-CCPCredential
				[int][System.Net.ServicePointManager]::SecurityProtocol | Should Be 0
			}

			It 'does not specify SslProtocol' {
				$InputObj | Get-CCPCredential
				Assert-MockCalled Invoke-RestMethod -ParameterFilter {

					$null -eq $SslProtocol

				} -Times 1 -Exactly -Scope It
			}

		}

		It 'invokes rest method with credentials' {

			$SomeCredential = New-Object System.Management.Automation.PSCredential('SomeUser', $('SomePassword' | ConvertTo-SecureString -AsPlainText -Force))
			$InputObj | Get-CCPCredential -Credential $SomeCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$credential -eq $SomeCredential

			} -Times 1 -Exactly -Scope It
		}

		It 'invokes rest method with query and credentials' {

			$SomeCredential = New-Object System.Management.Automation.PSCredential('SomeUser', $('SomePassword' | ConvertTo-SecureString -AsPlainText -Force))
			$InputObj | Get-CCPCredential -Query 'SomeQuery' -Credential $SomeCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$credential -eq $SomeCredential

			} -Times 1 -Exactly -Scope It
		}

		It 'invokes rest method with default credentials switch' {

			$InputObj | Get-CCPCredential -UseDefaultCredentials
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$UseDefaultCredentials -eq $true

			} -Times 1 -Exactly -Scope It
		}

		It 'invokes rest method with query and default credentials switch' {

			$InputObj | Get-CCPCredential -Query 'SomeQuery' -UseDefaultCredentials
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$UseDefaultCredentials -eq $true

			} -Times 1 -Exactly -Scope It
		}

		It 'invokes rest method with certificateThumbprint' {

			$thumbprint = 'C1Y2BFE0R0ADR3KDR508C4KAS4C1YFB7EAR4ACRK'
			$InputObj | Get-CCPCredential -CertificateThumbPrint $thumbprint
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$certificateThumbprint -eq $thumbprint

			} -Times 1 -Exactly -Scope It
		}

		It 'invokes rest method with query and certificateThumbprint' {

			$thumbprint = 'C1Y2BFE0R0ADR3KDR508C4KAS4C1YFB7EAR4ACRK'
			$InputObj | Get-CCPCredential -Query 'SomeQuery' -CertificateThumbPrint $thumbprint
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$certificateThumbprint -eq $thumbprint

			} -Times 1 -Exactly -Scope It
		}

		It 'invokes rest method with certificate' {

			$certificate = $TestCertificate
			$InputObj | Get-CCPCredential -Certificate $certificate
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$certificate -eq $certificate

			} -Times 1 -Exactly -Scope It
		}

		It 'invokes rest method with query and certificate' {

			$certificate = $TestCertificate
			$InputObj | Get-CCPCredential -Query 'SomeQuery' -Certificate $certificate
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$certificate -eq $certificate

			} -Times 1 -Exactly -Scope It
		}

		It 'invokes rest method with SkipCertificateCheck' -Skip:($PSVersionTable.PSEdition -ne 'Core') {

			$InputObj | Get-CCPCredential -SkipCertificateCheck
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$SkipCertificateCheck -eq $true

			} -Times 1 -Exactly -Scope It
		}

		Context 'Certificate Policy' {

			It 'skips certificate check during request on Windows PowerShell' -Skip:($PSVersionTable.PSEdition -eq 'Core') {

				Mock Invoke-RestMethod { $Script:RequestCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy }
				$InputObj | Get-CCPCredential -SkipCertificateCheck
				$Script:RequestCertificatePolicy.GetType().FullName | Should Be 'CredentialRetriever.TrustAllCertificatePolicy'
			}

			It 'restores certificate policy after request on Windows PowerShell' -Skip:($PSVersionTable.PSEdition -eq 'Core') {

				$CertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
				$InputObj | Get-CCPCredential -SkipCertificateCheck
				[System.Net.ServicePointManager]::CertificatePolicy | Should Be $CertificatePolicy
			}

			It 'restores certificate policy after failed request on Windows PowerShell' -Skip:($PSVersionTable.PSEdition -eq 'Core') {

				Mock Invoke-RestMethod { throw 'Some Error' }
				$CertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
				$InputObj | Get-CCPCredential -SkipCertificateCheck -ErrorAction SilentlyContinue
				[System.Net.ServicePointManager]::CertificatePolicy | Should Be $CertificatePolicy
			}

		}

		It 'invokes Skip-CertificateCheck on Windows PowerShell' -Skip:($PSVersionTable.PSEdition -eq 'Core') {

			Mock Skip-CertificateCheck { [System.Net.ServicePointManager]::CertificatePolicy }
			$InputObj | Get-CCPCredential -SkipCertificateCheck
			Assert-MockCalled Skip-CertificateCheck -Times 1 -Exactly -Scope It
		}

		It 'does not change certificate policy without SkipCertificateCheck on Windows PowerShell' -Skip:($PSVersionTable.PSEdition -eq 'Core') {

			Mock Skip-CertificateCheck { }
			$InputObj | Get-CCPCredential
			Assert-MockCalled Skip-CertificateCheck -Times 0 -Exactly -Scope It
		}

		It 'does not output previous result when a later request fails' {
			$Script:RequestCount = 0
			Mock Invoke-RestMethod {
				$Script:RequestCount++
				if ($Script:RequestCount -gt 1) { throw 'Some Error' }
				[pscustomobject]@{ 'Content' = 'SomePassword' }
			}
			$Script:Output = @()
			{
				@(
					[pscustomobject]@{ AppID = 'PS'; Safe = 'Safe1'; URL = 'https://P_URI' },
					[pscustomobject]@{ AppID = 'PS'; Safe = 'Safe2'; URL = 'https://P_URI' }
				) | Get-CCPCredential -ErrorAction Stop | ForEach-Object { $Script:Output += $_ }
			} | Should throw 'Some Error'
			$Script:Output.Count | Should Be 1
		}

		It 'continues processing piped input after a failed request' {
			$Script:RequestCount = 0
			Mock Invoke-RestMethod {
				$Script:RequestCount++
				if ($Script:RequestCount -eq 2) { throw 'Some Error' }
				[pscustomobject]@{ 'Content' = "SomePassword$Script:RequestCount" }
			}
			$result = @(
				[pscustomobject]@{ AppID = 'PS'; Safe = 'Safe1'; URL = 'https://P_URI' },
				[pscustomobject]@{ AppID = 'PS'; Safe = 'Safe2'; URL = 'https://P_URI' },
				[pscustomobject]@{ AppID = 'PS'; Safe = 'Safe3'; URL = 'https://P_URI' }
			) | Get-CCPCredential -ErrorAction SilentlyContinue -ErrorVariable RequestErrors
			$result.Content | Should Be @('SomePassword1', 'SomePassword3')
			$RequestErrors[-1].Exception.Message | Should Be 'Some Error'
		}

		It 'catches exceptions from Invoke-RestMethod' {
			Mock Invoke-RestMethod { throw 'Some Error' }

			{ $InputObj | Get-CCPCredential -ErrorAction Stop } | Should throw 'Some Error'
		}

		It 'catches exceptions returned from the web service' {
			$return = @{'ErrorMsg' = 'Some Message'; 'ErrorCode' = 'SomeCode' }
			Mock Invoke-RestMethod { throw $($return | ConvertTo-Json) }

			{ $InputObj | Get-CCPCredential -ErrorAction Stop } | Should throw 'Some Message'
		}

		It 'catches exceptions with only a Message property' {
			$return = @{'Message' = "The requested resource does not support http method 'POST'." }
			Mock Invoke-RestMethod { throw $($return | ConvertTo-Json) }

			{ $InputObj | Get-CCPCredential -ErrorAction Stop } | Should throw "does not support http method 'POST'"
		}

		It 'outputs object with ToSecureString method' {
			Mock Invoke-RestMethod { [pscustomobject]@{'content' = 'SomePassword'; 'username' = 'SomeUser' } }
			$result = $InputObj | Get-CCPCredential
			$result | Get-Member -MemberType ScriptMethod | Select-Object -ExpandProperty Name | Should Contain 'ToSecureString'
		}

		It 'converts output to expected SecureString' {
			Mock Invoke-RestMethod { [pscustomobject]@{'content' = 'SomePassword'; 'username' = 'SomeUser' } }
			$result = $InputObj | Get-CCPCredential
			$credential = New-Object System.Management.Automation.PSCredential('SomeUser', $result.ToSecureString())
			$credential.GetNetworkCredential().Password | Should Be 'SomePassword'

		}

		It 'outputs object with ToCredential method' {
			Mock Invoke-RestMethod { [pscustomobject]@{'content' = 'SomePassword'; 'username' = 'SomeUser' } }
			$result = $InputObj | Get-CCPCredential
			$result | Get-Member -MemberType ScriptMethod | Select-Object -ExpandProperty Name | Should Contain 'ToCredential'
		}

		It 'outputs expected password to pscredential object' {
			Mock Invoke-RestMethod { [pscustomobject]@{'content' = 'SomePassword'; 'username' = 'SomeUser' } }
			$result = $InputObj | Get-CCPCredential
			($result.ToCredential()).GetNetworkCredential().Password | Should Be 'SomePassword'
		}

		It 'does not send a body for GET requests' {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$null -eq $Body
			} -Times 1 -Exactly -Scope It
		}

		It 'throws on invalid Method' {
			{ $InputObj | Get-CCPCredential -Method PUT } | Should Throw
		}

		It 'sends POST request without query string' {
			$InputObj | Get-CCPCredential -Method POST
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Method -eq 'POST' -and $URI -eq 'https://SomeURL/AIMWebService/api/Accounts'
			} -Times 1 -Exactly -Scope It
		}

		It 'sends expected JSON body for POST request' {
			Get-CCPCredential -AppID PS -Safe PS -Object 'PSP-AccountName' -ConnectionTimeout 45 -FailRequestOnPasswordChange -Method POST -URL 'https://SomeURL'
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Sent = $Body | ConvertFrom-Json
				($Sent.PSObject.Properties.Name -join ',') -eq 'AppID,Safe,Object,ConnectionTimeout,FailRequestOnPasswordChange' -and
				$Sent.AppID -eq 'PS' -and
				$Sent.Safe -eq 'PS' -and
				$Sent.Object -eq 'PSP-AccountName' -and
				$Sent.ConnectionTimeout -eq 45 -and
				$Sent.FailRequestOnPasswordChange -eq $true
			} -Times 1 -Exactly -Scope It
		}

		It 'sends expected JSON body for POST Query request' {
			Get-CCPCredential -AppID PS -Query 'Safe=PS;Object=PSP-.*' -QueryFormat Regexp -Method POST -URL 'https://SomeURL'
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Sent = $Body | ConvertFrom-Json
				($Sent.PSObject.Properties.Name -join ',') -eq 'AppID,Query,QueryFormat' -and
				$Sent.Query -eq 'Safe=PS;Object=PSP-.*' -and
				$Sent.QueryFormat -eq 'Regexp'
			} -Times 1 -Exactly -Scope It
		}

	}

}
