Describe $($PSCommandPath -Replace '.Tests.ps1') {

	BeforeAll {
		#Get Current Directory
		$Here = Split-Path -Parent $PSCommandPath

		#Assume ModuleName from Repository Root folder
		$ModuleName = Split-Path (Split-Path $Here -Parent) -Leaf

		#Resolve Path to Module Directory
		$ModulePath = Resolve-Path "$Here\..\$ModuleName"

		#Define Path to Module Manifest
		$ManifestPath = Join-Path "$ModulePath" "$ModuleName.psd1"

		if ( -not (Get-Module -Name $ModuleName -All)) {

			Import-Module -Name "$ManifestPath" -ArgumentList $true -Force -ErrorAction Stop

		}

		$Script:RequestBody = $null
		$Script:BaseURI = 'https://SomeURL/SomeApp'
		$Script:ExternalVersion = '0.0'
		$Script:WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

	}


	AfterAll {

		$Script:RequestBody = $null

	}

	InModuleScope $(Split-Path (Split-Path (Split-Path -Parent $PSCommandPath) -Parent) -Leaf ) {

		Context 'General' {

			BeforeEach {

			}

			It 'does not throw' {

				{ $Script:CertificatePolicy = Skip-CertificateCheck } | Should -Not -Throw
				if ($PSVersionTable.PSEdition -ne 'Core') { [System.Net.ServicePointManager]::CertificatePolicy = $Script:CertificatePolicy }

			}

			It 'outputs previous certificate policy' -Skip:($PSVersionTable.PSEdition -eq 'Core') {

				$CertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
				$Result = Skip-CertificateCheck
				[System.Net.ServicePointManager]::CertificatePolicy = $CertificatePolicy
				$Result | Should -Be $CertificatePolicy

			}

			It 'sets certificate policy which trusts all certificates' -Skip:($PSVersionTable.PSEdition -eq 'Core') {

				$CertificatePolicy = Skip-CertificateCheck
				$Result = [System.Net.ServicePointManager]::CertificatePolicy
				[System.Net.ServicePointManager]::CertificatePolicy = $CertificatePolicy
				$Result.GetType().FullName | Should -Be 'CredentialRetriever.TrustAllCertificatePolicy'
				$Result.CheckValidationResult($null, $null, $null, 1) | Should -Be $true

			}

			It 'compiles certificate policy once' -Skip:($PSVersionTable.PSEdition -eq 'Core') {

				Mock Add-Type { }
				$CertificatePolicy = Skip-CertificateCheck
				$null = Skip-CertificateCheck
				[System.Net.ServicePointManager]::CertificatePolicy = $CertificatePolicy
				Assert-MockCalled Add-Type -Times 0 -Exactly -Scope It

			}

		}

	}

}