#InModuleScope is resolved during Pester's discovery phase, so the module must be imported here
#rather than from BeforeAll, which does not run until the later run phase.

#Get Current Directory
$Here = Split-Path -Parent $PSCommandPath

#Module Name
$ModuleName = 'CredentialRetriever'

#Resolve Path to Module Directory
$ModulePath = Resolve-Path "$Here\..\$ModuleName"

#Define Path to Module Manifest
$ManifestPath = Join-Path "$ModulePath" "$ModuleName.psd1"

if ( -not (Get-Module -Name $ModuleName -All)) {

	Import-Module -Name "$ManifestPath" -ArgumentList $true -Force -ErrorAction Stop

}

Describe 'Skip-CertificateCheck' {

	InModuleScope 'CredentialRetriever' {

		Context 'General' {

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
				Should -Invoke Add-Type -Times 0 -Exactly

			}

		}

	}

}