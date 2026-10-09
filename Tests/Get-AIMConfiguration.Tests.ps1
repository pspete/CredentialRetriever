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

Describe 'Get-AIMConfiguration' {

	InModuleScope 'CredentialRetriever' {

		Context 'General' {

			BeforeEach {

				Remove-Variable -Name AIM -Scope Script -ErrorAction SilentlyContinue

			}

			It 'outputs configuration' {

				$Script:AIM = [pscustomobject]@{ ClientPath = 'SomePath' }
				(Get-AIMConfiguration).ClientPath | Should -Be 'SomePath'

			}

			It 'outputs configuration set by Set-AIMConfiguration' {

				Mock Test-Path -MockWith { $true }
				Mock Export-Clixml -MockWith { }
				Set-AIMConfiguration -ClientPath 'OtherPath'
				(Get-AIMConfiguration).ClientPath | Should -Be 'OtherPath'

			}

			It 'outputs nothing if configuration not set' {

				Get-AIMConfiguration | Should -BeNullOrEmpty

			}

			It 'does not throw if configuration not set' {

				{ Get-AIMConfiguration -ErrorAction Stop } | Should -Not -Throw

			}

		}

	}

}
