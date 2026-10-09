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

Describe 'Set-AIMConfiguration' {

	InModuleScope 'CredentialRetriever' {

		Context 'General' {

			BeforeEach {

				Mock Test-Path -MockWith {
					$true
				}

				Mock Export-Clixml -MockWith { }

				$InputObj = [pscustomobject]@{
					ClientPath = 'SomePath'
				}

			}

			It 'sets value of script scope variable' {

				$InputObj | Set-AIMConfiguration
				$Script:AIM | Should -Not -BeNullOrEmpty
			}

			It 'sets client path property value' {
				$InputObj | Set-AIMConfiguration
				$($Script:AIM.ClientPath) | Should -Be 'SomePath'
			}

			It 'exports configuration to home folder' {
				$InputObj | Set-AIMConfiguration
				Should -Invoke Export-Clixml -ParameterFilter {
					$Path -eq (Join-Path -Path $HOME -ChildPath 'AIMConfiguration.xml')
				} -Times 1 -Exactly
			}

			It 'exports configuration with ClientPath property' {
				$InputObj | Set-AIMConfiguration
				Should -Invoke Export-Clixml -ParameterFilter {
					$InputObject.ClientPath -eq 'SomePath'
				} -Times 1 -Exactly
			}

			It 'specifies ClientPath as mandatory' {
				(Get-Command Set-AIMConfiguration).Parameters['ClientPath'].Attributes.Mandatory | Should -Be $true
			}

			It 'does not set configuration with WhatIf' {
				$Script:AIM = [pscustomobject]@{ ClientPath = 'OtherPath' }
				$InputObj | Set-AIMConfiguration -WhatIf
				$Script:AIM.ClientPath | Should -Be 'OtherPath'
				Should -Invoke Export-Clixml -Times 0 -Exactly
			}

		}

	}

}