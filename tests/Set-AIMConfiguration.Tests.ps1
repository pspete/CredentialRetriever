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

BeforeAll {

	#$Script:RequestBody = $null

}

AfterAll {

	#$Script:RequestBody = $null

}

Describe $FunctionName {

	InModuleScope $ModuleName {

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
				$Script:AIM | Should Not BeNullOrEmpty
			}

			It 'sets client path property value' {
				$InputObj | Set-AIMConfiguration
				$($Script:AIM.ClientPath) | Should Be 'SomePath'
			}

			It 'exports configuration to home folder' {
				$InputObj | Set-AIMConfiguration
				Assert-MockCalled Export-Clixml -ParameterFilter {
					$Path -eq (Join-Path -Path $HOME -ChildPath 'AIMConfiguration.xml')
				} -Times 1 -Exactly -Scope It
			}

			It 'exports configuration with ClientPath property' {
				$InputObj | Set-AIMConfiguration
				Assert-MockCalled Export-Clixml -ParameterFilter {
					$InputObject.ClientPath -eq 'SomePath'
				} -Times 1 -Exactly -Scope It
			}

			It 'specifies ClientPath as mandatory' {
				(Get-Command Set-AIMConfiguration).Parameters['ClientPath'].Attributes.Mandatory | Should Be $true
			}

			It 'does not set configuration with WhatIf' {
				$Script:AIM = [pscustomobject]@{ ClientPath = 'OtherPath' }
				$InputObj | Set-AIMConfiguration -WhatIf
				$Script:AIM.ClientPath | Should Be 'OtherPath'
				Assert-MockCalled Export-Clixml -Times 0 -Exactly -Scope It
			}

		}

	}

}