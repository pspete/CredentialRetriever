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

Describe 'Invoke-AIMClient' {

	InModuleScope 'CredentialRetriever' {

		Context 'Mandatory Parameters' {

			$Parameters = @{Parameter = 'CommandParameters' }

			It 'specifies parameter <Parameter> as mandatory' -TestCases $Parameters {
				(Get-Command Invoke-AIMClient).Parameters["$Parameter"].Attributes.Mandatory | Should -Be $true

			}



		}

		Context 'Default' {

			BeforeEach {

				Remove-Variable -Name AIM -Scope Script -ErrorAction SilentlyContinue

				Mock Start-AIMClientProcess -MockWith {
					Write-Output @{}
				}

				$InputObj = [pscustomobject]@{
					CommandParameters = 'Some Command Parameters'
				}


			}

			It 'throws if ClientPath is not resolvable' {

				{ $InputObj | Invoke-AIMClient -ClientPath .\RandomFile.exe } | Should -Throw "*CLIPasswordSDK not found at '.\RandomFile.exe'*"

			}

			It "throws if `$AIM variable not set in script scope" {

				{ $InputObj | Invoke-AIMClient } | Should -Throw '*CLIPasswordSDK path not set*'

			}

			It "throws if `$AIM variable does not have ClientPath property" {

				$object = [PSCustomObject]@{
					prop1 = 'Value1'
					prop2 = 'Value2'
				}
				New-Variable -Name AIM -Value $object -Scope Script

				{ $InputObj | Invoke-AIMClient } | Should -Throw '*CLIPasswordSDK path not set*'

			}

			It "throws if `$AIM.ClientPath is not resolvable" {

				$object = [PSCustomObject]@{
					ClientPath = '.\RandomFile.Exe'
					prop2      = 'Value2'
				}
				New-Variable -Name AIM -Value $object -Scope Script

				{ $InputObj | Invoke-AIMClient } | Should -Throw "*CLIPasswordSDK not found at '.\RandomFile.Exe'*"

			}

			It 'does not start process if ClientPath is not resolvable' {

				{ $InputObj | Invoke-AIMClient -ClientPath .\RandomFile.exe } | Should -Throw
				Should -Invoke Start-AIMClientProcess -Times 0 -Exactly

			}

			It "no throw if `$AIM.ClientPath is resolvable" {

				$object = [PSCustomObject]@{
					ClientPath = $PSCommandPath
					prop2      = 'Value2'
				}
				New-Variable -Name AIM -Value $object -Scope Script

				{ $InputObj | Invoke-AIMClient } | Should -Not -Throw

			}


		}

		Context 'Set-AIMConfiguration' {

			BeforeAll {

				Mock Export-Clixml -MockWith { }

				Mock Test-Path -MockWith {
					$true
				}

				Mock Start-AIMClientProcess -MockWith {
					Write-Output @{}
				}

				$InputObj = [pscustomobject]@{
					CommandParameters = 'Some Command Parameters'
				}

				Set-AIMConfiguration -ClientPath 'C:\SomePath\CLIPasswordSDK.exe'

			}

			It "does not throw after Set-AIMConfiguration has set the `$AIM variable" {

				{ $InputObj | Invoke-AIMClient } | Should -Not -Throw

			}

			It 'does not require Set-AIMConfiguration to be run more than once' {

				{ $InputObj | Invoke-AIMClient } | Should -Not -Throw
				{ $InputObj | Invoke-AIMClient } | Should -Not -Throw

			}

		}

		Context 'Reporting Errors' {

			BeforeEach {

				Mock Test-Path -MockWith {
					$true
				}

				$InputObj = [pscustomobject]@{
					CommandParameters = 'Some Command Parameters'
				}


			}

			It "reports 'ErrorCode Message' format errors on stderr" {

				Mock Start-AIMClientProcess -MockWith {
					[pscustomobject]@{
						'ExitCode' = -1
						'StdOut'   = $null
						'StdErr'   = 'APPAP008E Problem occurred while trying to use user in the Vault'
					}

				}

				{ $InputObj | Invoke-AIMClient -ErrorAction Stop } | Should -Throw '*Problem occurred while trying to use user in the Vault*'

			}

			It "reports '(ErrorCode) Message' format errors on stderr" {

				Mock Start-AIMClientProcess -MockWith {
					[pscustomobject]@{
						'ExitCode' = -1
						'StdOut'   = $null
						'StdErr'   = 'ERROR (999) Something Awful.'
					}

				}

				{ $InputObj | Invoke-AIMClient -ErrorAction Stop } | Should -Throw '*Something Awful.*'

			}

			It 'reports non-zero exit code with unrecognised stderr' {

				Mock Start-AIMClientProcess -MockWith {
					[pscustomobject]@{
						'ExitCode' = 1
						'StdOut'   = ''
						'StdErr'   = 'Something Unexpected'
					}

				}

				{ $InputObj | Invoke-AIMClient -ErrorAction Stop } | Should -Throw '*CLIPasswordSDK exited with code 0x00000001: Something Unexpected*'

			}

			It 'reports non-zero exit code with no stderr' {

				Mock Start-AIMClientProcess -MockWith {
					[pscustomobject]@{
						'ExitCode' = -1073740791
						'StdOut'   = ''
						'StdErr'   = ''
					}

				}

				{ $InputObj | Invoke-AIMClient -ErrorAction Stop } | Should -Throw '*CLIPasswordSDK exited with code 0xC0000409*'

			}

			It 'does not output result when exit code is non-zero' {

				Mock Start-AIMClientProcess -MockWith {
					[pscustomobject]@{
						'ExitCode' = 1
						'StdOut'   = ''
						'StdErr'   = ''
					}

				}

				$InputObj | Invoke-AIMClient -ErrorAction SilentlyContinue | Should -BeNullOrEmpty

			}

			It 'outputs only the process result' {

				Mock Start-AIMClientProcess -MockWith {
					[pscustomobject]@{
						'ExitCode' = 0
						'StdOut'   = 'SomeOutput'
						'StdErr'   = ''
					}

				}

				$result = @($InputObj | Invoke-AIMClient)
				$result.Count | Should -Be 1
				$result[0].StdOut | Should -Be 'SomeOutput'

			}

		}

		Context 'Command Arguments' {

			BeforeEach {

				Mock Test-Path -MockWith {
					$true
				}

				Mock Start-AIMClientProcess -MockWith {
					Write-Output @{}
				}

				$InputObj = [pscustomobject]@{
					CommandParameters = 'Some Command Parameters'
				}

			}

			It 'executes command with expected arguments' {

				$InputObj | Invoke-AIMClient

				Should -Invoke Start-AIMClientProcess -Times 1 -Exactly -ParameterFilter {

					$Process.StartInfo.Arguments -eq $('GetPassword  Some Command Parameters')

				}

			}

		}

	}

}