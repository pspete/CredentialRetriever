#Get Current Directory
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

#Get Function Name
$FunctionName = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -Replace ".Tests.ps1"

#Assume ModuleName from Repository Root folder
$ModuleName = Split-Path (Split-Path $Here -Parent) -Leaf

#Resolve Path to Module Directory
$ModulePath = Resolve-Path "$Here\..\$ModuleName"

#Define Path to Module Manifest
$ManifestPath = Join-Path "$ModulePath" "$ModuleName.psd1"

#Preference file must be removed and module must be re-imported for tests to complete
Remove-Item -Path "$env:HOMEDRIVE$env:HomePath\PARConfiguration.xml" -Force -ErrorAction SilentlyContinue
Remove-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue
Import-Module -Name "$ManifestPath" -ArgumentList $true -Force -ErrorAction Stop

BeforeAll {

	#$Script:RequestBody = $null

}

AfterAll {

	#$Script:RequestBody = $null

}

Describe $FunctionName {

	InModuleScope $ModuleName {

		Context "Mandatory Parameters" {

			$Parameters = @{Parameter = 'CommandParameters'}

			It "specifies parameter <Parameter> as mandatory" -TestCases $Parameters {

				param($Parameter)

				(Get-Command Invoke-AIMClient).Parameters["$Parameter"].Attributes.Mandatory | Should Be $true

			}



		}

		Context "Default" {

			BeforeEach {

				Mock Start-AIMClientProcess -MockWith {
					Write-Output @{}
				}

				$InputObj = [pscustomobject]@{
					CommandParameters = "Some Command Parameters"
				}


			}

			It "tests path" {

				{$InputObj | Invoke-AIMClient -ClientPath .\RandomFile.exe} | Should Throw

			}

			It "throws if `$AIM variable not set in script scope" {

				{$InputObj | Invoke-AIMClient} | Should Throw

			}

			It "throws if `$AIM variable does not have ClientPath property" {

				$object = [PSCustomObject]@{
					prop1 = "Value1"
					prop2 = "Value2"
				}
				New-Variable -Name AIM -Value $object

				{$InputObj | Invoke-AIMClient} | Should Throw

			}

			It "throws if `$AIM.ClientPath is not resolvable" {

				$object = [PSCustomObject]@{
					ClientPath = ".\RandomFile.Exe"
					prop2      = "Value2"
				}
				New-Variable -Name AIM -Value $object

				{$InputObj | Invoke-AIMClient} | Should Throw

			}

			It "no throw if `$AIM.ClientPath is resolvable" {

				$object = [PSCustomObject]@{
					ClientPath = ".\README.md"
					prop2      = "Value2"
				}
				New-Variable -Name AIM -Value $object

				{$InputObj | Invoke-AIMClient} | Should Throw

			}


		}

		Context "Set-AIMConfiguration" {

			BeforeEach {

				Mock Test-Path -MockWith {
					$true
				}

				Mock Start-AIMClientProcess -MockWith {
					Write-Output @{}
				}

				$InputObj = [pscustomobject]@{
					CommandParameters = "Some Command Parameters"
				}


			}

			it "does not throw after Set-AIMConfiguration has set the `$AIM variable" {

				Set-AIMConfiguration -ClientPath "C:\SomePath\CLIPasswordSDK.exe"
				{$InputObj | Invoke-AIMClient} | Should Not throw

			}

			it "does not require Set-AIMConfiguration to be run more than once" {

				{$InputObj | Invoke-AIMClient} | Should Not throw

			}

		}

		Context "Reporting Errors" {

			BeforeEach {

				$InputObj = [pscustomobject]@{
					CommandParameters = "Some Command Parameters"
				}


			}

			it "reports 'ErrorCode Message' format errors on stderr" {

				Mock Start-AIMClientProcess -MockWith {
					[pscustomobject]@{
						"ExitCode" = -1
						"StdOut"   = $null
						"StdErr"   = "APPAP008E Problem occurred while trying to use user in the Vault"
					}

				}

				{$InputObj | Invoke-AIMClient -ErrorAction Stop} | Should Throw "Problem occurred while trying to use user in the Vault"

			}

			it "reports '(ErrorCode) Message' format errors on stderr" {

				Mock Start-AIMClientProcess -MockWith {
					[pscustomobject]@{
						"ExitCode" = -1
						"StdOut"   = $null
						"StdErr"   = "ERROR (999) Something Awful."
					}

				}

				{$InputObj | Invoke-AIMClient -ErrorAction Stop} | Should Throw "Something Awful."

			}

		}

		Context "Command Arguments" {
			Mock Test-Path -MockWith {
				$true
			}

			Mock Start-AIMClientProcess -MockWith {
				Write-Output @{}
			}

			$InputObj = [pscustomobject]@{
				CommandParameters = "Some Command Parameters"
			}

			It "executes command with expected arguments" {

				$InputObj | Invoke-AIMClient

				Assert-MockCalled Start-AIMClientProcess -Times 1 -Exactly -Scope It -ParameterFilter {

					$Process.StartInfo.Arguments -eq $('GetPassword  Some Command Parameters')

				}

			}

		}

	}

}