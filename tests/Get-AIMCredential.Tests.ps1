#$here = Split-Path -Parent $MyInvocation.MyCommand.Path
#$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
#. "$here\$sut"

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

if( -not (Get-Module -Name $ModuleName -All)) {

	Import-Module -Name "$ManifestPath" -ArgumentList $true -Force -ErrorAction Stop

}
InModuleScope $ModuleName {
	Describe "Get-AIMCredential" {

		BeforeEach {

			Mock Invoke-AIMClient -MockWith {
				[pscustomobject]@{
					"ExitCode" = 0
					"StdOut"   = "SomeUser#_-_#value2#_-_#value3#_-_#value4#_-_#SomePassword#_-_#true"
					"StdErr"   = $null
				}
			}

			$InputObj = [pscustomobject]@{
				AppID         = "SomeApp"
				Safe          = "SomeSafe"
				Folder        = "SomeFolder"
				Object        = "SomeObject"
				UserName      = "SomeUser"
				QueryFormat   = "exact"
				RequiredProps = "UserName", "Prop2", "Prop3", "Prop4"
				Reason        = "SomeReason"
				Port          = 123
				Timeout       = 666


			}

		}

		It "executes command" {

			$InputObj | Get-AIMCredential -verbose

			Assert-MockCalled Invoke-AIMClient -Times 1 -Exactly -Scope It

		}

		It "outputs object with ToSecureString method" {
			$result = $InputObj | Get-AIMCredential
			$result | get-member -MemberType ScriptMethod | Select-Object -ExpandProperty Name | Should Contain "ToSecureString"
		}

		It "converts output to expected SecureString" {
			$result = $InputObj | Get-AIMCredential
			$credential = New-Object System.Management.Automation.PSCredential("SomeUser", $result.ToSecureString())
			$credential.GetNetworkCredential().Password | Should Be "SomePassword"

		}

		It "outputs object with ToCredential method" {
			$result = $InputObj | Get-AIMCredential
			$result | Get-Member -MemberType ScriptMethod | Select-Object -ExpandProperty Name | Should Contain "ToCredential"
		}

		It "outputs expected password to pscredential object" {
			$result = $InputObj | Get-AIMCredential
			($result.ToCredential()).GetNetworkCredential().Password | Should Be "SomePassword"
		}

		It "outputs expected password containing comma" {
			Mock Invoke-AIMClient -MockWith {
				[pscustomobject]@{
					"ExitCode" = 0
					"StdOut"   = "SomeUser#_-_#value2#_-_#value3#_-_#value4#_-_#Some,Password#_-_#true"
					"StdErr"   = $null
				}
			}
			$result = $InputObj | Get-AIMCredential
			$result.Password | Should Be "Some,Password"
		}

	}

}