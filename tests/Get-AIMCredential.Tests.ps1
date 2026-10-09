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
	Describe 'Get-AIMCredential' {

		BeforeEach {

			Mock Invoke-AIMClient -MockWith {
				[pscustomobject]@{
					'ExitCode' = 0
					'StdOut'   = 'SomeUser#_-_#value2#_-_#value3#_-_#value4#_-_#SomePassword#_-_#true'
					'StdErr'   = $null
				}
			}

			$InputObj = [pscustomobject]@{
				AppID         = 'SomeApp'
				Safe          = 'SomeSafe'
				Folder        = 'SomeFolder'
				Object        = 'SomeObject'
				UserName      = 'SomeUser'
				QueryFormat   = 'exact'
				RequiredProps = 'UserName', 'Prop2', 'Prop3', 'Prop4'
				Reason        = 'SomeReason'
				Port          = 123
				Timeout       = 666


			}

		}

		It 'executes command' {

			$InputObj | Get-AIMCredential -Verbose

			Assert-MockCalled Invoke-AIMClient -Times 1 -Exactly -Scope It

		}

		It 'outputs object with ToSecureString method' {
			$result = $InputObj | Get-AIMCredential
			$result | Get-Member -MemberType ScriptMethod | Select-Object -ExpandProperty Name | Should Contain 'ToSecureString'
		}

		It 'converts output to expected SecureString' {
			$result = $InputObj | Get-AIMCredential
			$credential = New-Object System.Management.Automation.PSCredential('SomeUser', $result.ToSecureString())
			$credential.GetNetworkCredential().Password | Should Be 'SomePassword'

		}

		It 'outputs object with ToCredential method' {
			$result = $InputObj | Get-AIMCredential
			$result | Get-Member -MemberType ScriptMethod | Select-Object -ExpandProperty Name | Should Contain 'ToCredential'
		}

		It 'outputs expected password to pscredential object' {
			$result = $InputObj | Get-AIMCredential
			($result.ToCredential()).GetNetworkCredential().Password | Should Be 'SomePassword'
		}

		It 'outputs expected password containing comma' {
			Mock Invoke-AIMClient -MockWith {
				[pscustomobject]@{
					'ExitCode' = 0
					'StdOut'   = 'SomeUser#_-_#value2#_-_#value3#_-_#value4#_-_#Some,Password#_-_#true'
					'StdErr'   = $null
				}
			}
			$result = $InputObj | Get-AIMCredential
			$result.Password | Should Be 'Some,Password'
		}

		It 'sends expected command' {
			$Expected = @(
				'/p Query="Safe=SomeSafe;Folder=SomeFolder;Object=SomeObject;UserName=SomeUser"'
				'/p QueryFormat="exact"'
				'/p RequiredProps=UserName,Prop2,Prop3,Prop4'
				'/p Reason="SomeReason"'
				'/p ConnectionParms.Port=123'
				'/p ConnectionParms.Timeout=666'
			)
			$InputObj | Get-AIMCredential
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters.StartsWith('/p AppDescs.AppID="SomeApp" ') -and
				$CommandParameters.EndsWith(' /o PassProps.UserName,PassProps.Prop2,PassProps.Prop3,PassProps.Prop4,Password,PasswordChangeInProcess /d #_-_#') -and
				@($Expected | Where-Object { -not $CommandParameters.Contains($_) }).Count -eq 0
			} -Times 1 -Exactly -Scope It
		}

		It 'sends separate query for each piped object' {
			$Objects = @(
				[pscustomobject]@{ AppID = 'SomeApp'; Safe = 'Safe1'; Object = 'Object1' },
				[pscustomobject]@{ AppID = 'SomeApp'; Safe = 'Safe2'; Object = 'Object2' }
			)
			$Objects | Get-AIMCredential
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters -eq '/p AppDescs.AppID="SomeApp" /p Query="Safe=Safe1;Object=Object1" /o Password,PasswordChangeInProcess /d #_-_#'
			} -Times 1 -Exactly -Scope It
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters -eq '/p AppDescs.AppID="SomeApp" /p Query="Safe=Safe2;Object=Object2" /o Password,PasswordChangeInProcess /d #_-_#'
			} -Times 1 -Exactly -Scope It
		}

		It 'outputs one object for each piped object' {
			Mock Invoke-AIMClient -MockWith {
				[pscustomobject]@{
					'ExitCode' = 0
					'StdOut'   = 'SomePassword#_-_#false'
					'StdErr'   = $null
				}
			}
			$result = @(
				[pscustomobject]@{ AppID = 'SomeApp'; Safe = 'Safe1' },
				[pscustomobject]@{ AppID = 'SomeApp'; Safe = 'Safe2' }
			) | Get-AIMCredential
			$result.Count | Should Be 2
			$result | ForEach-Object { $_.Password | Should Be 'SomePassword' }
		}

		It 'does not bind piped string to Safe' {
			{ 'SomeSafe' | Get-AIMCredential -AppID SomeApp -ErrorAction Stop } | Should Throw
		}

	}

}