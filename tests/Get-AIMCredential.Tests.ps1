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

			$Prefix = if ($IsWindows -eq $false) { '-' } else { '/' }

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

		It 'outputs PSCredential with AsCredential' {
			$result = $InputObj | Get-AIMCredential -AsCredential
			$result | Should BeOfType System.Management.Automation.PSCredential
			$result.UserName | Should Be 'SomeUser'
			$result.GetNetworkCredential().Password | Should Be 'SomePassword'
		}

		It 'requests UserName with AsCredential' {
			Get-AIMCredential -AppID SomeApp -Safe SomeSafe -AsCredential
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters -eq ('{0}p AppDescs.AppID="SomeApp" {0}p Query="Safe=SomeSafe" {0}p RequiredProps=UserName {0}o PassProps.UserName,Password,PasswordChangeInProcess {0}d #_-_#' -f $Prefix)
			} -Times 1 -Exactly -Scope It
		}

		It 'adds UserName to RequiredProps with AsCredential' {
			Get-AIMCredential -AppID SomeApp -Safe SomeSafe -RequiredProps Address -AsCredential
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters -eq ('{0}p AppDescs.AppID="SomeApp" {0}p Query="Safe=SomeSafe" {0}p RequiredProps=Address,UserName {0}o PassProps.Address,PassProps.UserName,Password,PasswordChangeInProcess {0}d #_-_#' -f $Prefix)
			} -Times 1 -Exactly -Scope It
		}

		It 'does not repeat UserName in RequiredProps with AsCredential' {
			$InputObj | Get-AIMCredential -AsCredential
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters.Contains('p RequiredProps=UserName,Prop2,Prop3,Prop4 ')
			} -Times 1 -Exactly -Scope It
		}

		It 'outputs SecureString with AsSecureString' {
			$result = $InputObj | Get-AIMCredential -AsSecureString
			$result | Should BeOfType System.Security.SecureString
			(New-Object System.Management.Automation.PSCredential('SomeUser', $result)).GetNetworkCredential().Password | Should Be 'SomePassword'
		}

		It 'throws when AsCredential and AsSecureString are used together' {
			{ $InputObj | Get-AIMCredential -AsCredential -AsSecureString } | Should Throw 'cannot be used together'
			Assert-MockCalled Invoke-AIMClient -Times 0 -Exactly -Scope It
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
				'{0}p Query="Safe=SomeSafe;Folder=SomeFolder;Object=SomeObject;UserName=SomeUser"'
				'{0}p QueryFormat="exact"'
				'{0}p RequiredProps=UserName,Prop2,Prop3,Prop4'
				'{0}p Reason="SomeReason"'
				'{0}p ConnectionParms.Port=123'
				'{0}p ConnectionParms.Timeout=666'
			) | ForEach-Object { $_ -f $Prefix }
			$Start = '{0}p AppDescs.AppID="SomeApp" ' -f $Prefix
			$End = ' {0}o PassProps.UserName,PassProps.Prop2,PassProps.Prop3,PassProps.Prop4,Password,PasswordChangeInProcess {0}d #_-_#' -f $Prefix
			$InputObj | Get-AIMCredential
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters.StartsWith($Start) -and
				$CommandParameters.EndsWith($End) -and
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
				$CommandParameters -eq ('{0}p AppDescs.AppID="SomeApp" {0}p Query="Safe=Safe1;Object=Object1" {0}o Password,PasswordChangeInProcess {0}d #_-_#' -f $Prefix)
			} -Times 1 -Exactly -Scope It
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters -eq ('{0}p AppDescs.AppID="SomeApp" {0}p Query="Safe=Safe2;Object=Object2" {0}o Password,PasswordChangeInProcess {0}d #_-_#' -f $Prefix)
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

		It 'sends free query' {
			Get-AIMCredential -AppID SomeApp -Query 'Safe=SomeSafe;CustomProp=Some Value' -QueryFormat regexp
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters -eq ('{0}p AppDescs.AppID="SomeApp" {0}p Query="Safe=SomeSafe;CustomProp=Some Value" {0}p QueryFormat="regexp" {0}o Password,PasswordChangeInProcess {0}d #_-_#' -f $Prefix)
			} -Times 1 -Exactly -Scope It
		}

		It 'sends command with - prefix on Linux' -Skip:($IsWindows -eq $true) {
			if ($PSVersionTable.PSEdition -eq 'Desktop') { $IsWindows = $false }
			Get-AIMCredential -AppID SomeApp -Safe SomeSafe -Reason SomeReason
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters -eq '-p AppDescs.AppID="SomeApp" -p Query="Safe=SomeSafe" -p Reason="SomeReason" -o Password,PasswordChangeInProcess -d #_-_#'
			} -Times 1 -Exactly -Scope It
		}

		It 'does not allow Query with search parameters' {
			{ Get-AIMCredential -AppID SomeApp -Query 'Safe=SomeSafe' -Object SomeObject } | Should Throw
		}

		It 'sends FailRequestOnPasswordChange' {
			Get-AIMCredential -AppID SomeApp -Safe SomeSafe -FailRequestOnPasswordChange
			Assert-MockCalled Invoke-AIMClient -ParameterFilter {
				$CommandParameters -eq ('{0}p AppDescs.AppID="SomeApp" {0}p Query="Safe=SomeSafe" {0}p FailRequestOnPasswordChange=true {0}o Password,PasswordChangeInProcess {0}d #_-_#' -f $Prefix)
			} -Times 1 -Exactly -Scope It
		}

		It 'outputs <na> and <null> property values as null' {
			Mock Invoke-AIMClient -MockWith {
				[pscustomobject]@{
					'ExitCode' = 0
					'StdOut'   = '<na>#_-_#<null>#_-_#SomePassword#_-_#false'
					'StdErr'   = $null
				}
			}
			$result = Get-AIMCredential -AppID SomeApp -Safe SomeSafe -RequiredProps Prop1, Prop2
			$result.Prop1 | Should BeNullOrEmpty
			$result.Prop2 | Should BeNullOrEmpty
			$result.Password | Should Be 'SomePassword'
		}

		It 'does not allow semicolon in search parameter value' {
			{ Get-AIMCredential -AppID SomeApp -Safe 'Some;Safe' } | Should Throw
			Assert-MockCalled Invoke-AIMClient -Times 0 -Exactly -Scope It
		}

		It 'does not allow double quote in Reason' {
			{ Get-AIMCredential -AppID SomeApp -Safe SomeSafe -Reason 'Some" /p Other=Value' } | Should Throw
			Assert-MockCalled Invoke-AIMClient -Times 0 -Exactly -Scope It
		}

	}

}