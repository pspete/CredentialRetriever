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

	Import-Module -Name "$ManifestPath" -Force -ErrorAction Stop

}
InModuleScope $ModuleName {
	Describe "Get-CCPCredential" {



		BeforeEach {
			Mock Invoke-RestMethod {}
			$InputObj = [pscustomobject]@{
				"AppID" = "SomeApplication"
				"URL"   = "https://SomeURL"
			}
		}

		It "sends request" {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -Scope It
		}

		It "sends request with expected method" {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$Method -eq "GET"

			} -Times 1 -Exactly -Scope It
		}

		It "sends request with expected content-type" {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {
				$ContentType -eq "application/json"

			} -Times 1 -Exactly -Scope It
		}

		It "sends request to expected URL" {
			$InputObj | Get-CCPCredential
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$URI -eq "https://SomeURL/AIMWebService/api/Accounts?AppID=SomeApplication"

			} -Times 1 -Exactly -Scope It
		}

		It "sends request to specified web service URL" {
			$InputObj | Get-CCPCredential -WebServiceName DEV
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$URI -eq "https://SomeURL/DEV/api/Accounts?AppID=SomeApplication"

			} -Times 1 -Exactly -Scope It
		}

		#If Tls12 Security Protocol is available
		if([Net.SecurityProtocolType].GetEnumNames() -contains "Tls12") {

			It "uses TLS12" {
				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11
				$InputObj | Get-CCPCredential
				[System.Net.ServicePointManager]::SecurityProtocol | Should Be Tls12
			}

		}

		It "invokes rest method with credentials" {

			$credential = New-Object System.Management.Automation.PSCredential("SomeUser", $("SomePassword" | ConvertTo-SecureString -AsPlainText -Force))
			$InputObj | Get-CCPCredential -credential $cred
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$credential -eq $cred

			} -Times 1 -Exactly -Scope It
		}

		It "invokes rest method with default credentials switch" {

			$InputObj | Get-CCPCredential -UseDefaultCredentials
			Assert-MockCalled Invoke-RestMethod -ParameterFilter {

				$UseDefaultCredentials -eq $true

			} -Times 1 -Exactly -Scope It
		}

		It "outputs object with ToSecureString method" {
			Mock Invoke-RestMethod {[pscustomobject]@{"content" = "SomePassword"; "username" = "SomeUser"}}
			$result = $InputObj | Get-CCPCredential
			$result | get-member -MemberType ScriptMethod | Select-Object -ExpandProperty Name | Should Contain "ToSecureString"
		}

		It "converts output to expected SecureString" {
			Mock Invoke-RestMethod {[pscustomobject]@{"content" = "SomePassword"; "username" = "SomeUser"}}
			$result = $InputObj | Get-CCPCredential
			$credential = New-Object System.Management.Automation.PSCredential("SomeUser", $result.ToSecureString())
			$credential.GetNetworkCredential().Password | Should Be "SomePassword"

		}

		It "outputs object with ToCredential method" {
			Mock Invoke-RestMethod {[pscustomobject]@{"content" = "SomePassword"; "username" = "SomeUser"}}
			$result = $InputObj | Get-CCPCredential
			$result | Get-Member -MemberType ScriptMethod | Select-Object -ExpandProperty Name | Should Contain "ToCredential"
		}

		It "outputs expected password to pscredential object" {
			Mock Invoke-RestMethod {[pscustomobject]@{"content" = "SomePassword"; "username" = "SomeUser"}}
			$result = $InputObj | Get-CCPCredential
			($result.ToCredential()).GetNetworkCredential().Password | Should Be "SomePassword"
		}

	}

}
