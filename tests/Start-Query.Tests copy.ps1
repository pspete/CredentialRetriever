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

		Context "Test AIM" {			
			It "Tests AIM Query with Regex"  {				
				$safe = "automation"
				$appID = "Automation"
				$url =  "https://myvault.test.lab"
				$queryFormat = "Regexp"				
				$query1 = "Safe=$($safe);Address=1.1.1.1;CustomProp=Customdata"
				
				
				$result = Get-CCPCredential -URL $url -AppID $appID -Query $query1 -QueryFormat $queryFormat 				 
				$cred = $result.ToCredential()
			}			
		}		
	}
}