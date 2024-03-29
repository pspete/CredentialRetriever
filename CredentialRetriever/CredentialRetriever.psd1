@{

	# Script module or binary module file associated with this manifest.
	RootModule        = 'CredentialRetriever.psm1'

	# Version number of this module.
	ModuleVersion     = '3.10.56'

	# ID used to uniquely identify this module
	GUID              = '6c792ac3-4068-4190-a2fc-099d9da50752'

	# Author of this module
	Author            = 'Pete Maan'

	# Company or vendor of this module
	# CompanyName = ''

	# Copyright statement for this module
	Copyright         = '(c) 2018-2022 Pete Maan. All rights reserved.'

	# Description of the functionality provided by this module
	Description       = 'Retrieve Credentials from CyberArk Central Credential Provider via REST, or Local Credential Provider using CLIPasswordSDK'

	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '5.1'

	# Name of the Windows PowerShell host required by this module
	# PowerShellHostName = ''

	# Minimum version of the Windows PowerShell host required by this module
	# PowerShellHostVersion = ''

	# Minimum version of Microsoft .NET Framework required by this module
	# DotNetFrameworkVersion = ''

	# Minimum version of the common language runtime (CLR) required by this module
	# CLRVersion = ''

	# Processor architecture (None, X86, Amd64) required by this module
	# ProcessorArchitecture = ''

	# Modules that must be imported into the global environment prior to importing this module
	# RequiredModules = @()

	# Assemblies that must be loaded prior to importing this module
	# RequiredAssemblies = @()

	# Script files (.ps1) that are run in the caller's environment prior to importing this module.
	# ScriptsToProcess = @()

	# Type files (.ps1xml) to be loaded when importing this module
	#TypesToProcess    = @()

	# Format files (.ps1xml) to be loaded when importing this module
	#FormatsToProcess  = @()

	# Functions to export from this module
	FunctionsToExport = @(
		'Get-CCPCredential',
		'Get-AIMCredential',
		'Set-AIMConfiguration'
	)

	#AliasesToExport   = @()

	# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData       = @{

		PSData = @{

			# Tags applied to this module. These help with module discovery in online galleries.
			Tags       = @('CyberArk', 'REST', 'API', 'Security', 'AIM', 'AAM', 'CentralCredentialProvider', 'CredentialProvider', 'CLIPasswordSDK')

			# A URL to the license for this module.
			LicenseUri = 'https://github.com/pspete/CredentialRetriever/blob/master/LICENSE.md'

			# A URL to the main website for this project.
			ProjectUri = 'https://github.com/pspete/CredentialRetriever'

			# A URL to an icon representing this module.
			# IconUri = ''

			# ReleaseNotes of this module
			# ReleaseNotes = ''

		} # End of PSData hashtable

	} # End of PrivateData hashtable

}
