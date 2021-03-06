# CredentialRetriever

| Master Branch            | Latest Build            | CodeFactor                | Coverage                    |  PowerShell Gallery       |  License                   |
|--------------------------|-------------------------|---------------------------|-----------------------------|---------------------------|----------------------------|
|[![appveyor][]][av-site]  |[![tests][]][tests-site] | [![codefactor][]][cf-site]| [![codecov][]][codecov-link]| [![psgallery][]][ps-site] |[![license][]][license-link]|
|                          |                         |                           | [![coveralls][]][cv-site]   | [![downloads][]][ps-site] |                            |

[appveyor]:https://ci.appveyor.com/api/projects/status/s2x3alg52ctp2pyl/branch/master?svg=true
[av-site]:https://ci.appveyor.com/project/pspete/CredentialRetriever/branch/master
[coveralls]:https://coveralls.io/repos/github/pspete/CredentialRetriever/badge.svg?branch=master
[cv-site]:https://coveralls.io/github/pspete/CredentialRetriever?branch=master
[psgallery]:https://img.shields.io/powershellgallery/v/CredentialRetriever.svg
[ps-site]:https://www.powershellgallery.com/packages/CredentialRetriever
[tests]:https://img.shields.io/appveyor/tests/pspete/CredentialRetriever.svg
[tests-site]:https://ci.appveyor.com/project/pspete/CredentialRetriever
[downloads]:https://img.shields.io/powershellgallery/dt/credentialretriever.svg?color=blue
[cf-site]:https://www.codefactor.io/repository/github/pspete/credentialretriever
[codefactor]:https://www.codefactor.io/repository/github/pspete/credentialretriever/badge
[codecov]:https://codecov.io/gh/pspete/CredentialRetriever/branch/master/graph/badge.svg
[codecov-link]:https://codecov.io/gh/pspete/CredentialRetriever
[license]:https://img.shields.io/github/license/pspete/credentialretriever.svg
[license-link]:https://github.com/pspete/CredentialRetriever/blob/master/LICENSE.md

## **CyberArk Central Credential Provider PowerShell Retriever**

Use PowerShell to retrieve credentials from the CyberArk Central Credential Provider Web Service or a local Credential Provider SDK.

----------

## Usage

### Get-CCPCredential

Supply the AppID and URL to the CyberArk Central Credential Provider Web Service.

Specify relevant parameter values needed to find the required account.

![Get-CCPCredential](media/RetrieveCreds.png)

### Get-AIMCredential

Set the path to the CLIPasswordSDK.exe utility. This value will persist, and be imported each time the CredentialRetriever module is imported.

![Set-AIMConfiguration](media/Set-AIMConfiguration.png)

Supply the AppID & relevant parameter values needed to find the required account.

![Get-AIMCredential](media/Get-AIMCredential.png)

### ToSecureString Method

Where required for downstream consumption, easily convert returned password to a
`System.Security.SecureString`, using the `ToSecureString()` Method.

![ToSecureString Method](media/ToSecureString.png)

### ToCredential Method

Use the `ToCredential()` Method to convert the returned Username/Password to a `PSCredential` Object.

![ToCredential Method](media/ToCredential.png)

## Installation

### Prerequisites

- Requires Powershell v5.1 (minimum)
- CyberArk Central Credential Provider Web Service, And\Or
- CyberArk Credential Provider

### Install Options

This repository contains a folder named ```CredentialRetriever```.

The folder needs to be copied to one of your PowerShell Module Directories.

Use one of the following methods:

#### Option 1: Install from PowerShell Gallery

PowerShell 5.0 or above & Administrator rights are required.

To download the module from the [PowerShell Gallery](https://www.powershellgallery.com/packages/CredentialRetriever/), </br>
from an elevated PowerShell prompt, run:

````Install-Module -Name CredentialRetriever -Scope CurrentUser````

#### Option 2: Manual Install

Find your PowerShell Module Paths with the following command:

```powershell

$env:PSModulePath.split(';')

```

[Download the ```master branch```](https://github.com/pspete/CredentialRetriever/archive/master.zip)

Extract the archive

Copy the ```CredentialRetriever``` folder to your "Powershell Modules" directory of choice.

#### Verification

Validate Module Exists on your local machine:

```powershell

Get-Module -ListAvailable CredentialRetriever

```

Import the module:

```powershell

Import-Module CredentialRetriever

```

Get detailed information on commands:

```powershell

Get-Help Get-CCPCredential -Full

```

## Changelog

All notable changes to this project will be documented in the [Changelog](CHANGELOG.md)

## Author

- **Pete Maan** - [pspete](https://github.com/pspete)

## License

This project is [licensed under the MIT License](LICENSE).

## Contributing

Any and all contributions to this project are appreciated.

See the [CONTRIBUTING.md](CONTRIBUTING.md) for a few more details.
