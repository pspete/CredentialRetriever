# CredentialRetriever Changelog

## 3.4.0 (March 2020)

## 3.3.16 (December 12th 2019)

- Update `Get-CCPCredential`
  - Added `certificate` parameter for specifyng an x509 certificate to use for the connection.

## 3.2.11 (April 30th 2019)

- Fix `Get-AIMCredential`
  - Adds support for spaces in application names.

## 3.1.9 (April 9th 2019)

- Updates
  - Changed configuration file path
    - Old Path: `$env:HOMEDRIVE$env:HomePath\AIMConfiguration.xml`
    - New Path: `$env:USERPROFILE\AIMConfiguration.xml`

## 3.0.7 (March 5th 2019)

Module updated to work with a locally installed Credential Provider in addition to the Central Credential Provider.

- New Functions
  - `Set-AIMConfiguration`
    - Sets path to a local credential provider utility
  - `Get-AIMCredential`
    - Retrieves password from a local credential provider

## 2.0.6 (December 5th 2018)

- Updates
  - Added support for client certificate authentication.
  - `UseBasicParsing` parameter added to `Invoke-RestMethod` call.

## 1.0.0 (April 2018)

Initial Release
