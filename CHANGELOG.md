# CredentialRetriever Changelog

## 3.8.36

- Update to avoid an observed unexpected error behaviour.

## 3.7.34 (April 11th 2021)

- Update `Get-CCPCredential`
  - Added `SkipCertificateCheck` parameter.

## 3.6.30 (September 20th 2020)

- Fix `Get-AIMCredential`
  - Resolves issue where specifying the `-ErrorAction` parameter when invoking the command resulted in an error.

## 3.5.25 (April 18th 2020)

- Fix `Get-AIMCredential`
  - Fix output parsing bug introduced in `3.5.22`.

## 3.5.22 (April 10th 2020)

- Fix `Get-AIMCredential`
  - Resolves error when returning passwords containing a comma character.

## 3.4.19 (March 27th 2020)

- Changed minimum required PowerShell version to 5.1

## 3.3.16 (December 12th 2019)

- Update `Get-CCPCredential`
  - Added `certificate` parameter for specifying an x509 certificate to use for the connection.

## 3.2.12 (April 30th 2019)

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
