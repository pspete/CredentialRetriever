# CredentialRetriever Changelog

## Unreleased

### Added

- `Get-CCPCredential`: `Method` parameter (`GET` or `POST`, default `GET`). `POST` sends request details in a JSON body (requires CCP 14.2 or later).
- `Get-CCPCredential`: `QueryFormat` parameter (`Exact` or `Regexp`), for use with `Query`.
- `Get-CCPCredential`: `FailRequestOnPasswordChange` parameter.
- `Get-AIMCredential`: `Query` parameter, for a free query of account properties (e.g. `Safe=PS;CustomProperty=Value`).
- `Get-AIMCredential`: `FailRequestOnPasswordChange` parameter.
- `Get-AIMConfiguration`: outputs the CLIPasswordSDK configuration.
- CLIPasswordSDK path is detected from its default install location when no configuration has been saved.
- Module manifest: `CompatiblePSEditions` (`Desktop`, `Core`).
- `Get-AIMCredential`: Linux support. CLIPasswordSDK arguments use the `-` prefix on Linux (`/` on Windows).
- `Get-CCPCredential`, `Get-AIMCredential`: `AsCredential` and `AsSecureString` switches, to output a `PSCredential` or `SecureString` instead of the result object. `Get-AIMCredential -AsCredential` requests the `UserName` property automatically.

### Changed

- **BREAKING** `Get-CCPCredential`: `Query` now takes the CCP free query value (e.g. `Safe=PS;Object=PSP-AccountName`) instead of a complete URL query string. `AppID` is now required with `Query`, and `Reason` can be used with it.
  - Before: `-Query 'AppID=PS&Safe=PS&Object=PSP-AccountName'`
  - After: `-AppID PS -Query 'Safe=PS;Object=PSP-AccountName'`
- **BREAKING** `Get-CCPCredential`: request errors are now non-terminating, so remaining pipeline input is still processed. Use `-ErrorAction Stop` for the previous behaviour.
- **BREAKING** `Get-AIMCredential`: `Safe` now binds from pipeline by property name, consistent with other parameters, instead of by value.
- **BREAKING** `Get-AIMCredential`: requested properties which do not exist (`<na>`) or have no value (`<null>`) are now output as `$null`.
- **BREAKING** `Set-AIMConfiguration`: `ClientPath` is now mandatory.
- `Get-AIMCredential`: search parameter values containing `;` or `"`, and `Query`/`Reason` values containing `"`, are now rejected.
- `Get-CCPCredential`: on Windows PowerShell, TLS 1.2 is added to explicitly configured security protocols instead of replacing them, and `SystemDefault` is left unchanged. On PowerShell Core, `SslProtocol` is no longer pinned to TLS 1.2, allowing TLS 1.3.
- `Get-CCPCredential`: on Windows PowerShell, `SkipCertificateCheck` now applies only to the request; the previous certificate policy is restored afterwards.
- Configuration file path is now `$HOME/AIMConfiguration.xml` (unchanged on Windows), for Linux/macOS support.

### Fixed

- `Get-CCPCredential`: error responses without `ErrorMsg`/`ErrorCode` (e.g. HTTP 405) were masked by an `ErrorRecord` constructor error.
- `Get-CCPCredential`: `ConnectionTimeout` was ignored when used with `Query`.
- `Get-CCPCredential`: when a piped request failed, the result of the previous request was output again.
- `Get-AIMCredential`: piping multiple objects repeated the first query and failed to parse output for subsequent objects.
- `Get-AIMCredential`: a failed `CLIPasswordSDK` process (non-zero exit code without a recognised error message) output an empty object instead of an error.
- `Get-AIMCredential`: a configured CLIPasswordSDK path which does not exist is now reported as not found.
- `Get-CCPCredential`: a `URL` with a trailing `/` produced a request URL containing `//`.
- `Set-AIMConfiguration`: `WhatIf` and `Confirm` were ignored.
- Module manifest: `LicenseUri`.

## 3.10.56

- Update `Get-CCPCredential`
  - Allow `Certificate`/`CertificateThumbprint` to be specified together with `Credential`/`UseDefaultCredential` parameters.

## 3.9.48 (July 25th 2022)

- Update Help Examples
  - Updates `Get-CCPCredential` examples.
    - Thanks [@jeffrechten](https://github.com/jeffrechten)

## 3.9.44 (January 9th 2022)

- Update `Get-AIMCredential`
  - Resolves issue where specifying a value for the `-Reason` parameter which includes a space resulted in an error.

- Update `Get-CCPCredential`
  - Adds `Query` parameter to allow users to specify own query filter value to include in request URL.

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
