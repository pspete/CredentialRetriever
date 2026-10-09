# CredentialRetriever Changelog

## Unreleased

- N/A

## [4.0.0] - 2026-10-09

### Added

- `Get-CCPCredential`: `Method` parameter (`GET` or `POST`, default `GET`). `POST` sends request details in a JSON body (requires CCP 14.2 or later).
  - Thanks [JP-Consulting](https://github.com/johannesconsulting)!!!!
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
- Help is now external help (`en-US/CredentialRetriever-help.xml`), generated from the command markdown in `docs/collections/_commands`.
- The module is now released as a single combined `.psm1`.
- Build, test and release moved from AppVeyor to GitHub Actions; tests now use Pester 5 and run on Windows PowerShell 5.1, PowerShell 7 on Windows and PowerShell 7 on Linux.

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

## [3.10.56] - 2022-09-18

- Update `Get-CCPCredential`
  - Allow `Certificate`/`CertificateThumbprint` to be specified together with `Credential`/`UseDefaultCredential` parameters.

## [3.9.48] - 2022-07-25

- Update Help Examples
  - Updates `Get-CCPCredential` examples.
    - Thanks [@jeffrechten](https://github.com/jeffrechten)

## [3.9.44] - 2022-01-09

- Update `Get-AIMCredential`
  - Resolves issue where specifying a value for the `-Reason` parameter which includes a space resulted in an error.

- Update `Get-CCPCredential`
  - Adds `Query` parameter to allow users to specify own query filter value to include in request URL.

## [3.8.36] - 2021-06-30

- Update to avoid an observed unexpected error behaviour.

## [3.7.34] - 2021-04-11

- Update `Get-CCPCredential`
  - Added `SkipCertificateCheck` parameter.

## [3.6.30] - 2020-09-20

- Fix `Get-AIMCredential`
  - Resolves issue where specifying the `-ErrorAction` parameter when invoking the command resulted in an error.

## [3.5.25] - 2020-04-18

- Fix `Get-AIMCredential`
  - Fix output parsing bug introduced in `3.5.22`.

## [3.5.22] - 2020-04-10

- Fix `Get-AIMCredential`
  - Resolves error when returning passwords containing a comma character.

## [3.4.19] - 2020-03-27

- Changed minimum required PowerShell version to 5.1

## [3.3.16] - 2019-12-12

- Update `Get-CCPCredential`
  - Added `certificate` parameter for specifying an x509 certificate to use for the connection.

## [3.2.12] - 2019-04-30

- Fix `Get-AIMCredential`
  - Adds support for spaces in application names.

## [3.1.9] - 2019-04-09

- Updates
  - Changed configuration file path
    - Old Path: `$env:HOMEDRIVE$env:HomePath\AIMConfiguration.xml`
    - New Path: `$env:USERPROFILE\AIMConfiguration.xml`

## [3.0.7] - 2019-03-05

Module updated to work with a locally installed Credential Provider in addition to the Central Credential Provider.

- New Functions
  - `Set-AIMConfiguration`
    - Sets path to a local credential provider utility
  - `Get-AIMCredential`
    - Retrieves password from a local credential provider

## [2.0.6] - 2018-12-05

- Updates
  - Added support for client certificate authentication.
  - `UseBasicParsing` parameter added to `Invoke-RestMethod` call.

## [1.0.0] - 2018-04-07

Initial Release
