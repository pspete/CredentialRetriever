---
external help file: CredentialRetriever-help.xml
Module Name: CredentialRetriever
online version:
schema: 2.0.0
title: Get-CCPCredential
---

# Get-CCPCredential

## SYNOPSIS
Use the GetPassword REST Web Service to retrieve passwords from the CyberArk AAM Central Credential Provider.

## SYNTAX

### Default (Default)
```
Get-CCPCredential -AppID <String> [-Safe <String>] [-Folder <String>] [-Object <String>] [-UserName <String>]
 [-Address <String>] [-Database <String>] [-PolicyID <String>] [-Reason <String>] [-ConnectionTimeout <Int32>]
 [-FailRequestOnPasswordChange] [-Credential <PSCredential>] [-UseDefaultCredentials]
 [-Certificate <X509Certificate>] [-CertificateThumbPrint <String>] [-WebServiceName <String>] -URL <String>
 [-SkipCertificateCheck] [-Method <String>] [-AsCredential] [-AsSecureString] [<CommonParameters>]
```

### Query
```
Get-CCPCredential -AppID <String> [-Reason <String>] -Query <String> [-QueryFormat <String>]
 [-ConnectionTimeout <Int32>] [-FailRequestOnPasswordChange] [-Credential <PSCredential>]
 [-UseDefaultCredentials] [-Certificate <X509Certificate>] [-CertificateThumbPrint <String>]
 [-WebServiceName <String>] -URL <String> [-SkipCertificateCheck] [-Method <String>] [-AsCredential]
 [-AsSecureString] [<CommonParameters>]
```

## DESCRIPTION
When the AAM Central Credential Provider for Windows is published via IIS and the Central
Credential Provider Web Service, this function can be used to retrieve credentials.
Passwords stored in the CyberArk Vault are retrieved to the Central Credential Provider, where
they can be accessed by authorized remote applications/scripts using a web service call.

## EXAMPLES

### EXAMPLE 1
```
Get-CCPCredential -AppID PSScript -Safe PSAccounts -Object PSPlatform-AccountName -URL https://cyberark.yourcompany.com
```

Uses the PSScript App ID to retrieve password for the PSPlatform-AccountName object in the PSAccounts safe from the
https://cyberark.yourcompany.com/AIMWebService CCP Web Service.

### EXAMPLE 2
```
Get-CCPCredential -AppID PowerShell -Safe PSAccounts -UserName svc-psProvision -WebServiceName DevAIM -URL https://cyberark-dev.yourcompany.com
```

Uses the PowerShell App ID to search for and retrieve the password for the svc-psProvision account in the PSAccounts safe
from the https://cyberark-dev.yourcompany.com/DevAIM CCP Web Service.

### EXAMPLE 3
```
Get-CCPCredential -AppID PowerShell -Safe PSAccounts -UserName svc-psProvision -WebServiceName DevAIM -Method POST -URL https://cyberark-dev.yourcompany.com
```

Uses the PowerShell App ID to search for and retrieve the password for the svc-psProvision account in the PSAccounts safe
from the https://cyberark-dev.yourcompany.com/DevAIM CCP Web Service using POST method.

### EXAMPLE 4
```
$result = Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com
$result.ToSecureString()
```

Returns the password retrieved from CCP as a Secure String

### EXAMPLE 5
```
$result = Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com
$result.ToCredential()
```

Returns the username & password retrieved from CCP as a PSCredential object

### EXAMPLE 6
```
$credential = Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -AsCredential
```

Outputs the username & password retrieved from CCP as a PSCredential object

### EXAMPLE 7
```
Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -UseDefaultCredentials
```

Calls Invoke-RestMethod with the UseDefaultCredentials switch to use OS User authentication

### EXAMPLE 8
```
Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -Credential $creds
```

Calls Invoke-RestMethod with the supplied Credentials for OS User authentication

### EXAMPLE 9
```
Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -CertificateThumbPrint $Cert_ThumbPrint
```

Calls Invoke-RestMethod with the supplied Certificate thumbprint

### EXAMPLE 10
```
Get-CCPCredential -AppID PS -Safe PS -Object PSP-AccountName -URL https://cyberark.yourcompany.com -Certificate $Cert
```

Calls Invoke-RestMethod with the supplied Certificate for Certificate authentication

### EXAMPLE 11
```
Get-CCPCredential -AppID PS -Query 'Safe=PS;Object=PSP-AccountName' -QueryFormat Exact -URL https://cyberark.yourcompany.com
```

Uses the PS App ID to retrieve the password matching the free query for the PSP-AccountName object in the PS safe.

### EXAMPLE 12
```
Get-CCPCredential -AppID PS -Query 'Safe=PS;CustomFileCategoryName1=Yourcompany Data' -URL https://cyberark.yourcompany.com
```

Uses the PS App ID to retrieve the password from the PS safe with a custom file category value that includes a space.

### EXAMPLE 13
```
Get-CCPCredential -AppID PS -Query 'Safe=PS;Object=PSP-.*' -QueryFormat Regexp -Method POST -URL https://cyberark.yourcompany.com
```

Sends a regular expression query in a POST request body.

## PARAMETERS

### -AppID
Specifies the unique ID of the application issuing the password request.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Safe
Specifies the name of the Safe where the password is stored.

```yaml
Type: String
Parameter Sets: Default
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Folder
Specifies the name of the folder where the password is stored.

```yaml
Type: String
Parameter Sets: Default
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Object
Specifies the name of the password object to retrieve.

```yaml
Type: String
Parameter Sets: Default
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -UserName
Defines search criteria according to the UserName account property.

```yaml
Type: String
Parameter Sets: Default
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Address
Defines search criteria according to the Address account property.

```yaml
Type: String
Parameter Sets: Default
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Database
Defines search criteria according to the Database account property.

```yaml
Type: String
Parameter Sets: Default
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -PolicyID
Defines search criteria according to the PolicyID account property.

```yaml
Type: String
Parameter Sets: Default
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Reason
The reason for retrieving the password.
This reason will be audited in the Credential Provider audit log

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Query
Defines a free query using account properties, including Safe, Folder and Object, separated by semicolons.
For example: Safe=SafeName;Object=ObjectName;CustomProperty=Value
When specified, all other search criteria (Safe/Folder/Object/UserName/Address/PolicyID/Database) are ignored
by the Central Credential Provider, so they cannot be used with this parameter.

```yaml
Type: String
Parameter Sets: Query
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -QueryFormat
Defines the query format, which can optionally use regular expressions.
Possible values are Exact or Regexp.
The Central Credential Provider default is Exact.

```yaml
Type: String
Parameter Sets: Query
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -ConnectionTimeout
The number of seconds that the Central Credential Provider will try to retrieve the password.
The timeout is calculated when the request is sent from the web service to the Vault and returned back
to the web service.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 0
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -FailRequestOnPasswordChange
Return an error if the request is made while a password change process is underway.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Credential
Specify the credentials object if OS User authentication is required for an AAM CCP Application.
Enter a PSCredential object generated by the Get-Credential cmdlet.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -UseDefaultCredentials
Indicates that the the credentials of the current user are used for CCP OS User authentication.
This can't be used with the Credential parameter and may not be supported on all platforms.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Certificate
Specifies the client certificate from a local storethat is used for the AIMWebService request.
Enter a variable that contains a certificate or a command or expression that gets the certificate.
To find a certificate, use Get-PfxCertificate or use the Get-ChildItem cmdlet in the Certificate (Cert:) drive.

```yaml
Type: X509Certificate
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -CertificateThumbPrint
Enter the certificate thumbprint of the certificate.
To get a certificate thumbprint, use the Get-Item or Get-ChildItem command in the PowerShell Cert: drive.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -WebServiceName
The name the CCP WebService is configured under in IIS.
Defaults to AIMWebService

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: AIMWebService
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -URL
The URL for the CCP Host

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -SkipCertificateCheck
Skips certificate validation checks.

Using this parameter is not secure and is not recommended.

This switch is only intended to be used against known hosts using a self-signed certificate for testing purposes.

Use at your own risk.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Method
The HTTP method used for the request.
Defaults to GET.
GET sends request parameters in the URL query string.
POST sends request parameters as a JSON body, and requires Central Credential Provider version 14.2 or later.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: GET
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsCredential
Outputs the username & password as a PSCredential object, instead of the result object.
Cannot be used with AsSecureString.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsSecureString
Outputs the password as a SecureString, instead of the result object.
Cannot be used with AsCredential.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
