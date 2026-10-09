---
external help file: CredentialRetriever-help.xml
Module Name: CredentialRetriever
online version:
schema: 2.0.0
title: Get-AIMCredential
---

# Get-AIMCredential

## SYNOPSIS
Retrieves password from a local Credential Provider.

## SYNTAX

### Default (Default)
```
Get-AIMCredential -AppID <String> [-Safe <String>] [-Folder <String>] [-Object <String>] [-UserName <String>]
 [-Address <String>] [-Database <String>] [-PolicyID <String>] [-QueryFormat <String>]
 [-RequiredProps <String[]>] [-Reason <String>] [-Port <Int32>] [-Timeout <Int32>]
 [-FailRequestOnPasswordChange] [-AsCredential] [-AsSecureString] [<CommonParameters>]
```

### Query
```
Get-AIMCredential -AppID <String> -Query <String> [-QueryFormat <String>] [-RequiredProps <String[]>]
 [-Reason <String>] [-Port <Int32>] [-Timeout <Int32>] [-FailRequestOnPasswordChange] [-AsCredential]
 [-AsSecureString] [<CommonParameters>]
```

## DESCRIPTION
Sends a query via a local credential provider using the CLIPasswordSDK utility.
Use the Set-AIMConfiguration function to set the path to the CLIPasswordSDK executable.

## EXAMPLES

### EXAMPLE 1
```
Get-AIMCredential -AppID YourApp -Safe YourSafe -Folder Root -UserName YourUser
```

Returns the password found via the query definition:

```
Password  PasswordChangeInProcess
--------  -----------------------
YourPass  false
```

### EXAMPLE 2
```
Get-AIMCredential -AppID YourApp -Safe YourSafe -UserName YourUser -RequiredProps Address,UserName
```

Returns the password, address and username properties:

```
Password   PasswordChangeInProcess UserName  Address
--------   ----------------------- --------  -------
YourPass   false                   YourUser DOMAIN.COM
```

### EXAMPLE 3
```
Get-AIMCredential -AppID YourApp -Query 'Safe=YourSafe;CustomProperty=Value' -RequiredProps UserName
```

Returns the password and username of the account found via a free query.
Properties which do not exist, or have no value, are returned as $null.

### EXAMPLE 4
```
$credential = Get-AIMCredential -AppID YourApp -Safe YourSafe -Object YourObject -AsCredential
```

Outputs the username & password as a PSCredential object.

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

### -Query
Defines a free query using account properties, including Safe, Folder and Object, separated by semicolons.
For example: Safe=SafeName;Object=ObjectName;CustomProperty=Value
Cannot be used with the Safe/Folder/Object/UserName/Address/Database/PolicyID parameters.

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
Whether to search via "exact" or "regexp" terms

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

### -RequiredProps
Defines the names of the account properties you want to be returned in addition to the Password

```yaml
Type: String[]
Parameter Sets: (All)
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

### -Port
The port to communicate with the credential provider

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

### -Timeout
Timeout value in seconds

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

### -AsCredential
Outputs the username & password as a PSCredential object, instead of the result object.
The UserName property is requested automatically.
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
