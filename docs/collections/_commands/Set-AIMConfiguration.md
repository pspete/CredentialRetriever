---
external help file: CredentialRetriever-help.xml
Module Name: CredentialRetriever
online version:
schema: 2.0.0
title: Set-AIMConfiguration
---

# Set-AIMConfiguration

## SYNOPSIS
Sets a variable in the script scope which holds default values for CLIPasswordSDK operations.
Must be run prior to other module functions if path to CLIPasswordSDK has not been previously set,
and CLIPasswordSDK is not installed in its default location.

## SYNTAX

```
Set-AIMConfiguration [-ClientPath] <String> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Sets properties on an object which is used as the value of a variable in the script scope.
The created variable can be queried and used by other module functions to provide default values.
Creates a file in the logged on users home folder named AIMConfiguration.xml.
This file contains the variable
used by the module, and will be imported with the module into the module's scope.

## EXAMPLES

### EXAMPLE 1
```
Set-AIMConfiguration -ClientPath D:\Path\To\CLIPasswordSDK.exe
```

Sets default path to CLIPasswordSDK to D:\Path\To\CLIPasswordSDK.exe.
This is accessed via the variable property $Script:AIM.ClientPath
Creates $HOME\AIMConfiguration.xml file to hold values for persistence.

## PARAMETERS

### -ClientPath
The path to the CLIPasswordSDK utility

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
