---
external help file: CredentialRetriever-help.xml
Module Name: CredentialRetriever
online version:
schema: 2.0.0
title: Get-AIMConfiguration
---

# Get-AIMConfiguration

## SYNOPSIS
Gets the configuration used for CLIPasswordSDK operations.

## SYNTAX

```
Get-AIMConfiguration [<CommonParameters>]
```

## DESCRIPTION
Outputs the configuration object used by module functions to provide default values for CLIPasswordSDK operations.
The configuration is imported with the module from $HOME\AIMConfiguration.xml, or set via Set-AIMConfiguration.
If no configuration file exists, and CLIPasswordSDK is installed in its default location, the default location is used.
Outputs nothing if no configuration has been set.

## EXAMPLES

### EXAMPLE 1
```
Get-AIMConfiguration
```

Outputs the current configuration:

```
ClientPath
----------
C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe
```

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
