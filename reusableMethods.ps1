# This module contains reusable functions for interacting with Azure AD,
# Azure Storage, Azure Event Hub, and Azure Cosmos DB.
# IMPORTANT: Hardcoding secrets is NOT recommended for production.

# Example placeholders for common variables.
# In a real scenario, these would be parameters to your functions or loaded securely.
$global:DefaultTenantId = 'YOUR_AZURE_AD_TENANT_ID'
$global:DefaultSubscriptionId = 'YOUR_AZURE_SUBSCRIPTION_ID'
$global:DefaultServicePrincipalClientId = 'YOUR_SERVICE_PRINCIPAL_CLIENT_ID'
$global:DefaultServicePrincipalClientSecret = 'YOUR_SERVICE_PRINCIPAL_CLIENT_SECRET' # Use securely!
$global:DefaultDatabricksWorkspaceUrl = 'YOUR_DATABRICKS_WORKSPACE_URL_E.G._EASTUS2.AZUREDATABRICKS.NET'
$global:DefaultDatabricksAccessToken = 'YOUR_DATABRICKS_PAT' # Use securely!

#region Azure AD Authentication Functions

<#
.SYNOPSIS
    Requests an OAuth 2.0 access token from Azure AD using client credentials flow.
.DESCRIPTION
    This function authenticates a Service Principal against Azure AD to obtain an access token
    for a specified resource. It uses the client ID and client secret of the Service Principal.
.PARAMETER TenantId
    The Azure Active Directory Tenant ID.
.PARAMETER ServicePrincipalClientId
    The Application (client) ID of your Azure AD Application/Service Principal.
.PARAMETER ServicePrincipalClientSecret
    The client secret (password) for your Azure AD Application/Service Principal.
.PARAMETER Resource
    The target audience or resource for which the token is requested (e.g., 'https://management.core.windows.net/', 'Azure Databricks service principal ID').
.RETURNS
    An object containing the access token and other details from the Azure AD token endpoint.
.EXAMPLE
    $Token = Get-AzAdAccessToken -TenantId "your-tenant-id" -ServicePrincipalClientId "your-client-id" -ServicePrincipalClientSecret "your-secret" -Resource "https://management.core.windows.net/"
    $AccessToken = $Token.access_token
#>
function Get-AzAdAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TenantId,

        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalClientId,

        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalClientSecret,

        [Parameter(Mandatory=$true)]
        [string]$Resource
    )

    Write-Verbose "Requesting Azure AD access token for resource: $Resource"
    $Params = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        Body   = @{
            grant_type = 'client_credentials'
            client_id = $ServicePrincipalClientId
            resource = $Resource
            client_secret = $ServicePrincipalClientSecret
        }
        Headers=@{"Content-Type" = "application/x-www-form-urlencoded"}
    }
    try {
        $TokenRequest = Invoke-RestMethod @Params
        Write-Verbose "Successfully obtained Azure AD access token."
        return $TokenRequest
    }
    catch {
        Write-Error "Failed to get Azure AD access token for resource '$Resource'. Error: $($_.Exception.Message)"
        throw $_
    }
}

<#
.SYNOPSIS
    Connects to Azure using Service Principal credentials.
.DESCRIPTION
    This function wraps the Connect-AzAccount cmdlet for Service Principal authentication,
    converting a plain text secret to a secure string internally.
.PARAMETER ServicePrincipalId
    The Application (client) ID of your Azure AD Service Principal.
.PARAMETER ServicePrincipalSecretPlain
    The plain text secret for your Service Principal. This will be converted to a secure string.
.PARAMETER TenantId
    Your Azure Active Directory Tenant ID.
.EXAMPLE
    Connect-AzServicePrincipal -ServicePrincipalId "your-client-id" -ServicePrincipalSecretPlain "your-secret" -TenantId "your-tenant-id"
#>
function Connect-AzServicePrincipal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalSecretPlain,

        [Parameter(Mandatory=$true)]
        [string]$TenantId
    )

    Write-Verbose "Attempting to connect to Azure via Service Principal..."
    try {
        $ServicePrincipalSecret = ConvertTo-SecureString -String $ServicePrincipalSecretPlain -AsPlainText -Force
        $PSCredential = New-Object -TypeName System.Management.Automation.PSCredential($ServicePrincipalId, $ServicePrincipalSecret)
        Connect-AzAccount -ServicePrincipal -Credential $PSCredential -Tenant $TenantId -ErrorAction Stop
        Write-Verbose "Successfully connected to Azure."
    }
    catch {
        Write-Error "Failed to connect to Azure via Service Principal. Error: $($_.Exception.Message)"
        throw $_
    }
}

#endregion

#region Azure Storage Functions

<#
.SYNOPSIS
    Generates an Account-Level Shared Access Signature (SAS) token for an Azure Storage Account.
.DESCRIPTION
    This function connects to Azure using Service Principal credentials and then generates
    a SAS token for the specified storage account with defined permissions and expiry.
.PARAMETER SubscriptionId
    Your Azure Subscription ID.
.PARAMETER ServicePrincipalId
    The Application (client) ID of your Azure AD Service Principal.
.PARAMETER TenantId
    Your Azure Active Directory Tenant ID.
.PARAMETER ServicePrincipalSecretPlain
    The plain text secret for your Service Principal.
.PARAMETER ResourceGroupName
    The name of the Azure resource group containing the storage account.
.PARAMETER StorageAccountName
    The name of your Azure Storage Account.
.PARAMETER SasPermissions
    Permissions for the SAS token (e.g., 'racwdlup').
    r=read, a=add, c=create, w=write, d=delete, l=list, u=update, p=process.
.PARAMETER SasDurationHours
    The duration in hours for which the SAS token will be valid. Default is 24 hours.
.RETURNS
    The generated SAS token string.
.EXAMPLE
    $Sas = New-AzStorageAccountSasToken -SubscriptionId "sub-id" -ServicePrincipalId "sp-id" `
        -TenantId "tenant-id" -ServicePrincipalSecretPlain "sp-secret" `
        -ResourceGroupName "my-rg" -StorageAccountName "mystorage" -SasPermissions "rl" -SasDurationHours 1
    Write-Host "Generated SAS: $Sas"
#>
function New-AzStorageAccountSasToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory=$true)]
        [string]$TenantId,

        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalSecretPlain,

        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$true)]
        [string]$SasPermissions,

        [int]$SasDurationHours = 24
    )

    Write-Verbose "Connecting to Azure for SAS token generation..."
    Connect-AzServicePrincipal -ServicePrincipalId $ServicePrincipalId -ServicePrincipalSecretPlain $ServicePrincipalSecretPlain -TenantId $TenantId
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    Write-Verbose "Retrieving Storage Account '$StorageAccountName' details..."
    try {
        $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
        $StorageKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName)[0]
        $StorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountKey $StorageKey.Value
        Write-Verbose "Storage context created."
    }
    catch {
        Write-Error "Failed to retrieve storage account details or create context. Error: $($_.Exception.Message)"
        throw $_
    }

    Write-Verbose "Generating account-level SAS token..."
    try {
        $SasToken = New-AzStorageAccountSASToken `
            -Context $StorageContext `
            -Service Blob,File,Table,Queue `
            -ResourceType Service,Container,Object `
            -Permission $SasPermissions `
            -StartTime (Get-Date).AddHours(-1) ` # Start 1 hour in the past to account for clock skew
            -ExpiryTime (Get-Date).AddHours($SasDurationHours) `
            -ErrorAction Stop
        Write-Verbose "Successfully generated SAS token."
        return $SasToken
    }
    catch {
        Write-Error "Failed to generate SAS token. Error: $($_.Exception.Message)"
        throw $_
    }
}

#endregion

#region Azure Event Hub Key Management Functions

<#
.SYNOPSIS
    Validates Event Hub connection strings stored in Azure Key Vault against the actual Event Hub keys.
.DESCRIPTION
    This function iterates through predefined Event Hub names and key types, constructs
    expected secret names, retrieves values from Key Vault, fetches corresponding
    connection strings from Event Hub, and compares them.
.PARAMETER SubscriptionId
    The Azure Subscription ID where these resources are located.
.PARAMETER TenantPrefix
    Prefix used in naming conventions (e.g., "NAME").
.PARAMETER Environment
    Environment-specific suffix (e.g., "uat", "dev").
.PARAMETER EventHubNameSuffixes
    Array of suffixes for Event Hub names (e.g., "name1", "name2").
.PARAMETER KeyTypes
    Array of key types (e.g., "listenkey", "sendkey", "managekey").
.PARAMETER KeyVaultNameSuffix
    Suffix for the Key Vault name (e.g., "kv01").
.PARAMETER EventHubNamespaceNameSuffix
    Suffix for the Event Hub Namespace name (e.g., "eventhub").
.PARAMETER ResourceGroupNameSuffix
    Suffix for the Resource Group name (e.g., "sourcing-rg").
.EXAMPLE
    Test-AzEventHubKeyVaultSecrets -SubscriptionId "sub-id" -TenantPrefix "XYZ" -Environment "prod" `
        -EventHubNameSuffixes @("topicA", "topicB") -KeyTypes @("listenkey", "sendkey")
#>
function Test-AzEventHubKeyVaultSecrets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$true)]
        [string]$TenantPrefix,

        [Parameter(Mandatory=$true)]
        [string]$Environment,

        [Parameter(Mandatory=$true)]
        [string[]]$EventHubNameSuffixes,

        [Parameter(Mandatory=$true)]
        [string[]]$KeyTypes,

        [string]$KeyVaultNameSuffix = "kv01",
        [string]$EventHubNamespaceNameSuffix = "eventhub",
        [string]$ResourceGroupNameSuffix = "sourcing-rg"
    )

    $KeyVaultName = $TenantPrefix + $Environment + $KeyVaultNameSuffix
    $EventHubNamespaceName = $TenantPrefix + $Environment + $EventHubNamespaceNameSuffix
    $ResourceGroupName = $TenantPrefix + "_" + $Environment + "_" + $ResourceGroupNameSuffix

    Write-Verbose "Setting Azure context to Subscription ID: $SubscriptionId"
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    Write-Verbose "Retrieving all secrets from Key Vault '$KeyVaultName'..."
    try {
        $AllKeyVaultSecrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName -ErrorAction Stop
        Write-Verbose "Successfully retrieved $($AllKeyVaultSecrets.Count) secrets from Key Vault."
    }
    catch {
        Write-Error "Failed to retrieve secrets from Key Vault '$KeyVaultName'. Error: $($_.Exception.Message)"
        throw $_
    }

    Write-Host "`n--- Starting Event Hub Connection String Validation ---"

    foreach ($ehSuffix in $EventHubNameSuffixes) {
        foreach ($keyType in $KeyTypes) {
            $SecretNameInKeyVault = $TenantPrefix + $ehSuffix + $keyType
            $EventHubFullName = $TenantPrefix + $Environment + $ehSuffix + "eh"
            $AuthorizationRuleName = $TenantPrefix + $Environment + $ehSuffix + $keyType

            Write-Host "`nChecking: Event Hub '$EventHubFullName', Rule '$AuthorizationRuleName', Secret '$SecretNameInKeyVault'"

            $TargetSecret = $AllKeyVaultSecrets | Where-Object { $_.Name -eq $SecretNameInKeyVault }

            if ($TargetSecret) {
                try {
                    $CurrentSecretValue = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameInKeyVault).SecretValueText
                    Write-Verbose "  Secret in Key Vault retrieved."

                    $EventHubKeyDetails = Get-AzEventHubKey -ResourceGroupName $ResourceGroupName -Namespace $EventHubNamespaceName -EventHubName $EventHubFullName -AuthorizationRuleName $AuthorizationRuleName -ErrorAction Stop
                    $EventHubPrimaryConnectionString = $EventHubKeyDetails.PrimaryConnectionString
                    Write-Verbose "  Connection string from Event Hub retrieved."

                    if ($CurrentSecretValue -eq $EventHubPrimaryConnectionString) {
                        Write-Host "$AuthorizationRuleName - OK" -ForegroundColor Green
                    } else {
                        Write-Host "$AuthorizationRuleName - ERROR: Mismatch between Key Vault and Event Hub." -ForegroundColor Red
                    }
                }
                catch {
                    Write-Error "  Failed to process Event Hub key for '$EventHubFullName' rule '$AuthorizationRuleName'. Error: $($_.Exception.Message)" -ErrorAction Continue
                    Write-Host "$AuthorizationRuleName - ERROR: Could not retrieve Event Hub key or compare." -ForegroundColor Yellow
                }
            } else {
                Write-Host "  Secret '$SecretNameInKeyVault' not found in Key Vault. Skipping validation." -ForegroundColor Yellow
            }
        }
    }
    Write-Host "`nEvent Hub Connection String Validation completed."
}

<#
.SYNOPSIS
    Updates Azure Key Vault secrets with Event Hub connection strings.
.DESCRIPTION
    This function retrieves primary connection strings for specified Event Hub authorization rules
    and updates the corresponding secrets in Azure Key Vault.
.PARAMETER SubscriptionId
    The Azure Subscription ID where these resources are located.
.PARAMETER TenantPrefix
    Prefix used in naming conventions (e.g., "NAME").
.PARAMETER Environment
    Environment-specific suffix (e.g., "uat", "dev").
.PARAMETER EventHubNameSuffixes
    Array of suffixes for Event Hub names (e.g., "name1", "name2").
.PARAMETER KeyTypes
    Array of key types (e.g., "listenkey", "sendkey", "managekey").
.PARAMETER KeyVaultNameSuffix
    Suffix for the Key Vault name (e.g., "kv01").
.PARAMETER EventHubNamespaceNameSuffix
    Suffix for the Event Hub Namespace name (e.g., "eventhub").
.PARAMETER ResourceGroupNameSuffix
    Suffix for the Resource Group name (e.g., "RG-NAME").
.PARAMETER ContentType
    (Optional) The content type for Key Vault secrets (e.g., 'text/plain').
.EXAMPLE
    Update-AzKeyVaultSecretsFromEventHub -SubscriptionId "sub-id" -TenantPrefix "XYZ" -Environment "prod" `
        -EventHubNameSuffixes @("topicA", "topicB") -KeyTypes @("listenkey", "sendkey") -ContentType "text/plain"
#>
function Update-AzKeyVaultSecretsFromEventHub {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$true)]
        [string]$TenantPrefix,

        [Parameter(Mandatory=$true)]
        [string]$Environment,

        [Parameter(Mandatory=$true)]
        [string[]]$EventHubNameSuffixes,

        [Parameter(Mandatory=$true)]
        [string[]]$KeyTypes,

        [string]$KeyVaultNameSuffix = "kv01",
        [string]$EventHubNamespaceNameSuffix = "eventhub",
        [string]$ResourceGroupNameSuffix = "RG-NAME", # This specific script uses 'RG-NAME'
        [string]$ContentType = ""
    )

    $KeyVaultName = $TenantPrefix + $Environment + $KeyVaultNameSuffix
    $EventHubNamespaceName = $TenantPrefix + $Environment + $EventHubNamespaceNameSuffix
    $ResourceGroupName = $TenantPrefix + "_" + $Environment + "_" + $ResourceGroupNameSuffix

    Write-Verbose "Setting Azure context to Subscription ID: $SubscriptionId"
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    foreach ($ehSuffix in $EventHubNameSuffixes) {
        foreach ($keyType in $KeyTypes) {
            $SecretNameInKeyVault = $TenantPrefix + $ehSuffix + $keyType
            $EventHubFullName = $TenantPrefix + $Environment + $ehSuffix # The Ev-to-kv.ps1 does not append "eh" here
            $AuthorizationRuleName = $TenantPrefix + $Environment + $ehSuffix + $keyType

            Write-Host "--- Processing Secret: $($SecretNameInKeyVault) ---"

            try {
                $SecretExists = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameInKeyVault -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Secret '$SecretNameInKeyVault' not found in Key Vault '$KeyVaultName' during existence check. Skipping."
                continue
            }

            if ($SecretExists) {
                # $CurrentSecretValue = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameInKeyVault).SecretValueText # For actual logging/comparison, not just check
                Write-Verbose "Current secret value in Key Vault: (retrieved for check)"

                try {
                    $NewConnectionString = (Get-AzEventHubKey -ResourceGroupName $ResourceGroupName -Namespace $EventHubNamespaceName -EventHubName $EventHubFullName -AuthorizationRuleName $AuthorizationRuleName -ErrorAction Stop).PrimaryConnectionString
                    Write-Verbose "New connection string from Event Hub retrieved."
                }
                catch {
                    Write-Error "Failed to retrieve connection string for Event Hub '$EventHubFullName' rule '$AuthorizationRuleName'. Error: $($_.Exception.Message)"
                    continue
                }

                try {
                    Update-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameInKeyVault -SecretValue $NewConnectionString -ContentType $ContentType | Out-Null
                    Write-Host "Successfully updated secret '$SecretNameInKeyVault' in Key Vault '$KeyVaultName'."
                }
                catch {
                    Write-Error "Failed to update secret '$SecretNameInKeyVault' in Key Vault '$KeyVaultName'. Error: $($_.Exception.Message)"
                }
            } else {
                 Write-Warning "Secret '$SecretNameInKeyVault' does not exist in Key Vault. No update performed."
            }
        }
    }
    Write-Host "`nEvent Hub Key Vault Update completed."
}

#endregion

#region Azure Cosmos DB Functions

<#
.SYNOPSIS
    Lists connection strings and keys for an Azure Cosmos DB account.
.DESCRIPTION
    This function connects to Azure and then retrieves and displays
    the connection strings and account keys for a specified Cosmos DB account.
.PARAMETER SubscriptionId
    Your Azure Subscription ID.
.PARAMETER ResourceGroupName
    The name of the Azure resource group where the Cosmos DB account resides.
.PARAMETER CosmosAccountName
    The name of your Azure Cosmos DB account.
.EXAMPLE
    Get-AzCosmosDbConnectionInfo -SubscriptionId "sub-id" -ResourceGroupName "my-rg" -CosmosAccountName "mycosmos"
#>
function Get-AzCosmosDbConnectionInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$CosmosAccountName
    )

    Write-Verbose "Setting Azure context to Subscription ID: $SubscriptionId"
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    Write-Host "`n--- Azure Cosmos DB Connection Strings ---"
    try {
        Invoke-AzResourceAction -Action listConnectionStrings `
            -ResourceType "Microsoft.DocumentDb/databaseAccounts" -ApiVersion "2015-04-08" `
            -ResourceGroupName $ResourceGroupName -Name $CosmosAccountName -ErrorAction Stop | Select-Object *
        Write-Verbose "Successfully listed Cosmos DB connection strings."
    }
    catch {
        Write-Error "Failed to list Cosmos DB connection strings. Error: $($_.Exception.Message)"
        throw $_
    }

    Write-Host "`n--- Azure Cosmos DB Account Keys ---"
    try {
        Invoke-AzResourceAction -Action listKeys `
            -ResourceType "Microsoft.DocumentDb/databaseAccounts" -ApiVersion "2015-04-08" `
            -ResourceGroupName $ResourceGroupName -Name $CosmosAccountName -ErrorAction Stop | Select-Object *
        Write-Verbose "Successfully listed Cosmos DB account keys."
    }
    catch {
        Write-Error "Failed to list Cosmos DB account keys. Error: $($_.Exception.Message)"
        throw $_
    }
}

#endregion