
This repo coniant Power Shell scripts used at my home lab.

# Azure Utility Functions

* **`Get-AzAdAccessToken`**
    * **Description**: Requests an OAuth 2.0 access token from Azure AD using the client credentials flow for a Service Principal.

* **`Connect-AzServicePrincipal`**
    * **Description**: Connects to Azure using provided Service Principal credentials.

* **`New-AzStorageAccountSasToken`**
    * **Description**: Generates an Account-Level Shared Access Signature (SAS) token for an Azure Storage Account with specified permissions and expiry.

* **`Test-AzEventHubKeyVaultSecrets`**
    * **Description**: Validates Event Hub connection strings stored in Azure Key Vault against the actual Event Hub keys.

* **`Update-AzKeyVaultSecretsFromEventHub`**
    * **Description**: Updates Azure Key Vault secrets with primary connection strings retrieved from Event Hub authorization rules.

* **`Get-AzCosmosDbConnectionInfo`**
    * **Description**: Lists connection strings and keys for a specified Azure Cosmos DB account.