<#
.SYNOPSIS
Clone an existing Cloud Sync Group Provisioning Config - Clone-EntraCloudSyncConfig.ps1

.NOTES
Author:         Jakob Schaefer, thinformatics AG
Version:        1.0
Creation Date:  2024/05/06

.DESCRIPTION
This script creates a new Microsoft Entra Cloud Sync Configuration based on an existing configuration. 
It was designed to duplicate a Group Provisioning Job including the configuration.

.PARAMETER ProvisioningAppName
(String; Mandatory) The name of the Service Principal that will be created in Entra ID.
.PARAMETER ManagedDomainName
(String; Mandatory) The name of the target domain which was defined while the provisioning agent was installed in the target Active Directory.
.PARAMETER CloneFrom
(String; Mandatory) Choose between "JSONFile" and "ExistingConfig". 
"ExistingConfig" will create a 1:1 clone from a provisioning job, while "JSONFile" allows you a modification of the job by editing the content of the JSON.
.PARAMETER JSONPath
(String, conditional mandatory) The path to the json file which contains the job schema. Mandatory parameter if CloneFrom equals "JSONFile".
.PARAMETER ServicePrincipalObject
(String, conditional mandatory) The ObjectID of the ServicePrincipal which should be cloned. Mandatory parameter if CloneFrom equals "ExistingConfig".
.PARAMETER SyncJobID
(String, conditional mandatory) The ID of the SyncJob which should be cloned. Mandatory parameter if CloneFrom equals "ExistingConfig".
.PARAMETER StartJob
(Boolean, Optional) If this value is set to true, the created job will be started after the creation was successfull.

.EXAMPLE
.\Clone-CloudSyncConfig.ps1 -ProvisioningAppName "SyncGroupsToDev" -ManagedDomainName "dev.customdomain.com" -CloneFrom "JSONFile" -JSONPath "c:\temp\SchemaDefinition.json"
This Example create a CloudSync Configuration to provide groups into the managed domain dev.customdomain.com. The configuration is defined in the JSON File. The Job will needs to be started afterwards manually.

.\Clone-CloudSyncConfig.ps1 -ProvisioningAppName "TestPlannedChanges" -ManagedDomainName "customdomain.com" -CloneFrom "ExistingConfig" -ServicePrincipalObject "848d49e3-1f18-4127-85d9-9dec18143c7c" -SyncJobID "AAD2ADGroupProvisioning.763aefeaa45b49f4a4a430d135e944f5.e6fcbbe7-674c-41c2-bde1-ef5d078a6a57" -StartJob $true
This Example create a CloudSync Configuration to provide groups into the managed domain customdomain.comm. The configuration will be an 1:1 clone of the existing Job which is defined in the provisioning of the EA "848d49e3-1f18-4127-85d9-9dec18143c7c". The Sync Job will be started automatically
#>
Param (
    [Parameter(Mandatory=$true)][string]$ProvisioningAppName,
    [Parameter(Mandatory=$false)][string]$ManagedDomainName,
    [Parameter(Mandatory=$true)][ValidateSet("JSONFile","ExistingConfig")]$CloneFrom,
    [Parameter(Mandatory=$false)][bool]$StartJob
    
)
DynamicParam {
    if ($CloneFrom -eq "JSONFile") {
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $true
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)

        $dynParam1 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("JSONPath", [string], $paramAttributesCollect)

        $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramDictionary.Add("JSONPath", $dynParam1)
        return $paramDictionary
    }
    if ($CloneFrom -eq "ExistingConfig") {
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $true
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)

        $dynParam1 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("ServicePrincipalObjectID", [string], $paramAttributesCollect)
        $dynParam2 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("SyncJobID", [string], $paramAttributesCollect)

        $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramDictionary.Add("ServicePrincipalObjectID", $dynParam1)
        $paramDictionary.Add("SyncJobID", $dynParam2)
        return $paramDictionary
    }
}
Begin{
    function Get-AppAuthCredentials{
        param (
            [Parameter(Mandatory=$false)][string]$Environment
        )

        # Application (client) ID, tenant ID and secret
        if ($Environment -eq "DEV" -OR !($Environment)) {
            $clientId = (Get-Secret "AppReg-CloudSync-AppID" -Vault Local -AsPlainText) #Insert the AppReg Application ID here. 
            $tenantId = (Get-Secret "AppReg-CloudSync-TenantID" -Vault Local -AsPlainText) #Insert the TenantID here
            $clientSecret = (Get-Secret "AppReg-CloudSync-AppSecret" -Vault Local -AsPlainText) # Insert the ClientSecret Value here
        }

        # Construct URI
        $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

        # Construct Body
        $body = @{
            client_id     = $clientId
            scope         = "https://graph.microsoft.com/.default"
            client_secret = $clientSecret
            grant_type    = "client_credentials"
        }

        # Get OAuth 2.0 Token
        $tokenRequest = Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing

        # Access Token
        return $token = ($tokenRequest.Content | ConvertFrom-Json).access_token
        #$tokenRequestTime=get-date
    }
}Process{
    $graphBaseURL="https://graph.microsoft.com"
    $graphVersion="/beta"
    $ServicePrincipalTemplateID="fb81332f-3eca-4ecf-a939-4278e501d330"
    $SyncJobTemplateID="AAD2ADGroupProvisioning"
    $SyncServicePrincipalAppName=$ProvisioningAppName
    $ManagedDomain=$ManagedDomainName

    #Region Auth

    $token=Get-AppAuthCredentials
    #EndRegion

    #Region create cloneObject
    write-host -ForegroundColor "Gray" -object "INFO: Fetching Sync Job Schema Definition"
    if($CloneFrom -eq "JsonFile"){
        try {
            $CloneObject=get-content -path $PSBoundParameters.JSONPath -Raw    
        }
        catch {
            Write-Error -Message "Cloud not load the json file"
            $Errors[0]
        }     
    }elseif ($CloneFrom -eq "ExistingConfig") {
        $query=@{
            Method="GET"
            URI=$graphBaseURL+$graphVersion+"/servicePrincipals/"+$PSBoundParameters.ServicePrincipalObjectID+"/synchronization/jobs/"+$PSBoundParameters.SyncJobID+"/schema"
            Headers=@{
                Authorization="Bearer $($token)"
            }
            ContentType="application/json"
            ErrorAction="Stop"
        }
        try {
            $CloneObjectrequest=Invoke-RestMethod @query    
        }
        catch {
            Write-Error -Message "Could not fetch the template from the existing job"
            $Errors[0]

        }
        
        $CloneObject=$CloneObjectrequest |convertTo-JSON -Depth 50
    }
    #endRegion

    #region Create a Service Principal Object
    write-host -ForegroundColor Gray -object "INFO: Create ServicePrincipal"
    $query=@{
        Method="POST"
        URI=$graphBaseURL+$graphVersion+"/applicationTemplates/$($ServicePrincipalTemplateID)/instantiate"
        Headers=@{
            Authorization="Bearer $($token)"
        }
        ContentType="application/json"
        ErrorAction="Stop"
        Body=@{
            displayName=$SyncServicePrincipalAppName
        } |ConvertTo-Json
    }
    try{
        $request=Invoke-RestMethod @query
        $ServicePrincipal=$request.servicePrincipal
    }
    catch {
        Write-Error -Message "Could not create the Enterprise Application"
        $Errors[0]
        Read-Host -Prompt "Press any key to exit"
        exit
    }
    #endRegion
    Start-Sleep -Seconds 20

    #Region Create a sync job
    write-host -ForegroundColor Gray -object "INFO: Create a Sync Job"
    $query=@{
        Method="POST"
        URI=$graphBaseURL+$graphVersion+"/servicePrincipals/$($ServicePrincipal.objectId)/synchronization/jobs"
        Headers=@{
            Authorization="Bearer $($token)"
        }
        ContentType="application/json"
        ErrorAction="Stop"
        Body=@{
            templateId=$SyncJobTemplateID
        }|convertTo-JSON
    }
    try{
        $request=Invoke-RestMethod @query
        $SyncJob=$request
    }
    catch {
        Write-Error -Message "Could not Create syncjob"
        $Errors[0]
        Read-Host -Prompt "Press any key to exit"
        exit
    }
    #endRegion
    Start-Sleep -Seconds 5

    #Region Add managed Domain
    write-host -ForegroundColor Gray -object "INFO: Define Managed Domain"
    $query=@{
        Method="PUT"
        URI=$graphBaseURL+$graphVersion+"/servicePrincipals/$($ServicePrincipal.objectId)/synchronization/secrets"
        Headers=@{
            Authorization="Bearer $($token)"
        }
        ContentType="application/json"
        ErrorAction="Stop"
        Body=@{
            value=@(
                @{
                    key="Domain"
                    value=[string]'{"domain":"'+$ManagedDomain+'"}'
                }
            )
        }|convertTo-JSON -Depth 3
    }
    try{
        $request=Invoke-RestMethod @query
    }
    catch {
        Write-Error -Message "Could not add managed domain"
        $errors[0]
        Read-Host -Prompt "Press any key to exit"
        exit
    }
    #endRegion

    #Region update Job Schema
    write-host -ForegroundColor Gray -object "INFO: Set Job Schema"
    $query=@{
        Method="PUT"
        URI=$graphBaseURL+$graphVersion+"/servicePrincipals/$($ServicePrincipal.objectId)/synchronization/jobs/"+$SyncJob.id+"/schema"
        Headers=@{
            Authorization="Bearer $($token)"
        }
        ContentType="application/json"
        ErrorAction="Stop"
        Body=$CloneObject
    }

    try {
        $request=Invoke-RestMethod @query    
    }
    catch {
        Write-Error -Message "Could not update Schema"
        $errors[0]
        Read-Host -Prompt "Press any key to exit"
        exit
    }
    #EndRegion

    #Region Start Sync Job
    if($StartJob){
        write-host -ForegroundColor Gray -object "INFO: Starting Sync Job"
        $query=@{
            Method="POST"
            URI=$graphBaseURL+$graphVersion+"/servicePrincipals/$($ServicePrincipal.objectId)/synchronization/jobs/"+$SyncJob.id+"/start"
            Headers=@{
                Authorization="Bearer $($token)"
            }
            ContentType="application/json"
            ErrorAction="Stop"
        }

        try {
            $request=Invoke-RestMethod @query    
        }
        catch {
            Write-Error -Message "Could not start Job"
            $errors[0]
            Read-Host -Prompt "Press any key to exit"
        exit
        }
    }
    #EndRegion
}