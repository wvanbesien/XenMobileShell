#
# Version: 1.2.3
# Revision 2016.10.19: improved the new-xmenrollment function: added parameters of notification templates as well as all other options. Also included error checking to provide a more useful error message in case incorrect information is provided to the function. 
# Revision 2016.10.21: adjusted the confirmation on new-xmenrollment to ensure "YesToAll" actually works when pipelining. Corrected typo in notifyNow parameter name.
# Revision 1.1.4 2016.11.24: corrected example in new-xmenrollment
# Revision 1.2.0 2016.11.25: added the use of a PScredential object with the new-xmsession command.   
# Revision 1.2.1 2022-02-20: Code beautification and consistency.
# Revision 1.2.2 2022-02-21: Modified New-XMSession with static timeout parameters. This is a quick fix/workaround for making it work when the account used is RBAC limited, and not able to read server properties.
# Revision 1.2.3 2022-02-21: Added Revoke-XMEnrollment, Remove-XMEnrollment, Switch-XMDeviceAppLock, Get-XMApp



# The request object is used by many of the functions. Do not delete.  
$Request = [PSCustomObject]@{
    Method = $null
    Entity = $null
    Uri    = $null
    Header = $null
    Body   = $null
}


# Supporting functions. These functions are called by other functions in the module.
function Invoke-XMRequest {
    param(
        [Parameter(mandatory)]
        $Request
    )
    try {
        $Result = Invoke-RestMethod -Method $Request.Method -Headers $Request.Header -Uri $Request.Uri -Body (ConvertTo-Json -Depth 8 $Request.Body) -ErrorAction Stop
        Write-Verbose -Message ($Result | ConvertTo-Json)
        return $Result
    }
    catch {
        Write-Host 'Submission of the request to the server failed.' -ForegroundColor Red
        $ErrorMessage = $_.Exception.Message
        Write-Host $ErrorMessage -ForegroundColor Red
    }
}

function Search-XMObject {
    #this function submits a search request to the server and returns the results.
    #a token is required, server, as well as the url which specifies the API this goes to. 
    #the url is the portion after https://<server>:4443/xenmobile/api/v1 beginning with slash. 
    param(
        [Parameter()]
        $Criteria = $null,

        [Parameter(Mandatory = $true)]
        $Entity,

        [Parameter()]
        $FilterIds = '[]',

        [Parameter()]
        $ResultSetSize = 999
    )
    process { 
        $Request.Method = 'POST'
        $Request.Entity = $Entity
        $Request.Uri    = "$($XMSServerApiUrl)$($Entity)"
        $Request.Header = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.Body   = @{
            start          = '0';
            limit          = [int]$ResultSetSize;
            sortOrder      = 'ASC';
            sortColumn     = 'ID';
            search         = $Criteria;
            enableCount    = 'true';
            filterIds      = $FilterIds
        }
    }
    end {
        return Invoke-XMRequest -Request $Request
    }
}

function Remove-XMObject {
    <#
    This function is used by DELETE type requests. 
    #>
    param(
        [Parameter(Mandatory = $true)]
        $Entity,

        [Parameter()]
        [string]$Target
    )
    process { 
        $Request.Method = 'DELETE'
        $Request.Entity = $Entity
        $Request.Url    = "$($XMSServerApiUrl)$($Entity)"
        $Request.Header = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.Body = $Target
    }
    end {
        return Invoke-XMRequest -Request $Request
    }
}

function postObject {
    #function used by POST Type requests. 
    param(
        [Parameter(Mandatory = $true)]
        $Entity,

        [Parameter(Mandatory = $true)]
        $Target
    )
    process { 
        Write-Verbose -Message 'Submitting POST request.'
        $Request.Method = 'POST'
        $Request.Entity = $Entity
        $Request.Url    = "$($XMSServerApiUrl)$($Entity)"
        $Request.Header = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.Body   = $Target
    }
    end {
        return Invoke-XMRequest -Request $Request
    }
}

function putObject {
    #function used by PUT Type requests. 
    param(
        [Parameter(Mandatory = $true)]
        $Entity,

        [Parameter(Mandatory = $true)]
        $Target
    )
    process { 
        Write-Verbose -Message 'Submitting PUT request.'
        $Request.Method = 'PUT'
        $Request.Entity = $Entity
        $Request.Url    = "$($XMSServerApiUrl)$($Entity)"
        $Request.Header = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.Body   = $Target
    }
    end {
        return Invoke-XMRequest -Request $Request
    }
}

function getObject {
    #function used to submit GET type requests to the server. 
    param(
        [Parameter(Mandatory = $true)]
        $Entity
    )
    process {
        $Request.Method = 'GET'
        $Request.Entity = $Entity
        $Request.Url    = "$($XMSServerApiUrl)$($Entity)"
        $Request.Header = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.Body   = $null
    }
    end {
        return Invoke-XMRequest -Request $Request
    }
}

function checkSession {
    #this functions checks the state of the session timeout. And will update in case the timeout type is inactivity. 
    if ($XMSessionExpiry -gt (Get-Date)) {
        Write-Verbose -Message "Session is still active."
        #if we are using an inactivity timer (rather than static timeout), update the expiry time.
        if ($XMSessionUseInactivity -eq $true) {
            $TimeToExpiry = (($XMSessionInactivityTimer) * 60) - 30
            Set-Variable -Name 'XMSessionExpiry' -Value (Get-Date).AddSeconds($TimeToExpiry) -Scope global
            Write-Verbose -Message 'Session expiry extended by ' + $TimeToExpiry + ' sec. New expiry time is: ' + $XMSessionExpiry
        }
    }
    else {
        Write-Host 'Session has expired. Please create a new XMSession using the New-XMSession command.' -ForegroundColor Yellow
        break 
    }
}

# Main functions. 
function New-XMSession {
<#
.SYNOPSIS
Starts a XMS session. Run this before running any other commands. 

.DESCRIPTION
This command will login to the server and get an authentication token. This command will set several session variables that are used by all the other commands.
This command must be run before any of the other commands. 
This command can use either a username or password pair entered as variables, or you can use a PScredential object. To create a PScredential object,
run the get-credential command and store the output in a variable. 
If both a user, password and credential are provided, the credential will take precedence. 

.PARAMETER -User
Specify the user with required permissions to access the XenMobile API. 

.PARAMETER -Password
Specify the password for the API user. 

.PARAMETER -Credential
Specify a PScredential object. This replaces the user and password parameters and can be used when stronger security is desired. 

.PARAMETER -Server
Specify the server you will connect to. This should be a FQDN, not IP address. PowerShell is picky with regards to connectivity to encrypted paths. 
Therefore, the servername must match the certificate, be valid and trusted by system you are running these commands. 

.PARAMETER -Port
You can specify an alternative port to connect to the server. This is optional and will default to 4443 if not specified.

.PARAMETER -TimeoutType
If specified, this value, along with the -Timeout value, is used instead of querying the server for the values. This is useful if access to server properties is restricted using RBAC.
Must be set to the same value as the Server Property "xms.publicapi.timeout.type". Can be "STATIC_TIMEOUT" or "INACTIVITY_TIMEOUT".

.PARAMETER -Timeout
If specified, this value, along with the -TimeoutType value, is used instead of querying the server for the values. This is useful if access to server properties is restricted using RBAC.
Must be set to the same value as the Server Property associated with the timeout type; ie. "xms.publicapi.static.timeout" if STATIC_TIMEOUT and "xms.publicapi.inactivity.timeout" if INACTIVITY_TIMEOUT. 

.EXAMPLE
New-XMSession -User "admin" -Password "password" -Server "mdm.citrix.com"

.EXAMPLE
New-XMSession -User "admin" -Password "password" -Server "mdm.citrix.com" -Port "4443"

.EXAMPLE
$Credential = Get-Credential
New-XMSession -Credential $Credential -Server mdm.citrix.com

.EXAMPLE
New-XMSession -Credential (Get-Credential) -Server mdm.citrix.com

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            ValueFromPipeLine)]
        [string]$User,

        [Parameter(ValueFromPipelineByPropertyName,
            ValueFromPipeLine)]
        [string]$Password,

        [Parameter(valueFromPipelineByPropertyName, 
            ValueFromPipeLine)]
        $Credential = $null,

        [Parameter(ValueFromPipelineByPropertyName, 
            ValueFromPipeLine)]
        [string]$Server,

        [Parameter(ValueFromPipeLIneByPropertyName)]
        [string]$Port = '4443',

        [Parameter(ParameterSetName = 'Timeout', 
            Mandatory = $false)]
        [ValidateSet('STATIC_TIMEOUT',
            'INACTIVITY_TIMEOUT')]
        [string]$TimeoutType,

        [Parameter(ParameterSetName = 'Timeout', 
            Mandatory = $true)]
        [int]$Timeout
    )
    process {
        Set-Variable -Name 'XMSServer' -Value $Server -Scope global

        Write-Verbose -Message 'Setting the server port.'
        Set-Variable -Name 'XMSServerPort' -Value '4443' -Scope global
        if ($Port.Length -gt 0 -and $Port -ne '4443') {
            Set-Variable -Name 'XMSServerPort' -Value $Port -Scope global
        }
        Set-Variable -Name 'XMSServerBaseUrl' -Value "http://$($XMSServer):$($XMSServerPort)" -Scope global
        Set-Variable -Name 'XMSServerApiPath' -Value '/xenmobile/api/v1' -Scope global
        Set-Variable -Name 'XMSServerApiUrl'  -Value "$($XMSServerBaseUrl)$($XMSServerApiPath)" -Scope global

        Write-Verbose -Message 'Creating an authentication token, and setting the XMSAuthToken and XMSServer variables'
        #if a credential object is used, convert the secure password to a clear text string to submit to the server. 
        if ($null -ne $Credential) {
            $User = $Credential.username
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.password)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
        try {
            #Set-Variable -Name 'XMSAuthToken' -Value (Get-XMAuthToken -User $User -Password $Password -Server $Server -Port $XMSServerPort) -Scope global -ErrorAction Stop
            Set-Variable -Name 'XMSAuthToken' -Value (Get-XMAuthToken -Credential $Credential -Api $XMSServerApiUrl) -Scope global -ErrorAction Stop
        }
        catch {
            Write-host 'Authentication failed.' -ForegroundColor Yellow
            break
        }
        #clear the password variable, to reduce chance of compromise
        #$Password = $null
        Clear-Variable -Name 'Password'
        #create variables to establish the session timeout. 
        Set-Variable -Name 'XMSessionStart' -Value (Get-Date) -Scope global
        Write-Verbose -Message "Setting session start to: $($XMSessionStart)"
        #check if the timeout type is set to inactivity or static and set the global value accordingly. 
        #if a static timeout is used, the session expiry can be set based on the static timeout. 
        if (!$TimeoutType) {
            Write-Verbose -Message "TimeoutType isn't defined. Will attempt to read timeout from server properties."
            Write-Verbose -Message 'Checking the type of timeout the server uses:'
            if ((Get-XMServerProperty -Name 'xms.publicapi.timeout.type' -SkipCheck $true).Value -eq 'INACTIVITY_TIMEOUT') {
                Write-Verbose -Message 'Server is using an inactivity timeout for the API session. This is preferred.'
                Set-Variable -Name 'XMSessionUseInactivity' -Value $true -Scope global
                Set-Variable -Name 'XMSessionInactivityTimer' -Value ([System.Convert]::ToInt32((Get-XMServerProperty -Name 'xms.publicapi.inactivity.timeout' -SkipCheck $true).Value)) -Scope global
                #due to network conditions and other issues, the actual timeout of the server may be quicker than here. So, we will reduce the timeout by 30 seconds.
                $TimeToExpiry = (($XMSessionInactivityTimer) * 60) - 30 
                Set-Variable -Name 'XMSessionExpiry' -Value (Get-Date).AddSeconds($TimeToExpiry) -Scope global
                Write-Verbose -Message "The session expiry time is set to: $($XMSessionExpiry)"
            }
            else {
                Write-Verbose 'Server is using a static timeout. The use of an inactivity timeout is recommended.'
                Set-Variable -Name 'XMSessionUseInactivity' -Value $false -Scope global
                #get the static timeout and deduct 30 seconds. 
                $TimeToExpiry = ([System.Convert]::ToInt32((Get-XMServerProperty -Name 'xms.publicapi.static.timeout' -SkipCheck $true).Value)) * 60 - 30
                Write-Verbose -Message "Expiry in seconds: $($TimeToExpiry)"
                Set-Variable -Name 'XMSessionExpiry' -Value (Get-Date).AddSeconds($TimeToExpiry) -Scope global
                Write-Verbose -Message "The session expiry time is set to: $($XMSessionExpiry)"
            }
        }
        else {
            Write-Verbose -Message "TimeoutType is defined: $($TimeoutType)"
            If ($TimeoutType -eq "INACTIVITY_TIMEOUT") {
                Write-Verbose "   Server is using an inactivity timeout for the API session. This is preferred."
                Set-Variable -Name "XMSessionUseInactivity" -Value $true -Scope Global
                Set-Variable -Name "XMSessionInactivityTimer" -Value $Timeout -Scope Global
                #due to network conditions and other issues, the actual timeout of the server may be quicker than here. So, we will reduce the timeout by 30 seconds.
                $TimeToExpiry = (($XMSessionInactivityTimer) * 60) - 30
                Set-Variable -Name "XMSessionExpiry" -Value (get-Date).AddSeconds($TimeToExpiry) -Scope Global
                Write-verbose "The session expiry time is set to: $($XMSessionExpiry)"
            }
            Else {
                Write-Verbose "   Server is using a static timeout. The use of an inactivity timeout is recommended."
                Set-Variable -Name "XMSessionUseInactivity" -Value $false -Scope Global
                #get the static timeout and deduct 30 seconds. 
                $TimeToExpiry = $Timeout * 60 - 30
                Write-Verbose "Expiry in seconds: $($TimeToExpiry)"
                Set-Variable -Name "XMSessionExpiry" -Value (Get-Date).AddSeconds($TimeToExpiry) -Scope Global
                Write-Verbose "The session expiry time is set to: $($XMSessionExpiry)"
            }
        }
        Write-Verbose -Message 'A session has been started.'
        Write-Host "Authentication successfull. Token: $($XMSAuthToken)`nSession will expire at: $($XMSessionExpiry)" -ForegroundColor Yellow
    }
}

function Get-XMAuthToken {
<#
.SYNOPSIS
This function will authenticate against the server and will provide you with an authentication token.
Most cmdlets in this module require a token in order to authenticate against the server. 

.DESCRIPTION
This cmdlet will authenticate against the server and provide you with a token. It requires a username, password and server address. 
The cmdlet assumes you are connecting to port 4443. All parameters can be piped into this command.  

.PARAMETER Api
Specify the API address. Example: https://mdm.citrix.com:4443/xenmobile/api/v1

.PARAMETER -Credential
Specify a PScredential object. This replaces the user and password parameters and can be used when stronger security is desired. 

.PARAMETER User
Specify the username. This username must have API access. 

.PARAMETER Password
Specify the password to use. 

.PARAMETER Server
Specify the servername. IP addresses cannot be used. Do no specify a port number. Example: mdm.citrix.com

.PARAMETER Port
Specify the port to connect to. This defaults to 4443. Only specify this parameter is you are using a non-standard port. 

.EXAMPLE
$Token = Get-XMAuthToken -User "admin" -Password "citrix123" -Server "mdm.citrix.com

.EXAMPLE
$Token = Get-XMAuthToken -Api "https://mdm.citrix.com:4443/xenmobile/api/v1" -Credential $StoredPSCredential

#> 
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            ValueFromPipeLine)]
        [string]$Api,

        [Parameter(valueFromPipelineByPropertyName, 
            ValueFromPipeLine)]
        $Credential = $null,

        [Parameter(ValueFromPipelineByPropertyName, 
            ValueFromPipeLine)]
        [string]$User,

        [Parameter(ValueFromPipelineByPropertyName, 
            ValueFromPipeLine)]
        [string]$Password,

        [Parameter(ValueFromPipelineByPropertyName, 
            ValueFromPipeLine)]
        [string]$Server,

        [Parameter(ValueFromPipeLIneByPropertyName)]
        [string]$Port = '4443'
    )
    $Entity = '/authentication/login'
    #$URL    = "https://$($Server):$($Port)/xenmobile/api/v1/authentication/login"
    $URL    = "$($Api)$($Entity)"

    #if a credential object is used, convert the secure password to a clear text string to submit to the server. 
    if ($null -ne $Credential) {
        $User = $Credential.UserName
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    }

    $Header = @{
        'Content-Type' = 'application/json'
    }
    $Body = @{
        login          = $User;
        password       = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    Write-Verbose -Message 'Submitting authentication request.'
    $Token = Invoke-RestMethod -Uri $URL -Method POST -Body (ConvertTo-Json $Body) -Headers $Header
    Write-Verbose -Message "Received token: $($Token)"
    return [string]$Token.auth_token
}

# Enrollment functions
function New-XMEnrollment {
<#
.SYNOPSIS
This command will create an enrollment for the specified user.

.DESCRIPTION
Use this command to create enrollments. You can pipe parameters into this command from another command. 
The command currently does not process notifications. It will return an object with details of the enrollment including the URL and PIN code (called secret).  

.PARAMETER User
The user parameter specifies the target user.
This parameter is required. This is either the UPN or sAMAccountName depending on what you are using in your environment. 

.PARAMETER OS
The OS parameter specifies the type of operating system. Options are iOS, SHTP.
For android, use SHTP. This parameter is required. 

.PARAMETER PhoneNumber
This is the phone number notifications will be sent to. The parameter is optional but without it no SMS notifications are sent. 

.PARAMETER Carrier
Specify the carrier to use. This is optional and only required in case multiple cariers and SMS gateway have been configured. 

.PARAMETER DeviceBindingType
You can specify either SERIALNUMBER, IMEI or UDID as the device binding paramater. This defaults to SERIALNUMBER. 
This parameter is only useful if you also specify the deviceBindingData. 

.PARAMETER DeviceBindingData
By specifying devicebindingdata you can link an enrollment invitation to a specific device. Use the deviceBindingType to specify what you will use, 
and specify the value here. For example, to bind to a serial number set the deviceBindingType to SERIALNUMBER and provide the serialnumber as the value of deviceBindingData. 

.PARAMETER Ownership
This parameter specifies the ownership of the device. Values are either CORPORATE or BYOD or NO_BINDING.
Default value is NO_BINDING. 

.PARAMETER Mode
This parameter specifes the type of enrollment mode you are using. Make sure the specified mode is enable on the server otherwise, an error will be thrown. 
Default mode is classic. The select enrollment type must be enabled on the server. 
Options are: 
classic: username and password (default)
high_security: generates an invitation URL, one time PIN and requires used to provide username, PIN and password.
invitation: generates an invitation URL
invitation_pin: generates and invitation and one time PIN
invitation_pwd: generates an inivation and will request the user's password during enrollment 
username_pin: generates a one time PIN and requires users to login with that pin and the username
two_factor: generates an invitation url, a one time PIN and requires the user to login with, password and PIN. 

.PARAMETER AgentTemplate
Specify the template to use when sending a notification to the user to download Secure Hub. The default is blank. 
This value is case sensitive. To find out the correct name, create an enrollment invitation in the XMS GUI and view the available options for the notification template. 

.PARAMETER InvitationTemplate
Specify the template to use when sending a notification to the user to with the enrollment URL. The default is blank. 
This value is case sensitive. To find out the correct name, create an enrollment invitation in the XMS GUI and view the available options for the notification template. 

.PARAMETER PinTemplate
Specify the template to use when sending a notification for the one time PIN to the user. The default is blank. 
This value is case sensitive. To find out the correct name, create an enrollment invitation in the XMS GUI and view the available options for the notification template. 

.PARAMETER ConfirmationTemplate
Specify the template to use when sending a notification to the user at completion of the enrollment. The default is blank. 
This value is case sensitive. To find out the correct name, create an enrollment invitation in the XMS GUI and view the available options for the notification template. 

.PARAMETER NotifyNow
Specify if you want to send notifications to the user. Value is either "true" or "false" (default.) 

.EXAMPLE
New-XMEnrollment -User "ward@citrix.com" -OS "iOS" -Ownership "BYOD" -Mode "invitation_url"

.EXAMPLE
Import-Csv -Path users.csv | New-XMEnrollment -OS iOS -Ownership BYOD

This will read a CSV file and create an enrolment for each of the entries.

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipeLineByPropertyName, 
            ValueFromPipeLine, 
            Mandatory = $true)]
        [string]$User,

        [Parameter(ValueFromPipeLineByPropertyName, 
            ValueFromPipeLine, 
            Mandatory = $true)]
        [ValidateSet('iOS', 
            'SHTP')]
        [string]$OS,

        [Parameter(valueFromPipelineByPropertyName)]
        $PhoneNumber = $null,

        [parameter(valueFromPipelineByPropertyName)]
        $Carrier = $null,

        [Parameter(valueFromPipelineByPropertyName)]
        [ValidateSet('SERIALNUMBER', 
            'UDID', 
            'IMEI')]
        $DeviceBindingType = 'SERIALNUMBER',

        [Parameter(valueFromPipelineByPropertyName)]
        $DeviceBindingData = $null,

        [Parameter(ValueFromPipeLineByPropertyName, 
            ValueFromPipeLine)]
        [ValidateSet('CORPORATE', 
            'BYOD', 
            'NO_BINDING')]
        [string]$Ownership = 'NO_BINDING',

        [Parameter(valueFromPipeLineByPropertyName)]
        [ValidateSet('classic', 
            'high_security', 
            'invitation', 
            'invitation_pin', 
            'invitation_pwd', 
            'username_pin', 
            'two_factor')]
        $Mode = 'classic',

        [Parameter(ValueFromPipeLineByPropertyName)]
        $AgentTemplate = $null,

        [Parameter(ValueFromPipeLineByPropertyName)]
        $InvitationTemplate = $null,

        [Parameter(ValueFromPipeLineByPropertyName)]
        $PinTemplate = $null,

        [Parameter(ValueFromPipeLineByPropertyName)]
        $ConfirmationTemplate = $null,

        [Parameter(ValueFromPipeLineByPropertyName)]
        [ValidateSet('true', 
            'false')]
        $NotifyNow = 'false',

        [switch]$Force
    )
    begin {
        #check session state
        checkSession
        $RejectAll  = $false
        $ConfirmAll = $false
    }
    process {
        if ($Force -or $PSCmdlet.ShouldContinue('Do you want to continue?', "Creating enrollment for '$($User)'", [ref]$ConfirmAll, [ref]$RejectAll)) {
            $Body = @{
                platform = $OS
                deviceOwnership = $Ownership
                mode = @{
                    name = $Mode
                }
                userName = $User
                notificationTemplateCategories = @(
                    @{
                        notificationTemplate = @{
                            name = $AgentTemplate
                        }
                        category = 'ENROLLMENT_AGENT'
                    }
                    @{
                        notificationTemplate = @{
                            name = $InvitationTemplate
                        }
                        category = 'ENROLLMENT_URL'
                    }
                    @{
                        notificationTemplate = @{
                            name = $PinTemplate
                        }
                        category = 'ENROLLMENT_PIN'
                    }
                    @{
                        notificationTemplate = @{
                            name = $ConfirmationTemplate
                        }
                        category = 'ENROLLMENT_CONFIRMATION'
                    }
                )
                phoneNumber = $PhoneNumber
                carrier = $Carrier
                deviceBindingType = $DeviceBindingType
                deviceBindingData = $DeviceBindingData
                notifyNow = $NotifyNow
            }
            Write-Verbose -Message 'Created enrollment request object for submission to server.'
            $EnrollmentResult = postObject -Entity '/enrollment' -Target $Body -ErrorAction Stop
            Write-Verbose -Message "Enrollment invitation submitted."
            # the next portion of the function will download additional information about the enrollment request
            # this is pointless if the invitation was not correctly created due to an error with the request. 
            # Hence, we only run this, if there is an actual invitation in the enrollmentResult value. 
            if ($null -ne $EnrollmentResult) {
                Write-Verbose -Message 'An enrollment invication was created. Searching for additional details.'
                $SearchResult = Search-XMObject -Entity '/enrollment/filter' -Criteria $EnrollmentResult.token
                $Enrollment = $SearchResult.enrollmentFilterResponse.enrollmentList.enrollments
                $Enrollment | Add-Member -NotePropertyName url -NotePropertyValue $EnrollmentResult.url
                $Enrollment | Add-Member -NotePropertyName message -NotePropertyValue $EnrollmentResult.message
                $Enrollment | Add-Member -NotePropertyName AgentNotificationTemplateName -NotePropertyValue $SearchResult.enrollmentFilterResponse.enrollmentList.enrollments.notificationTemplateCategories.notificationTemplate.name
                return $Enrollment 
            } 
            else {
                Write-Host "The server was unable to create an enrollment invitation for '$($User)'. Common causes are connectivity issues, as well as errors in the information supplied such as username, template names etc. Ensure all values in the request are correct." -ForegroundColor Yellow
            }
        }
    }
}

function Revoke-XMEnrollment {
<#
.SYNOPSIS
Revoke Enrollment Token

.DESCRIPTION
NEEDS TEXT

.PARAMETER Token
NEEDS TEXT

.EXAMPLE
NEEDS TEXT

.EXAMPLE
NEEDS TEXT

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipeLineByPropertyName, 
            ValueFromPipeLine, 
            Mandatory = $true)]
        [string[]]$Token
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Body = "[`"$($Token -join '","')`"]"
        postObject -Entity '/enrollment/revoke' -Target $Body -ErrorAction Stop
    }
}

function Remove-XMEnrollment {
<#
.SYNOPSIS
Remove Enrollment Token

.DESCRIPTION
NEEDS TEXT

.PARAMETER Token
NEEDS TEXT

.EXAMPLE
NEEDS TEXT

.EXAMPLE
NEEDS TEXT

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipeLineByPropertyName, 
            ValueFromPipeLine, 
            Mandatory = $true)]
        [string[]]$Token
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Body = "[`"$($Token -join '","')`"]"
        Remove-XMObject -Entity '/enrollment/revoke' -Target $Body -ErrorAction Stop
    }
}

function Get-XMEnrollment {
<#
.SYNOPSIS
Searches for enrollment invitations. 

.DESCRIPTION
Searches for enrollment invitations. Without parameters, it will return all invitations. You can get all enrollment for a given user by specifing a the criteria parameter. 

.PARAMETER user
Specify the user if you wnat enrollments for a particular user account. If you specify a UPN or username, all enrollments for the username will be returned. 

.PARAMETER filter
This parameter allows you to filter results based on other criteria. The syntax is "[filter]". For example, to see all BYOD device enrolments, use "[enrollment.ownership.byod]". 
Multiple values can be specified, separated by a comma. Following are some of the filters that can be used (not an exhaustive list). 
enrollment.ownership.byod
enrollment.ownership.corporate
enrollment.ownership.unknown
enrollment.invitationMode#classic@_fn_@invitation
enrollment.invitationMode#invitation@_fn_@invitation
enrollment.invitationStatus.ios
enrollment.invitationPlatform.android
enrollment.invitationStatus.redeemed
enrollment.invitationStatus.expired
enrollment.invitationStatus.pending
enrollment.invitationStatus.failed

.PARAMETER ResultSetSize
By default, only the first 1000 entries will be returned. You can override this value to get more (or less) results. 

.EXAMPLE
Get-XMEnrollment 

.EXAMPLE
Get-XMEnrollment -User "ward@citrix.com"

.EXAMPLE
Get-XMEnrollment -Filter "[enrollment.invitationStatus.expired]"

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$User,

        [Parameter()]
        [string]$Filter = '[]',

        [Parameter()]
        [int]$ResultSetSize = 999
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Searchresult = Search-XMObject  -Entity '/enrollment/filter' -Criteria $User -FilterIds $Filter -ResultSetSize $ResultSetSize
        $ResultSet =  $Searchresult.enrollmentFilterResponse.enrollmentList.enrollments
        $ResultSet | Add-Member -NotePropertyName AgentNotificationTemplateName -NotePropertyValue $Searchresult.enrollmentFilterResponse.enrollmentList.enrollments.notificationTemplateCategories.notificationTemplate.name
        return $ResultSet
    }
}

# Devices functions.
function Get-XMDevice {
<#
.SYNOPSIS
Basic search function to find devices

.DESCRIPTION
Search function to find devices. If you specify the user parameter, you get all devices for a particular user. 
The devices are returned as an array of objects, each object representing a single device. 

.PARAMETER Criteria
Specify a search criteria. If you specify a UPN or username, all enrollments for the username will be returned. 
It also possible to provide other values such as serial number to find devices. Effectively, anything that will work in the 'search' field in the GUI will work here as well.    

.PARAMETER Filter
Specify a filter to further reduce the amount of data returned.  The syntax is "[filter]". For example, to see all MDM device enrolments, use "[device.mode.mdm.managed,device.mode.mdm.unmanaged]".
Here are some of the filters: 
device.mode.enterprise.managed
device.mode.enterprise.unmanaged
device.mode.mdm.managed
device.mode.mdm.unmanaged
device.mode.mam.managed
device.mode.mam.unmanaged 
device.status.jailbroken
device.status.as.gateway.blocked
device.status.out.of.compliance
device.status.samsung.knox.not.attested
device.status.enrollment.program.registred (for Apple DEP)
group#/group/ActiveDirectory/citrix/com/XM-Users@_fn_@normal   (for users in AD group XM-users in the citrix.com AD)
device.platform.ios
device.platform.android
device.platform#10.0.1@_fn_@device.platform.ios.version   (for iOS device, version 10.0.1)
device.ownership.byod
device.ownership.corporate
device.ownership.unknown
device.inactive.time.30.days
device.inactive.time.more.than.30.days
device.inactive.time.8.hours

.PARAMETER ResultSetSize
By default only the first 1000 records are returned. Specify the resultsetsize to get more records returned. 

.EXAMPLE
Get-XMDevice -Criteria "ward@citrix.com" -Filter "[device.mode.enterprise.managed]"

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [string]$Criteria,

        [Parameter()]
        [string]$Filter = '[]',

        [Parameter()]
        [int]$ResultSetSize = 999
    )
    begin {
        #check session state
        checkSession
    } 
    process { 
        $Results = Search-XMObject -Entity '/device/filter' -Criteria $Criteria -FilterIds $Filter -ResultSetSize $ResultSetSize
        return $Results.filteredDevicesDataList 
    }
}

function Remove-XMDevice {
<#
.SYNOPSIS
Removes a device from the XMS server and database. 

.DESCRIPTION
Removes a devices from the XMS server. Requires the id of the device. 

.PARAMETER Id
The id parameter identifies the device. You can get the id by searching for the correct device using get-device. 

.EXAMPLE
Remove-XMDevice -Id "21" 

.EXAMPLE
Get-XMDevice -User "ward@citrix.com | ForEach-Object { Remove-XMDevice -Id $PSItem.id }

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipeLineByPropertyName, 
            Mandatory = $true)]
        [string[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Id)) {
            Remove-XMObject -Entity '/device' -Target $Id
        }
    }
}

function Update-XMDevice {
<#
.SYNOPSIS
Sends a deploy command to the selected device. A deploy will trigger a device to check for updated policies. 

.DESCRIPTION
Sends a deploy command to the selected device. 

.PARAMETER Id
This parameter specifies the id of the device to target. This can be pipelined from a search command. 

.EXAMPLE
Update-XMDevice -Id "24" 

.EXAMPLE
Get-XMDevice -User "aford@corp.vanbesien.com" | Update-XMDevice

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [int[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        write-verbose -Message "This will send an update to device $($Id)"
        postObject -Entity '/device/refresh' -Target $Id
    }
}

function Invoke-XMDeviceWipe {
<#
.SYNOPSIS
Sends a device wipe command to the selected device.

.DESCRIPTION
Sends a device wipe command. this is similar to a factory reset

.PARAMETER id
This parameter specifies the id of the device to wipe. This can be pipelined from a search command. 

.EXAMPLE
Invoke-XMDeviceWipe -Id "24" 

.EXAMPLE
Get-XMDevice -User "ward@citrix.com" | Invoke-XMDeviceWipe

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [int[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Id)) {
            postObject -Entity '/device/wipe' -Target $Id
        }
    }
}

function Invoke-XMDeviceSelectiveWipe {
<#
.SYNOPSIS
Sends a selective device wipe command to the selected device.

.DESCRIPTION
Sends a selective device wipe command. This removes all policies and applications installed by the server but leaves the rest of the device alone.

.PARAMETER Id
This parameter specifies the id of the device to wipe. This can be pipelined from a search command. 

.EXAMPLE
Invoke-XMDeviceSelectiveWipe -Id "24"

.EXAMPLE
Get-XMDevice -User "ward@citrix.com" | Invoke-XMDeviceSelectiveWipe

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [int[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($id)) {
            postObject -Entity '/device/selwipe' -Target $Id
        }
    }
}

function Get-XMDeviceDeliveryGroups {
<#
.SYNOPSIS
Displays the delivery groups for a given device specified by id.

.DESCRIPTION
This command lets you find all the delivery groups that apply to a particular device. You search based the ID of the device.
To find the device id, use get-XMDevice.

.PARAMETER Id
Specify the ID of the device. Use get-XMDevice to find the id of each device.  

.EXAMPLE
Get-XMDeviceDeliveryGroups -Id "8"

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/device/$($Id)/deliverygroups"
        return $Result.deliveryGroups
    }
}

function Get-XMDeviceActions {
<#
.SYNOPSIS
Displays the smart actions applied to a given device specified by id.

.DESCRIPTION
This command lets you find all the smart actions available that apply to a particular device. You search based the ID of the device.
To find the device id, use get-XMDevice.

.PARAMETER Id
Specify the ID of the device. Use get-XMDevice to find the id of each device.  

.EXAMPLE
Get-XMDeviceActions -Id "8"

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/device/$($Id)/actions"
        return $Result
    }
}

function Get-XMDeviceApps { 
<#
.SYNOPSIS
Displays all XenMobile store apps installed on a device, whether or ot the app was installed from the XenMobile Store 

.DESCRIPTION
This command will display all apps from the XenMobile Store installed on a device. This includes apps that were installed by the user themselves without selecting it from the XenMobile store. Thus is includes apps that are NOT managed but listed as available to the device.
For apps that are NOT managed, an inventory policy is required to detect them. 

This command is useful to find out which of the XenMobile store apps are installed (whether or not they are managed or installed from the XenMobile store).  

.PARAMETER Id
Specify the ID of the device. Use get-XMDevice to find the id of each device.  

.EXAMPLE
Get-XMDeviceApps -Id "8" 

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/device/$($Id)/apps"
        return $Result.applications
    }
}

function Get-XMDeviceManagedApps { 
<#
.SYNOPSIS
Displays the XMS managed apps for a given device specified by id. Managed Apps include those apps installed from the XenMobile Store.  

.DESCRIPTION
This command displays all managed applications on a particular device. Managed applications are those applications that have been installed from the XenMobile Store. 
If a public store app is installed through policy on a device where the app is already installed, the user is given the option to have XMS manage the app. In that case, the app will be included in the output of this command. 
If the user chooses not to let XMS manage the App, it will not be included in the output of this command. the get-XMDeviceApps will still list that app. 

.PARAMETER Id
Specify the ID of the device. Use get-XMDevice to find the id of each device.  

.EXAMPLE
Get-XMDeviceManagedApps -Id "8" 

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/device/$($Id)/managedswinventory"
        return $Result.softwareinventory
    }
}

function Get-XMDeviceSoftwareInventory { 
<#
.SYNOPSIS
Displays the application inventory of a particular device.   

.DESCRIPTION
This command will list all installed applications as far as the server knows. Apps managed by the server are always included, other apps (such as personal apps) are only included if an inventory policy is deployed to the device. 

.PARAMETER Id
Specify the ID of the device. Use get-XMDevice to find the id of each device.  

.EXAMPLE
Get-XMDeviceSoftwareInventory -Id "8" 

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/device/$($Id)/softwareinventory"
        return $Result.softwareInventories
    }
}

function Get-XMDeviceInfo {
<#
.SYNOPSIS
Displays the properties of a particular device.   

.DESCRIPTION
This command will output all properties, settings, configurations, certificates etc of a given device. This is typically an extensive list that may need to be further filtered down.
This command aggregates a lot of information available through other commands as well. 

.PARAMETER Id
Specify the ID of the device. Use get-XMDevice to find the id of each device.  

.EXAMPLE
Get-XMDeviceInfo -Id "8"

#>  
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/device/$($Id)"
        return $Result.device
    }
}

function Get-XMDevicePolicy {
<#
.SYNOPSIS
Displays the policies applies to a particular device.   

.DESCRIPTION
This command will list the policies applied to a particular device. 
 
.PARAMETER Id
Specify the ID of the device. Use Get-XMDevice to find the id of each device.  

.EXAMPLE
Get-XMDevicePolicy -Id "8"

#>  
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/device/$($Id)/policies"
        return $Result.policies
    }
}

function Get-XMDeviceProperty {
<#
.SYNOPSIS
Gets the properties for the device. 

.DESCRIPTION
Gets the properties for the device. This is different from the get-xmdeviceinfo command which includes the properties but also returns all other information about a device. This command returns a subset of that data. 

.PARAMETER Id
Specify the ID of the device for which you want to get the properties. 

.EXAMPLE
Get-XMDeviceProperty -Id "8"

.EXAMPLE
Get-XMDevice -Name "Ward@citrix.com" | Get-XMDeviceProperties

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/device/properties/$($Id)"
        return $Result.devicePropertiesList.deviceProperties.devicePropertyParameters
    }
}

function Set-XMDeviceProperty {
<#
.SYNOPSIS
adds, changes a properties for a device. 

.DESCRIPTION
add or change properties for a device. Specify the device by ID, and property by name. To get the name of the property, search using get-xmdeviceproperties or get-xmdeviceknownproperties. 
WARNING, avoid making changes to properties that are discovered by the existing processes. Use to to configure/set new properties. Most properties should not be changed this way.

One property that is often changed is the ownership of a device. That property is called "CORPORATE_OWNED". Value '0' means BYOD, '1' means corporate and for unknown the property doesn't exist. 

.PARAMETER Id
Specify the ID of the device for which you want to get the properties. 

.PARAMETER Name
Specify the name of the property. Such as "CORPORATE_OWNED" 

.PARAMETER Value
Specify the value of the property. 

.EXAMPLE
Set-XMDeviceProperty -Id "8" -Name "CORPORATE_OWNED" -Value "1"

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact='High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Value
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Id)) {
            $Body     = @{
                name  = $Name;
                value = $Value
            }
            postObject -Entity "/device/property/$($Id)" -Target $Body
        }
    }
}

function Remove-XMDeviceProperty { 
<#
.SYNOPSIS
Deletes a properties for a device. 

.DESCRIPTION
Delete a property from a device. 
WARNING: be careful when using this function. There is no safety check to ensure you don't accidentally delete things you shouldn't.

.PARAMETER Id
Specify the ID of the device for which you want to get the properties. 

.PARAMETER Name
Specify the name of the property. Such as "CORPORATE_OWNED" 

.EXAMPLE
Remove-XMDeviceProperty -Id "8" -Name "CORPORATE_OWNED"

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Name
    )
    begin {
        # Check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Id)) {
            #The property is deleted based on the id of the property which is unique. 
            #Thus, we first look for the property
            $Property = Get-XMDeviceProperty -Id $Id | Where-Object {
                $PSItem.name -eq $Name
            }
            Write-Verbose -Message "Property id for property: $($Name) is $($Property.id)"
            Remove-XMObject -Entity "/device/property/$($Property.id)" -Target $null
        }
    }
}

function Switch-XMDeviceAppLock {
<#
.SYNOPSIS
Sends app lock/unlock command.

.DESCRIPTION
The appLock api is a toggle api. Subsequent requests lock/unlock in a toggle fashion.

.PARAMETER Id
This parameter specifies the id of the device(s) to switch/toggle the App Lock for.

.EXAMPLE
Switch-XMDeviceAppLock -Id "8"

.EXAMPLE
Switch-XMDeviceAppLock -Id "8", "11"

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [int[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Id)) {
            postObject -Entity '/device/appLock' -Target $Id
        }
    }
}

# Application functions.
function Get-XMApp { #TODO
<#
.SYNOPSIS
Get Applications by Filter

.DESCRIPTION
NEEDS TEXT

.PARAMETER Search
NEEDS TEXT

.PARAMETER FilterByType
NEEDS TEXT

.PARAMETER FilterByPlatform
NEEDS TEXT

.PARAMETER Start
NEEDS TEXT

.PARAMETER Limit
NEEDS TEXT

.PARAMETER Sort
NEEDS TEXT

.PARAMETER EnableCount
NEEDS TEXT

.EXAMPLE
NEEDS TEXT

.EXAMPLE
NEEDS TEXT

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipeLineByPropertyName, 
            ValueFromPipeLine)]
        [string]$Search,

        [Parameter(ValueFromPipeLine)]
        [ValidateSet('mdx', 
            'enterprise', 
            'store', 
            'weblink', 
            'saas', 
            'all')]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string]$FilterByType = 'all',

        [Parameter(ValueFromPipeLine)]
        [ValidateSet('iOS', 
            'Android', 
            'AndroidKNOX', 
            'WinPhone', 
            'Windows8', 
            'WindowsCE', 
            'All')]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string]$FilterByPlatform = 'All',

        [Parameter()]
        [int]$Start = 0,

        [Parameter()]
        [int]$Limit = 10,

        [Parameter()]
        [ValidateSet('ASC', 
            'DESC')]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string]$Sort = 'ASC',

        [Parameter()]
        [switch]$EnableCount
    )
    begin {
        checkSession
        $Body = @{
            enableCount = $EnableCount.ToString()
            start = $Start
            limit = $Limit
        }
    }
    process {
        if ($Search) {
            $Body.Add('search', $Search)
        }
        $Filter = @()
        if ($FilterbyType -and $FilterByType -ne 'All') {
            $Filter += "[application.type.$($FilterByType.ToLower())]"
        }
        if ($FilterByPlatform -and $FilterByPlatform -ne 'All') {
            $Filter += "[application.platform.$($FilterByPlatform.ToLower())]"
        }
        if ($Filter.Length -gt 0) {
            $Body.Add('filterIds', $($Filter -join ','))
        }
        $Response = postObject -Entity '/application/filter' -Target $Body
        return $Response.applicationListData.appList
    }
}

function Get-XMAppDetails { #TODO
<#
.SYNOPSIS
NEEDS TEXT

.DESCRIPTION
NEEDS TEXT

.PARAMETER Id
NEEDS TEXT

.PARAMETER Platform
NEEDS TEXT

.EXAMPLE
NEEDS TEXT
{
    "status": 0,
    "message": "Success",
    "container": {
        "id": 4,
        "name": "Microsoft Word",
        "description": "app description",
        "createdOn": null,
        "lastUpdated": null,
        "disabled": false,
        "nbSuccess": 0,
        "nbFailure": 0,
        "nbPending": 0,
        "schedule": {
            "enableDeployment": true,
            "deploySchedule": "LATER",
            "deployScheduleCondition": "EVERYTIME",
            "deployDate": "3/14/2018",
            "deployTime": "17:44",
            "deployInBackground": false
        },
        "permitAsRequired": true,
        "iconData": "/9j/4AAQSkZJRgABAQEA...",
        "appType": "App Store App",
        "categories": [ "Default" ],
        "roles": [ "AllUsers" ],
        "workflow": null,
        "vppAccount": null,
        "iphone": {
            "name": "MobileApp6",
            "displayName": "Microsoft Office Word",
            "description": "Microsoft Office Word app from app store",
            "paid": false,
            "removeWithMdm": true,
            "preventBackup": true,
            "changeManagementState": true,
            "associateToDevice": false,
            "canAssociateToDevice": false,
            "canDissociateVPP": true,
            "appVersion": "2.3",
            "store": {
                "rating": {
                    "rating": 0,
                    "reviewerCount": 0
                },
                "screenshots": [],
                "faqs": [ {
                    "question": "Question?",
                    "answer": "Answer",
                    "displayOrder": 1 
                } ],
                "storeSettings": {
                    "rate": false,
                    "review": false
                }
            },
            "avppParams": null,
            "avppTokenParams": null,
            "rules": null,
            "appType": "mobile_ios",
            "uuid": "8b0f08d0-52ef-453f-8d99-d4c1a3e973d7",
            "id": 9,
            "vppAccount": -1,
            "iconPath": "/9j/4AAQSkZJRgABAQE..",
            "iconUrl": "http://is3.mzstatic.com/image/thumb/Purple127/v4/e1/35/d2/e135d280-67cf-7f63-ca16-3c5f970a1d70/source/60x60bb.jpg",
            "bundleId": "com.microsoft.Office.Word",
            "appId": "586447913",
            "appKey": null,
            "storeUrl": "https://itunes.apple.com/us/app/microsoft-word/id586447913?mt=8&uo=4",
            "b2B": false
        },
        "ipad": null,
        "android": {
            "name": "MobileApp5",
            "displayName": "Microsoft Office Word","description": "Microsoft Word", "paid": false, "removeWithMdm": true, "preventBackup": true, "changeManagementState": false, "associateToDevice": false, "canAssociateToDevice": false, "canDissociateVPP": true, "appVersion": "16.0.8326.2034", "store": { "rating": { "rating": 0, "reviewerCount": 0 }, "screenshots": [], "faqs": [],
    "storeSettings": { "rate": true, "review": true } }, "avppParams": null, "avppTokenParams": null, "rules": null, "appType": "mobile_android", "uuid": "40c514dd-1a8a-4e48-96ed-512b658fb333", "id": 8, "vppAccount": -1, "iconPath": "iVBORw0KGgoAAAANSU...", "iconUrl": "https://lh3.ggpht.com/j6aNgkpGRXp9PEinADFoSkyfup46-6Rb83bS41lfQC_Tc2qg96zQ_aqZcyiaV3M-Ai4", "bundleId": "com.microsoft.office.word", "appId": null, "appKey": null, "storeUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.word", "b2B": false }, "windows": null, "android_work": null, "windows_phone": null }
}
#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [ValidateSet('mdx', 
            'enterprise', 
            'store', 
            'weblink', 
            'saas')]
        [string]$Type,

        [Parameter(ValueFromPipeLineByPropertyName, 
            ValueFromPipeLine)]
        [int]$Id,

        [string]$Connector
    )
    begin {
        checkSession
        $Method = 'GET'
    }
    process {
        switch ($Type.ToLower()) {
            'mdx' {
                $Entity = "/application/mobile/$($Id)"
                break
            }
            'enterprise' {
                $Entity = "/application/mobile/$($Id)"
                break
            }
            'weblink' {
                $Entity = "/application/weblink/$($Id)"
                break
            }
            'saas' {
                if ($Connector) {
                    $Entity = "/application/saas/connector/$($Connector)"
                }
                else {
                    $Entity = "/application/saas/$($Id)"
                }
                break
            }
            'store' {
                $Entity = "/application/store/$($Id)"
                break
            }
        }
        $Uri = "$($XMSBaseUri)$($Entity)"
        Write-Verbose -Message "Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers"
        $Response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers
        return $Response.container
    }
}

function Update-XMPublicStoreApp { #TODO
<#
.SYNOPSIS


.DESCRIPTION


.PARAMETER Id


.PARAMETER Platform


.EXAMPLE

{
    "removeWithMdm": false,
    "preventBackup": false,
    "changeManagementState": false,
    "displayName": "Microsoft Word - App Store",
    "description": "description",
    "faqs": [ {
        "question": "Question?",
        "answer": "Answer"
    } ],
    "storeSettings": {
        "rate": false,
        "review": false
    },
    "checkForUpdate": true
}

Valid plaforms are: iphone, ipad, android, android_work, windows, windows_phone.
#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Id,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [ValidateSet('iphone', 
            'ipad', 
            'android', 
            'android_work', 
            'windows', 
            'windows_phone')]
        [string]$Platform,

        [switch]$CheckForUpdate
    )
    begin {
        Get-XMSession
        $Method = 'PUT'
    }
    process {
        $Entity = "/application/store/$($Id)/platform/$($Platform)"
        $Uri = "$($XMSBaseUri)$($Entity)"
        if ($PSCmdlet.ShouldProcess($Id)) {
            $Payload = @{
                checkForUpdate = $CheckForUpdate.ToString()
            }
            $JSON = $Payload | ConvertTo-Json
            Write-Verbose -Message "Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $JSON"
            $Response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $JSON
            return $Response.container
        }
    }
}

# ServerProperty functions.
function Get-XMServerProperty {
<#
.SYNOPSIS
Queries the server for server properties. 

.DESCRIPTION
Queries the server for server properties. Without any parameters, this command will return all properties. 

.PARAMETER name
Specify the parameter for which you want to get the values. The parameter name typically looks like xms.publicapi.static.timeout. 

.EXAMPLE
Get-XMServerProperty  #returns all properties

.EXAMPLE
Get-XMServerProperty -Name "xms.publicapi.static.timeout"

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [string]$Name = $null,

        [Parameter(dontshow)]
        [bool]$SkipCheck = $false
    )
    begin {
        #The Get-XMServerProperty function is called during the XMSession setup in order to specify the timeout values.
        #If you check the session during this time, the check will fail.
        #Using the hidden skipcheck parameter, we can override the check during the initial xmsession setup.
        if (!$SkipCheck) {
            Write-verbose -Message 'Checking the session state'
            #Check session state.
            checkSession
        }
        else {
            write-verbose -Message 'The session check is skipped.'
        }
    }
    process {
        Write-Verbose -Message 'Creating the Get-XMServerProperty request.'
        $Request.Entity = ''
        $Request.Method    = 'POST'
        $Request.Uri       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1/serverproperties/filter"
        $Request.header    = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.body      = @{
            start          = '0';
            limit          = '1000';
            orderBy        = 'name';
            sortOrder      = 'desc';
            searchStr      = $Name;
        }
        Write-Verbose -Message 'Submitting the Get-XMServerProperty request to the server.'
        $Results = Invoke-XMRequest -Request $Request
        return $Results.allEwProperties
    }
}

function Set-XMServerProperty {
<#
.SYNOPSIS
Sets the server for server properties. 

.DESCRIPTION
Changes the value of an existing server property.  

.PARAMETER Name
Specify the name of the property to change. The parameter name typically looks like xms.publicapi.static.timeout. 

.PARAMETER Value
Specify the new value of the property. 

.PARAMETER DisplayName
Specify a new display name. This parameter is optional. If not specified the existing display name is used. 

.PARAMETER Description
Specify a new description. This parameter is optional. If not specified the existing description is used. 

.EXAMPLE
Set-XMServerProperty -Name "xms.publicapi.static.timeout" -Value "45"

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Value,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DisplayName = $null,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description = $null
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Name)) {
            #if no displayname or description is provided, search for the existing values and use those. 
            if (!$DisplayName) {
                $DisplayName = (Get-XMServerProperty -Name $Name).displayName
            }
            if (!$Description) {
                $Description = (Get-XMServerProperty -Name $Name).description
            }
            $Request.Method    = 'PUT'
            $Request.Url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1/serverproperties" 
            $Request.Header    = @{
                'auth_token'   = $XMSAuthToken;
                'Content-Type' = 'application/json'
            }
            $Request.Body      = @{
                name           = $Name;
                value          = $Value;
                displayName    = $DisplayName;
                description    = $Description;
            }
            Invoke-XMRequest -Request $Request
        } 
    }
}

function New-XMserverProperty {
<#
.SYNOPSIS
Create a new server property.  

.DESCRIPTION
Creates a new server property. All parameters are required.   

.PARAMETER Name
Specify the name of the property. The parameter name typically looks like xms.publicapi.static.timeout. 

.PARAMETER Value
Specify the value of the property. The value set during creation becomes the default value. 

.PARAMETER DisplayName
Specify a the display name.  

.PARAMETER Description
Specify a the description. 

.EXAMPLE
New-XMServerProperty -Name "xms.something.something" -Value "indeed" -DisplayName "something" -Description "a something property."

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Value,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Description
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Name)) {
            $Request.Method    = 'POST'
            $Request.Url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1/serverproperties" 
            $Request.Header    = @{
                'auth_token'   = $XMSAuthToken;
                'Content-Type' = 'application/json'
            }
            $Request.Body      = @{
                name           = $Name;
                value          = $Value;
                displayName    = $DisplayName;
                description    = $Description;
            }
            Invoke-XMRequest -Request $Request
        }
    }
}

function Remove-XMserverProperty {
<#
.SYNOPSIS
Removes a server property. 

.DESCRIPTION
Removes a server property. This command accepts pipeline input.  

.PARAMETER Name
Specify the name of the propery to remove. This parameter is mandatory. 

.EXAMPLE
Remove-XMServerProperty -Name "xms.something.something"

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string[]]$Name
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Name)) {
            Write-Verbose "Deleting $($Name)"
            Remove-XMObject -Entity "/serverproperties" -Target $Name
        }
    }
}

# ClientProperty functions.
function Get-XMClientProperty {
<#
.SYNOPSIS
Queries the server for client properties. 

.DESCRIPTION
Queries the server for server properties. Without any parameters, this command will return all properties. 

.PARAMETER Key
Specify the parameter for which you want to get the values. The parameter key typically looks like ENABLE_PASSWORD_CACHING. 

.EXAMPLE
Get-XMClientProperty  #returns all properties

.EXAMPLE
Get-XMClientProperty -Key "ENABLE_PASSWORD_CACHING"

#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Key = $null
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Entity "/clientproperties/$($Key)"
        return $Result.allClientProperties
    }
}

function New-XMClientProperty {
<#
.SYNOPSIS
Creates a new client property. 

.DESCRIPTION
Creates a new client property. All parameters are required. Use this to create/add new properties. To change an existing property, use set-xmclientproperty

.PARAMETER Displayname
Specify name of the property. 

.PARAMETER Description
Specify the description of the property.

.PARAMETER Key
Specify the key. 

.PARAMETER Value
Specify the value of the property. The value set when the property is created is used as the default value. 

.EXAMPLE
New-XMClientProperty -Displayname "Enable touch ID" -Description "Enables touch ID" -Key "ENABLE_TOUCH_ID_AUTH" -Value "true"

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Displayname,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Key,

        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string]$Value
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Key)) {
            $Body           = @{
                displayName = $Displayname;
                description = $Description;
                key         = $Key;
                value       = $Value
            }
            Write-Verbose -Message "Creating: displayName: $($Displayname), description: $($Description), key: $($Key), value: $($Value)"
            postObject -Entity '/clientproperties' -Target $Body
        }
    }
}

function Set-XMClientProperty {
<#
.SYNOPSIS
Edit a client property. 

.DESCRIPTION
Edit a client property. Specify the key. All other properties are optional and will unchanged unless otherwise specified. 

.PARAMETER Displayname
Specify name of the property. 

.PARAMETER Description
Specify the description of the property.

.PARAMETER Key
Specify the key. 

.PARAMETER Value
Specify the value of the property. 

.EXAMPLE
Set-XMClientProperty -Key "ENABLE_TOUCH_ID_AUTH" -Value "false"

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Displayname = $null,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description = $null,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
        [string]$Key,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Value = $null
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Key)) {
            if (!$Displayname) {
                $Displayname = (Get-XMClientProperty -Key $Key).displayName
            }
            if (!$Description) {
                $Description = (Get-XMClientProperty -Key $Key).description
            }
            if (!$Value) {
                $Value = (Get-XMClientProperty -Key $Key).value
            }
            $Body = @{
                displayName = $Displayname;
                description = $Description;
                value       = $Value
            }
            Write-Verbose -Message "Changing: displayName: $($Displayname), description: $($Description), key: $($Key), value: $($Value)"
            putObject -Entity "/clientproperties/$($Key)" -Target $Body
        }
    }
}

function Remove-XMClientProperty {
<#
.SYNOPSIS
Removes a client property. 

.DESCRIPTION
Removes a client property. This command accepts pipeline input.  

.PARAMETER Key
Specify the key of the propery to remove. This parameter is mandatory. 

.EXAMPLE
Remove-XMClientProperty -Key "TEST_PROPERTY"

#>
    [CmdletBinding(SupportsShouldProcess = $true, 
        ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            Mandatory = $true)]
        [string[]]$Key
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Key)) {
            Write-Verbose -Message "Deleting: $($Key)"
            Remove-XMObject -Entity "/clientproperties/$($Key)" -Target $null
        }
    }
}

Export-ModuleMember -Function Get-XMApp
Export-ModuleMember -Function Get-XMClientProperty
Export-ModuleMember -Function Get-XMDevice
Export-ModuleMember -Function Get-XMDeviceActions
Export-ModuleMember -Function Get-XMDeviceApps
Export-ModuleMember -Function Get-XMDeviceDeliveryGroups
Export-ModuleMember -Function Get-XMDeviceInfo
Export-ModuleMember -Function Get-XMDeviceManagedApps
Export-ModuleMember -Function Get-XMDevicePolicy
Export-ModuleMember -Function Get-XMDeviceProperty
Export-ModuleMember -Function Get-XMDeviceSoftwareInventory
Export-ModuleMember -Function Get-XMEnrollment
Export-ModuleMember -Function Get-XMServerProperty
Export-ModuleMember -Function Invoke-XMDeviceSelectiveWipe
Export-ModuleMember -Function Invoke-XMDeviceWipe
Export-ModuleMember -Function New-XMClientProperty
Export-ModuleMember -Function New-XMEnrollment
Export-ModuleMember -Function New-XMserverproperty
Export-ModuleMember -Function New-XMSession
Export-ModuleMember -Function Remove-XMClientProperty
Export-ModuleMember -Function Remove-XMDevice
Export-ModuleMember -Function Remove-XMDeviceProperty
Export-ModuleMember -Function Remove-XMEnrollment
Export-ModuleMember -Function Remove-XMServerProperty
Export-ModuleMember -Function Revoke-XMEnrollment
Export-ModuleMember -Function Set-XMClientProperty
Export-ModuleMember -Function Set-XMDeviceProperty
Export-ModuleMember -Function Set-XMServerProperty
Export-ModuleMember -Function Switch-XMDeviceAppLock
Export-ModuleMember -Function Update-XMDevice
