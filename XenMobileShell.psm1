#
# Version: 1.2.1
# Revision 2016.10.19: improved the new-xmenrollment function: added parameters of notification templates as well as all other options. Also included error checking to provide a more useful error message in case incorrect information is provided to the function. 
# Revision 2016.10.21: adjusted the confirmation on new-xmenrollment to ensure "YesToAll" actually works when pipelining. Corrected typo in notifyNow parameter name.
# Revision 1.1.4 2016.11.24: corrected example in new-xmenrollment
# Revision 1.2.0 2016.11.25: added the use of a PScredential object with the new-xmsession command.   
# Revision 1.2.1 2022-02-20: Code beautification and consistency.


#the request object is used by many of the functions. Do not delete.  
$Request = [pscustomobject]@{
    method = $null
    url    = $null
    header = $null
    body   = $null
}


#supporting functions. These functions are called by other functions in the module.

#$XMSServerProtocol = 'https://'
#$XMSServerHost = 'mdm.citrix.com'
#$XMSServerPort = 4443
#$XMSServerApiPath = '/xenmobile/api/v1'

#function submitToServer {
function Invoke-XMRequest {
    param(
        [Parameter(mandatory)]
        $Request
    )
    try {
        $Result = Invoke-RestMethod -Uri $Request.url -Method $Request.method -Body (ConvertTo-Json -Depth 8 $Request.body) -Headers $Request.header -ErrorAction Stop
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

        [Parameter(mandatory)]
        $Url,

        [Parameter()]
        $FilterIds = '[]',

        [Parameter()]
        $ResultSetSize = 999
    )
    process { 
        $Request.method    = 'POST'
        $Request.url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1$($Url)"
        $Request.header    = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.body      = @{
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
        [Parameter(mandatory)]
        $Url,

        [Parameter()]
        [string[]]$Target
    )
    process { 
        $Request.method    = 'DELETE'
        $Request.url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1$($Url)"
        $Request.header    = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.body      = $Target
    }
    end {
        return Invoke-XMRequest -Request $Request
    }
}

function postObject {
    #function used by POST Type requests. 
    param(
        [Parameter(mandatory)]
        $Url,

        [Parameter(mandatory)]
        $Target
    )
    process { 
        Write-Verbose -Message 'Submitting POST request.'
        $Request.method    = 'POST'
        $Request.url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1$($Url)"
        $Request.header    = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.body      = $Target
    }
    end {
        return Invoke-XMRequest -Request $Request
    }
}

function putObject {
    #function used by PUT Type requests. 
    param(
        [Parameter(mandatory)]
        $Url,

        [Parameter(mandatory)]
        $Target
    )
    process { 
        Write-Verbose -Message 'Submitting PUT request.'
        $Request.method    = 'PUT'
        $Request.url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1$($Url)"
        $Request.header    = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.body      = $Target
    }
    end {
        return Invoke-XMRequest -Request $Request
    }
}

function getObject {
    #function used to submit GET type requests to the server. 
    param(
        [Parameter(mandatory)]
        $Url
    )
    process {
        $Request.method    = 'GET'
        $Request.url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1$($Url)"
        $Request.header    = @{
            'auth_token'   = $XMSAuthToken;
            'Content-Type' = 'application/json'
        }
        $Request.body      = $null
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

function Join-Url {
    param(
        [Parameter(mandatory)]
        [string]$Hostname,

        [Parameter(mandatory)]
        [string[]] $Parts,

        [Parameter()]
        [ValidateSet('http', 
            'https')]
        [string]$Scheme = 'https',

        [Parameter()]
        [int]$Port = 4443,

        [Parameter()]
        [string] $Seperator = '/'
    )
    $BaseUrl = "$($Scheme)://$($Hostname):$($Port)"
    return (,$BaseUrl+$Parts | Where-Object { $PSItem } | ForEach-Object { $PSItem.Trim('/') } | Where-Object { $PSItem } ) -join '/'
}

#main functions. 

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
        [string]$Port = '4443'
    )
    process {
        #Set-Variable -Name 'XMSServer' -Value $Server -Scope global
        $XMSServerScheme = 'https'
        $XMSServerHostname = $Server

        Write-Verbose -Message 'Setting the server port.'
        #Set-Variable -Name 'XMSServerPort' -Value '4443' -Scope global
        $XMSServerPort = 4443
        if ($Port.Length -gt 0 -and $Port -ne '4443') {
            #Set-Variable -Name 'XMSServerPort' -Value $Port -Scope global
            $XMSServerPort = $Port
        }
        #Set-Variable -Name 'XMSServerApiPath' -Value '/xenmobile/api/v1' -Scope global
        $XMSServerApiPath = '/xenmobile/api/v1'
        #$XMSServerBaseUrl = "$($XMSServerScheme)://$($XMSServerHostname):$($XMSServerPort)"
        $XMSServerApiUrl  = Join-Url -Scheme $XMSServerScheme -Hostname $XMSServerHostname -Port $XMSServerPort -Parts $XMSServerApiPath -Seperator '/'

        Write-Verbose -Message 'Creating an authentication token, and setting the XMSAuthToken and XMSServer variables'
        #if a credential object is used, convert the secure password to a clear text string to submit to the server. 
        if ($null -ne $Credential) {
            $User = $Credential.username
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.password)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
        try {
            Set-Variable -Name 'XMSAuthToken' -Value (Get-XMAuthToken -User $User -Password $Password -Server $Server -Port $XMSServerPort) -Scope global -ErrorAction Stop
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
        $User = $Credential.username
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.password)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    $Header = @{
        'Content-Type' = 'application/json'
    }
    $Body = @{
        login          = $user;
        password       = $password
    }
    Write-Verbose -Message 'Submitting authentication request.'
    $ReturnedToken = Invoke-RestMethod -Uri $URL -Method POST -Body (ConvertTo-Json $Body) -Headers $Header
    Write-Verbose -Message "Received token: $($ReturnedToken)"
    return [string]$ReturnedToken.auth_token
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
            $EnrollmentResult = postObject -Url '/enrollment' -Target $Body -ErrorAction Stop
            Write-Verbose -Message "Enrollment invitation submitted."
            # the next portion of the function will download additional information about the enrollment request
            # this is pointless if the invitation was not correctly created due to an error with the request. 
            # Hence, we only run this, if there is an actual invitation in the enrollmentResult value. 
            if ($null -ne $EnrollmentResult) {
                Write-Verbose -Message 'An enrollment invication was created. Searching for additional details.'
                $SearchResult = Search-XMObject -Url '/enrollment/filter' -Criteria $EnrollmentResult.token
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
        $Searchresult = Search-XMObject  -Url '/enrollment/filter' -Criteria $User -FilterIds $Filter -ResultSetSize $ResultSetSize
        $ResultSet =  $Searchresult.enrollmentFilterResponse.enrollmentList.enrollments
        $ResultSet | Add-Member -NotePropertyName AgentNotificationTemplateName -NotePropertyValue $Searchresult.enrollmentFilterResponse.enrollmentList.enrollments.notificationTemplateCategories.notificationTemplate.name
        return $ResultSet
    }
}

# fuctions to manage devices. 

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
        $Results = Search-XMObject -Url '/device/filter' -Criteria $Criteria -FilterIds $Filter -ResultSetSize $ResultSetSize
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
            mandatory)]
        [string[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Id)) {
            Remove-XMObject -Url '/device' -Target $Id
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
            mandatory = $true)]
        [int[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        write-verbose -Message "This will send an update to device $($Id)"
        postObject -Url '/device/refresh' -Target $Id
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
            mandatory = $true)]
        [int[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Id)) {
            postObject -Url '/device/wipe' -Target $Id
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
        ConfirmImpact='High')]
    param(
        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory = $true)]
        [int[]]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($id)) {
            postObject -Url '/device/selwipe' -Target $Id
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
            mandatory)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Url "/device/$($Id)/deliverygroups"
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
            mandatory)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Url "/device/$($Id)/actions"
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
            mandatory)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Url "/device/$($Id)/apps"
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
            mandatory)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Url "/device/$($Id)/managedswinventory"
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
            mandatory)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Url "/device/$($Id)/softwareinventory"
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
            mandatory)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Url "/device/$($Id)"
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
            mandatory)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Url "/device/$($Id)/policies"
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
            mandatory)]
        [string]$Id
    )
    begin {
        #check session state
        checkSession
    }
    process {
        $Result = getObject -Url "/device/properties/$($Id)"
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
            mandatory)]
        [string]$Id,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
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
            postObject -Url "/device/property/$($Id)" -Target $Body
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
            mandatory)]
        [string]$Id,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
        [string]$Name
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Id)) {
            #the property is deleted based on the id of the property which is unique. 
            #thus, we first look for the property
            $Property = Get-XMDeviceProperty -Id $Id | Where-Object {
                $PSItem.name -eq $Name
            }
            Write-Verbose -Message "Property id for property: $($Name) is $($Property.id)"
            Remove-XMObject -Url "/device/property/$($Property.id)" -Target $null
        }
    }
}

#functions to manage server properties. 

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
        #The get-xmserverproperty function is called during the xmsession setup in order to specify the timeout values.
        #If you check the session during this time, the check will fail.
        #using the hidden skipcheck parameter, we can override the check during the initial xmsession setup.
        if (!$SkipCheck) {
            Write-verbose -Message 'Checking the session state'
            #check session state.
            checkSession
        }
        else {
            write-verbose -Message 'The session check is skipped.'
        }
    }
    process {
        Write-Verbose -Message 'Creating the Get-xmserverproperty request.'
        $Request.method    = 'POST'
        $Request.url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1/serverproperties/filter"
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
            mandatory)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
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
        if ($PSCmdlet.ShouldProcess($name)) {
            #if no displayname or description is provided, search for the existing values and use those. 
            if (!$DisplayName) {
                $DisplayName = (Get-XMServerProperty -Name $Name).displayName
            }
            if (!$Description) {
                $Description = (Get-XMServerProperty -Name $Name).description
            }
            $Request.method    = 'PUT'
            $Request.url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1/serverproperties" 
            $Request.header    = @{
                'auth_token'   = $XMSAuthToken;
                'Content-Type' = 'application/json'
            }
            $Request.body      = @{
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
            mandatory)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
        [string]$Value,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
        [string]$DisplayName,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
        [string]$Description
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Name)) {
            $Request.method    = 'POST'
            $Request.url       = "https://$($XMSServer):$($XMSServerPort)/xenmobile/api/v1/serverproperties" 
            $Request.header    = @{
                'auth_token'   = $XMSAuthToken;
                'Content-Type' = 'application/json'
            }
            $Request.body      = @{
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
            mandatory)]
        [string[]]$Name
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Name)) {
            Write-Verbose "Deleting $($Name)"
            Remove-XMObject -Url "/serverproperties" -Target $Name
        }
    }
}

#functions to manage client properties. (Client is WorxHome / Secure Hub)

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
        $Result = getObject -Url "/clientproperties/$($Key)"
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
            mandatory)]
        [string]$Displayname,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
        [string]$Key,

        [Parameter(ValueFromPipelineByPropertyName, 
            mandatory)]
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
            postObject -Url '/clientproperties' -Target $Body
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
            putObject -Url "/clientproperties/$($Key)" -Target $Body
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
            mandatory)]
        [string[]]$Key
    )
    begin {
        #check session state
        checkSession
    }
    process {
        if ($PSCmdlet.ShouldProcess($Key)) {
            Write-Verbose -Message "Deleting: $($Key)"
            Remove-XMObject -Url "/clientproperties/$($Key)" -Target $null
        }
    }
}

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
Export-ModuleMember -Function Remove-XMServerProperty
Export-ModuleMember -Function Set-XMClientProperty
Export-ModuleMember -Function Set-XMDeviceProperty
Export-ModuleMember -Function Set-XMServerProperty
Export-ModuleMember -Function Update-XMDevice