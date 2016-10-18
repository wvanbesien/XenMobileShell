# XenMobileShell
The XenMobileShell is a PowerShell module that allows easy use of the XenMobile Server API

########################################### INSTALLATION ###################################################

You can use the module by importing it using import-module, or by copying it to:

C:\Windows\System32\WindowsPowerShell\v1.0\Modules\XenMobileShell 

If you have git installed, create a folder in pull in the file through GIT. 

########################################## REQUIREMENTS ###################################################

This is written for PowerShell 5.0 and above. So, if your version of PowerShell is older, please upgrade it. (it's free!)

While I have not extensively tested this, it does appear to work on the opensource PowerShell on macOS as well. (make sure you update openssl using homebrew).

You will need a username and password of a user with access to the API. API access is controlled throuhg RBAC. 

The PC you are running the module on will need to connnect to the rest API on the XMS server which typically runs on port 4443. 
The module defaults to this port, however you can override it should that be needed. 

########################################## DISCLAIMER ####################################################

Citrix will not provide any support for this module whatsoever, so don't contact Citrix support. I also don't provide support. Help information is provided with each command. 


########################################## USAGE ##########################################################

get-command *xm*    # will list all commands available in the module
get-help <command name>   # will show help information for each command 

start with
new-xmsession -user <username> -password <password> -server <server>   # this will setup a session. 
get-xmdevice    # this will list the first 1000 devices. 
