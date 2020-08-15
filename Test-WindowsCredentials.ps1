<#
.Synopsis
   Tests windows credentials.
.DESCRIPTION
   Tests windows credentials programmatically.
.EXAMPLE
   Test-Credentials
    This will prompt the user for a username and password and indicate if the username/password are valid.
    For domain accounts you will likely need to include the domain with the username either in the form of "domain\user" or "user@domain".
.PARAMETER Credential
    This is the username and password you would like to test.
.PARAMETER Interactive
    Determines if you want a pop-up or not.
.NOTES
    File Name       : Test-WindowsCredentials
    Author          : Kevin Stevens
    Creation Date   : 8/15/2020
#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true)]
    [PSCredential]$Credential,

    [Parameter(Mandatory=$false)]
    [switch]$Interactive,

    [Parameter(Mandatory=$false)]
    [Ref]$ErrorInfo
)

#For Message Boxes
Add-Type -AssemblyName "PresentationFramework"

#Using old methods used in C# applications.
add-type @"
using System;
using System.Runtime.InteropServices;
public class EpicCredTester
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LogonUser(string username, string domain, string password, int logonType, int logonProvider, ref IntPtr identityPtr);

    [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CloseHandle(IntPtr ptr);

    public static string SplitDomainAndUserName(string username, out string domain)
    {
        if (username.IndexOf('\\') > 0)
        {
            string[] array = username.Split('\\');
            if (array.Length > 2)
            {
                domain = null;
                return null;
            }
            domain = array[0];
            return array[1];
        }
        if (username.IndexOf('@') > 0)
        {
            string[] array2 = username.Split('@');
            if (array2.Length > 2)
            {
                domain = null;
                return null;
            }
            domain = array2[1];
            return array2[0];
        }
        domain = ".";
        return username;
    }
}
"@

$msgBoxTitle = "Epic Windows Credential Tester"
$intPointer = [System.IntPtr]::Zero
$domain = ""

#Parse out domain and username to separate variables. If no Domain is specified then "." is used.
$user = [EpicCredTester]::SplitDomainAndUserName($Credential.UserName,[ref] $domain)
$userMsgBoxInfo = "Domain:`t`tUser:`n-----------`t-----------`n$Domain`t$User"

<#
Test the credentials using the same parameters as Interconnect for username token authentication.

LogonUser(User,Domain,Password,LogonType,LogonProvider,Pointer)
    LogonType = 8 | LOGON32_LOGON_NETWORK_CLEARTEXT
    LogonProvider = 0 | LOGON32_PROVIDER_DEFAULT
#>
if([EpicCredTester]::LogonUser($user,$domain,[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)),8,0,[ref] $intPointer))
{
    if($Interactive.IsPresent)
    {
        [System.Windows.MessageBox]::Show("Username and Password are good!`n`n$userMsgBoxInfo", $msgBoxTitle, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
    }
    $ErrorInfo.Value = $null
    #We never need to use the pointer. So closing it out.
    [EpicCredTester]::CloseHandle($intPointer) | Out-Null
    return $true
}else
{
    #This error comes from the function due to the "SetLastError" attribute when instantiating the method.
    $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $errorString = "Validation failed with win32 error code: $lastError`n`n$userMsgBoxInfo"
    if($Interactive.IsPresent)
    {
        [System.Windows.MessageBox]::Show($errorString, $msgBoxTitle, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning) | Out-Null
    }
    else
    {
        $ErrorInfo.Value = $errorString
    }
    #We never need to use the pointer. So closing it out.
    [EpicCredTester]::CloseHandle($intPointer) | Out-Null
    return $false
}