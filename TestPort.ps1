<#
.Synopsis
To test if a port is open.

.Description
Identify if a port is open and attempt to identify a device further by querying Active Directory for a canonical name.

.Example

Test-Port -Name MyComputer -Port 80 -Protocol TCP

Name          : MyComputer
CanonicalName : MyDomain.Local/Computers/MyComputer
IP            : 192.168.1.23
Port          : 80
Protocol      : TCP
Online        : Online
PortStatus    : Open

.Example


Test-Port -IPaddress 192.168.1.15 -Port 443 -Protocol TCP

Name          : MyComputer
CanonicalName : MyDomain.Local/Computers/MyComputer
IP            : 192.168.1.15
Port          : 443
Protocol      : TCP
Online        : Online
PortStatus    : Open

.LINK
https://github.com/BlueGadgetEngineer/Test-Port

.COMPONENT
# Requires -Module 'ActiveDirectory'
#>
function Test-Port {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            ParameterSetName = 'IP',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('IP', 'Address')]
        [AllowEmptyString()]
        [System.Net.IPAddress]
        $IPaddress,


        [Parameter(Mandatory = $true,
            ParameterSetName = 'Name',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('ComputerName', 'Server', 'Host', 'HostName')]
        [AllowEmptyString()]
        [String]$Name,


        [Parameter(Mandatory = $true,
            ParameterSetName = 'Name',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Parameter(Mandatory = $true,
            ParameterSetName = 'IP',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Int32]$Port,


        [Parameter(Mandatory = $true,
            ParameterSetName = 'Name',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Parameter(Mandatory = $true,
            ParameterSetName = 'IP',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateSet('TCP', 'UDP')]
        [String]$Protocol
    )
    
    begin {
    }
    
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Name' {
                $Ping = [System.Net.NetworkInformation.Ping]::new()
                $Ping = $Ping.Send($Name)
                if ($Ping.Status -eq 'Success') {
                    $IP = $Ping.Address
                    $Online = $true

                    switch ($Protocol) {
                        'TCP' {
                            $TCPobject = [System.Net.Sockets.TcpClient]::new()
                            $TCPobject.Connect("$Name", "$Port")
                            if ($TCPobject -eq $True) {
                                $PortStatus = 'Open'
                            }
                            else {
                                $PortStatus = $Error[0].Exception.InnerException.SocketErrorCode
                                $Error.Clear()
                            }
                        }
                        'UDP' {
                            [int]$UDPtimeout = 1000
                            $UDPobject = [System.Net.Sockets.UdpClient]::new()
                            $UDPobject.Client.ReceiveTimeout = $UDPtimeout
                            $UDPobject.Connect("$IP", "$Port")
                            $MSG = [System.Text.ASCIIEncoding]::new()
                            $MSGbytes = $MSG.GetBytes("$(Get-Date)")
                            [void]$UDPobject.Send($MSGbytes, $MSGbytes.Length)
                            $RemoteEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                            $ReceiveBytes = $UDPobject.Receive([ref]$RemoteEndpoint)
                            if ($null -eq $ReceiveBytes) {
                                $PortStatus = $Error[0].Exception.InnerException.SocketErrorCode
                                $Error.Clear()
                            }
                            else {
                                $PortStatus = 'Open'
                            }
            
                        }
                    }
                }
                else {
                    if ($null -eq $Ping.Status) {
                        $Online = $Error[0].Exception.InnerException.InnerException.SocketErrorCode
                        $Error.Clear()
                    }
                    else {
                        $Online - $Ping.Status
                        $PortStatus = $null
                    }
                }
                $AD = Get-ADComputer -Identity $Name -Properties CanonicalName -ErrorVariable ADERR
                if ($Name - $AD.Name) {
                    $CN = $AD.CanonicalName
                }
                else {
                    $CN = $ADERR
                }

                $Out = [PSCustomObject]@{
                    'Name'          = $Name;
                    'CanonicalName' = $CN;
                    'IP'            = $IP;
                    'Port'          = $Port;
                    'Protocol'      = $Protocol;
                    'Online'        = $Online;
                    'PortStatus'    = $PortStatus
                }
            }

            'IP' {
                $Ping = [System.Net.NetworkInformation.Ping]::new()
                $Ping = $Ping.Send("$IPaddress")
                if ($Ping.Status -eq 'Success') {
                    $IP = $Ping.Address
                    $Online = $true

                    switch ($Protocol) {
                        'TCP' {
                            $TCPobject = [System.Net.Sockets.TcpClient]::new()
                            $TCPobject.Connect("$IPaddress", "$Port")
                            if ($TCPobject -eq $True) {
                                $PortStatus = 'Open'
                            }
                            else {
                                $PortStatus = $Error[0].Exception.InnerException.SocketErrorCode
                                $Error.Clear()
                            }
                        }
                        'UDP' {
                            [int]$UDPtimeout = 1000
                            $UDPobject = [System.Net.Sockets.UdpClient]::new()
                            $UDPobject.Client.ReceiveTimeout = $UDPtimeout
                            $UDPobject.Connect("$IP", "$Port")
                            $MSG = [System.Text.ASCIIEncoding]::new()
                            $MSGbytes = $MSG.GetBytes("$(Get-Date)")
                            [void]$UDPobject.Send($MSGbytes, $MSGbytes.Length)
                            $RemoteEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                            $ReceiveBytes = $UDPobject.Receive([ref]$RemoteEndpoint)
                            if ($null -eq $ReceiveBytes) {
                                $PortStatus = $Error[0].Exception.InnerException.SocketErrorCode
                                $Error.Clear()
                            }
                            else {
                                $PortStatus = 'Open'
                            }
            
                        }
                    }
                }
                else {
                    if ($null -eq $Ping.Status) {
                        $Online = $Error[0].Exception.InnerException.InnerException.SocketErrorCode
                        $Error.Clear()
                    }
                    else {
                        $Online - $Ping.Status
                        $PortStatus = $null
                    }
                }
                #Try to resolve hostname
                $DNS = [System.Net.Dns]::GetHostByAddress($IPaddress)
                if ($DNS.GetType().Name -eq 'IPHostEntry') {
                    $HostName = $DNS.HostName.Split('.')[0]
                }
                else {
                    $HostName = $Error[0].Exception.InnerException.SocketErrorCode
                    $error.Clear()
                }

                if ($HostName.GetType().Name -ne 'SocketError') {
                    $AD = Get-ADComputer -Identity $HostName -Properties CanonicalName -ErrorVariable ADERR
                    if ($HostName - $AD.Name) {
                        $CN = $AD.CanonicalName
                    }
                    else {
                        $CN = $ADERR
                    }
    
                }
                else {
                    $CN = $null
                }


                $Out = [PSCustomObject]@{
                    'Name'          = $HostName;
                    'CanonicalName' = $CN;
                    'IP'            = $IP;
                    'Port'          = $Port;
                    'Protocol'      = $Protocol;
                    'Online'        = $Online;
                    'PortStatus'    = $PortStatus
                }

            }
        }
    }
    
    end {
        $Out
    }
}