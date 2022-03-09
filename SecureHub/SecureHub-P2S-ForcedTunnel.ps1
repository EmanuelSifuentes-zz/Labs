#Initialize variables
$rgName = "vwan-demo-rg"
$vwanName = "vwan-lab"
$vHubName = "vhub-eu2"
$vHubPrefix = "172.16.0.0/23"
$location = "eastus2"
$azfwPolicyName = "azfw-policy-standard"
$azfwPolicyRcgName = "vwan-demo-netrcg"
$azfwPolicyRcName = "vwan-demo-netrc"
$azFwName = "vwan-azfw-standard"
$azFwLawName = "azfw-law"
$p2sVpnGatewayName = "vhub-p2s-vpn-gw"
$vpnClientAddressSpaces = '192.168.0.0/24'
$vpnServerConfigName = "p2s-vpn-cfg"
$certFolder = "C:\vwanDemo"
$rootCertPath = "C:\vwanDemo\rootCert.cer"
$rootCertb64Path = "C:\vwanDemo\rootCert-base64.cer"
$rootPfxPath = "C:\vwanDemo\rootPfx.pfx"
$childPfxPath = "C:\vwanDemo\childPfx.pfx"

#Create RG
New-AzResourceGroup -name $rgName -Location $location

#Create vWAN and vHub
$vwan = New-AzVirtualWan -ResourceGroupName $rgName -Name $vwanName -Location $location -AllowVnetToVnetTraffic -AllowBranchToBranchTraffic -VirtualWANType Standard
$vHub = New-AzVirtualHub -ResourceGroupName $rgName -Name $vHubName -VirtualWan $vwan -AddressPrefix $vHubPrefix -Location $location

#Create and configure Azure Firewall Policy
New-AzFirewallPolicy -Name $azfwPolicyName -ResourceGroupName $rgName -Location $location
$azFwPolicy = Get-AzFirewallPolicy -Name $azfwPolicyName -ResourceGroupName $rgName

$networkRule = New-AzFirewallPolicyNetworkRule -Name "AllowRFC1918" -SourceAddress "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16" -Protocol Any -DestinationAddress * -DestinationPort *
$ruleCollectionCfg = New-AzFirewallPolicyFilterRuleCollection -Name $azfwPolicyRcName -Priority 100 -ActionType Allow -Rule $networkRule

New-AzFirewallPolicyRuleCollectionGroup -Name $azfwPolicyRcgName -Priority 200 -RuleCollection $ruleCollectionCfg -FirewallPolicyObject $azFwPolicy

#Create secure hub
$azFwPip = New-AzFirewallHubPublicIpAddress -Count 1
$azFwHubIp = New-AzFirewallHubIpAddress -PublicIP $AzFwPip
$azFw = New-AzFirewall -Name $azFwName -ResourceGroupName $rgName -Location $location -VirtualHubId $vHub.Id -FirewallPolicyId $azFwPolicy.Id -Sku AZFW_Hub -HubIPAddress $azFwHubIp

#Enable logging
$azFwLaw = New-AzOperationalInsightsWorkspace -Name $azFwLawName -ResourceGroupName $rgName -Location $location
Set-AzDiagnosticSetting -ResourceId $AzFW.Id -Enabled $True -Category AzureFirewallApplicationRule, AzureFirewallNetworkRule -WorkspaceId $azFwLaw.ResourceId

#Check on vHub routing status
$azContext = Get-AzContext
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
$authHeader = @{
    'Content-Type'='application/json'
    'Authorization'='Bearer ' + $token.AccessToken
}

# Invoke the REST API
$vHubId = $vHub.Id
$restUri = "https://management.azure.com"+$vHubId+"?api-version=2021-08-01"
$routingStatus = $false

while ($routingStatus -eq $false)
{
    $response = Invoke-RestMethod -Uri $restUri -Method Get -Headers $authHeader
    if ($response.properties.routingState -eq "Provisioned") 
    {
        $routingStatus = $true
    }
    else {
        Start-Sleep -Seconds 30
    }
}


#Create static routes in default Route table
$azFwId = $(Get-AzVirtualHub -ResourceGroupName $rgName -name $vHubName).AzureFirewall.Id
$azFwRoute = New-AzVHubRoute -Name "internet_traffic" -Destination @("0.0.0.0/0") -DestinationType "CIDR" -NextHop $azFwId -NextHopType "ResourceId"
$defaultRt = Update-AzVHubRouteTable -Name "defaultRouteTable" -ResourceGroupName $rgName -VirtualHubName $vHubName -Route @($azFwRoute)

#Create P2S VPN Certificates
$rootCert = New-SelfSignedCertificate -Type Custom -KeySpec Signature `
-Subject "CN=P2SRootCert" -KeyExportPolicy Exportable `
-HashAlgorithm sha256 -KeyLength 2048 `
-CertStoreLocation "Cert:\CurrentUser\My" -KeyUsageProperty Sign -KeyUsage CertSign

$childCert = New-SelfSignedCertificate -Type Custom -DnsName P2SChildCert -KeySpec Signature `
-Subject "CN=P2SChildCert" -KeyExportPolicy Exportable `
-HashAlgorithm sha256 -KeyLength 2048 `
-CertStoreLocation "Cert:\CurrentUser\My" `
-Signer $rootCert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")


#Convert root cert to B64 Encoded
if (!(Test-Path -Path $certFolder))
{
    mkdir $certFolder
}
$rootCertThumbprint = $rootCert.Thumbprint
$childCertThumbprint = $childCert.Thumbprint
Export-Certificate -Type CERT -FilePath $rootCertPath -Cert Cert:\CurrentUser\My\$rootCertThumbprint -NoClobber
certutil -encode $rootCertPath $rootCertb64Path
Remove-Item -Path $rootCertPath -Force

#Exporting child and root cert for reusability
$mypwd = ConvertTo-SecureString -String "password" -Force -AsPlainText
Get-ChildItem -Path Cert:\CurrentUser\My\$rootCertThumbprint | Export-PfxCertificate -FilePath $rootPfxPath -Password $mypwd
Get-ChildItem -Path Cert:\CurrentUser\My\$childCertThumbprint | Export-PfxCertificate -FilePath $childPfxPath -Password $mypwd

#Create P2S VPN Config
$p2sVpnCertList = New-Object "System.Collections.Generic.List[String]"
$p2sVpnCertList.Add($rootCertb64Path)

New-AzVpnServerConfiguration -Name $vpnServerConfigName -ResourceGroupName $rgName -VpnProtocol IkeV2,OpenVPN -VpnAuthenticationType Certificate -VpnClientRootCertificateFilesList $p2sVpnCertList -Location $location

#Create P2S VPN GW
$customDnsServers = New-Object string[] 1
$customDnsServers[0] = "168.63.129.16"
$vpnServerConfig = Get-AzVpnServerConfiguration -ResourceGroupName $rgName -Name $vpnServerConfigName
$createdP2SVpnGateway = New-AzP2sVpnGateway -ResourceGroupName $rgName -Name $p2sVpnGatewayName -VirtualHub $vHub -VpnGatewayScaleUnit 2 -VpnClientAddressPool $vpnClientAddressSpaces -VpnServerConfiguration $vpnServerConfig -EnableInternetSecurityFlag -CustomDnsServer $customDnsServers

#Optional - Clean up certs to avoid mismatch
$ask = Read-Host -Prompt "Do you want to delete the existing certificates? Y/N"
switch ($ask) {
    y { 
        Remove-Item -Path $certFolder -Recurse -Force
        Get-ChildItem -Path Cert:\CurrentUser\My\$rootCertThumbprint | Remove-Item
        Get-ChildItem -Path Cert:\CurrentUser\My\$childCertThumbprint | Remove-Item
     }
    Default {
        break
    }
}

#Interface Modification
#$Route = Get-NetRoute -AddressFamily ipv4 | ? {$_.DestinationPrefix -eq "0.0.0.0/0"}
$Route | Set-NetRoute -RouteMetric 256
Get-NetIPInterface -ifIndex $Route.ifIndex -AddressFamily IPv4 | Set-NetIPInterface -InterfaceMetric 56

$ifMetricPath = "c:\vwanDiags"
if (!(Test-Path -Path $ifMetricPath))
{
    mkdir $ifMetricPath
}

$defaultRoutes = Get-NetRoute -AddressFamily ipv4 | ? {$_.DestinationPrefix -eq "0.0.0.0/0"}
cd $ifMetricPath

foreach ($route in $defaultRoutes)
{
    $netIpIf = Get-NetIPInterface -InterfaceIndex $route.ifIndex -AddressFamily IPv4
    $fileName = $netIpIf.ifAlias + '-' + $netIpIf.ifIndex + ".txt"
    $oldIfMetric = $netIpIf.InterfaceMetric
    $oldRouteMetric = $route.RouteMetric
    $ifIndex = $netIpIf.ifIndex
    $ifAlias = $netIpIf.ifAlias
    $tempContent = "Metric information about default route (0.0.0.0/0) for $ifIndex - $ifAlias `n---------------------------------------------------`nInterface Index: $ifIndex`nInterface Alias: $ifAlias`nOld Interface Metric: $oldIfMetric`nOld Route Metric: $oldRouteMetric`n"
    New-Item -Name $fileName -ItemType File -Value $tempContent

    #Change the local metric to 1 higher than VPN
    $route | Set-NetRoute -RouteMetric 256
    Get-NetIPInterface -ifIndex $route.ifIndex -AddressFamily IPv4 | Set-NetIPInterface -InterfaceMetric 56
}