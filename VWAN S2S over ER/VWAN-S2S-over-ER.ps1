#Variables
$rgName = "s2s-over-er-rg"
$location = "eastus2"
$onPremVnetName = "onprem-vnet"
$onPremVnetCidr = "10.10.0.0/16"
$onPremOctet1 = $onPremVnetCidr.Split('.')[0]
$onPremOctet2 = $onPremVnetCidr.Split('.')[1]
$onPremErGwName = 'onprem-er-gw'
$onPremErGwPipName = 'onprem-er-gw-pip'
$vwanName = "vwan-lab"
$vhubName = "eu2-vhub"

#Create RG
New-AzResourceGroup -Name $rgName -Location $location

#Create "On-Prem" resources

$csrSnetCidr = "$onPremOctet1.$onPremOctet2.1.0/24"
$csrSnet = New-AzVirtualNetworkSubnetConfig -Name 'nva-snet' -AddressPrefix $csrSnetCidr


$gwSnetCidr = "$onPremOctet1.$onPremOctet2.255.0/24"
$erSnet = New-AzVirtualNetworkSubnetConfig -Name 'GatewaySubnet' -AddressPrefix $gwSnetCidr

$onPremVnet = New-AzVirtualNetwork -Name $onPremVnetName -ResourceGroupName $rgName -Location $location -AddressPrefix $onPremVnetCidr -Subnet $csrSnet,$erSnet


$erGwPip = New-AzPublicIpAddress -Name $onPremErGwPipName -ResourceGroupName $rgName -Location $location -Sku Standard
$gwSnet = Get-AzVirtualNetworkSubnetConfig -name 'GatewaySubnet' -VirtualNetwork $onPremVnet
$erGwIpCfg = New-AzVirtualNetworkGatewayIpConfig -Name 'er-gw-ip-cfg' -SubnetId $gwSnet.Id -PublicIpAddressId $erGwPip.Id

New-AzVirtualNetworkGateway -Name $onPremErGwName -ResourceGroupName $rgName -Location $location -GatewayType ExpressRoute -GatewaySku ErGw1AZ -IpConfigurations $erGwIpCfg -

#Create VWAN

#Create vHub

#Create ER + S2S VPN GW

#Waiting for ER to be provisioned

#Connect