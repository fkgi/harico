# ip tuntap add tun0 mode tun
# ip link set tun0 up
# ip addr add 10.0.1.101/24 dev tun0
# ip rorute add 10.0.2.0/24 dev tun0

# cat ifcfg-tun0
# DEVICE=tun0
# TYPE=Tap
# BOOTPROTO=none
# IPADDR=10.0.1.101
# PREFIX=24
# DEFROUTE=no
# IPV6INIT=yes
# NAME=tun0
# ONBOOT=yes

# cat route-tun0
# 10.0.2.0/24 via 10.0.1.101 dev tun0

# ./smf -l=10.0.0.101:8805 -r=10.0.0.102:8805
# ./gnb -l=10.0.0.101:2152 -m=:8081

smfapi="localhost:8080"
gnbapi="localhost:8081"

ueip="10.0.1.101"
asip="10.0.1.102"

###
# init PFCP session
###
req=$(cat << EOS
{
    "PDR": [{
        "ID": 101,
        "precedence": 1,
        "PDI": {
            "interface": "Access",
            "FTEID": {
                "IPv4": "0.0.0.0"
            },
            "QFI": 5
        },
        "headerRemoval": {
            "description": "GTP-U/UDP/IPv4"
        },
        "FAR": 1101,
        "URR": [2101],
        "QER": [1]
    },{
        "ID": 201,
        "precedence": 1,
        "PDI": {
            "interface": "Core",
            "networkInstance": "ladn01",
            "UE_IP": {
                "dest": true,
                "IPv4": "${ueip}"
            }
        },
        "FAR": 1201,
        "URR": [2101],
        "QER": [1]
    }],
    "FAR": [{
        "ID": 1101,
        "action": {
            "FORW": true
        },
        "forwardingParam": {
            "interface": "Core",
            "networkInstance": "ladn01"
        }
    },{
        "ID": 1201,
        "action": {
            "BUFF": true
        }
    }],
    "URR":[{
        "ID": 2101,
        "measurementMethod": {
            "volume": true
        },
        "reportingTriggers": [2],
        "volumeThreshold": {
            "total": 1024000,
            "uplink": 102400,
            "downlink": 204800
        }
    }],
    "QER":[{
        "ID": 1,
        "gateStatus": {
            "ul": true,
            "dl": true
        },
        "MBR": {
            "ul": 1024,
            "dl": 2048
        },
        "QFI": 5
    }],
    "pdnType": "IPv4",
    "inactivityTimer": 3600
}
EOS
)
res=$(curl -v -X POST -H "Content-Type: application/json" -d "${req}" ${smfapi}/pfcp-cp/v1/session)

###
# get UPF side tunnel-endpoint id
###
context=$(echo $res | jq -r '.ID')
teid=$(echo $res | jq -r '.PDR[0].FTEID.ID')
teip=$(echo $res | jq -r '.PDR[0].FTEID.IPv4')

###
# init GTP tunnel
###
req=$(cat << EOS
{
    "ID": ${teid},
    "device": "tun0",
    "IP": "${teip}"
}
EOS
)
res=$(curl -v -X POST -H "Content-Type: application/json" -d "${req}" ${gnbapi}/gtp-an/v1/session)

###
# get gNB tunnel-endpoint id
###
teid=$(echo $res | jq -r '.ID')
teip=$(echo $res | jq -r '.IP')

###
# modify PFCP session
# notify gNB tunnel-endpoint id
###
req=$(cat << EOS
{
    "updateFAR": [{
        "ID": 1201,
        "action": {
            "FORW": true
        },
        "forwardingParam": {
            "headerCreation":{
                "ID": ${teid},
                "IPv4": "${teip}"
            }
        }
    }]
}
EOS
)
curl -v -X PATCH -H "Content-Type: application/json" -d "${req}" ${smfapi}/pfcp-cp/v1/session/${context}

###
# modify gNB local tunnel-endoint id to HEX
# for call gNB API
###
teid=$(printf '%x' ${teid})

###
# ping from UE to AS
###
ping ${asip} -I ${ueip} -c 5

###
# modify PFCP session to buffer mode
###
bufreq=$(cat << EOS
{
    "updateFAR": [{
        "ID": 1201,
        "action": {
            "NOCP": true,
            "BUFF": true
        }
    }]
}
EOS
)
curl -v -X PATCH -H "Content-Type: application/json" -d "${bufreq}" ${smfapi}/pfcp-cp/v1/session/${context}

###
# ping from UE to AS
###
ping ${asip} -I ${ueip} -c 5
sleep 10

###
# modify PFCP session to forward mode
###
curl -v -X PATCH -H "Content-Type: application/json" -d "${req}" ${smfapi}/pfcp-cp/v1/session/${context}

###
# ping from UE to AS
###
ping ${asip} -I ${ueip} -c 5
sleep 5

###
# stop PFCP session
###
res=$(curl -v -X DELETE ${smfapi}/pfcp-cp/v1/session/${context})

###
# stop GTP tunnel
###
res=$(curl -v -X DELETE ${gnbapi}/gtp-an/v1/session/${teid})
