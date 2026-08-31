# How to execute Simurlation

## 1.Execute Docker image
$ docker build -t ntp426-lab(image name) -f Dockerfile.ntp426(DockerFile) .

## 2.Destroy current containerlab setting
$ sudo containerlab destroy -t ../topology.clab.yml(containerlab settingFile)

## 3.Deploy containerlab setting
$ sudo containerlab deploy -t ../topology.clab.yml(contaienerlab settingFile)

## 4.Run container preparation
$ sudo ./setup_tap_containers.sh tap_config.txt 

## 5.Run NTP server preparation
$ sudo ./setup_ntp426_servers.sh ntp_targets.txt tap_config.txt 

## 6.Run ns network
./ns3 run small_internet
