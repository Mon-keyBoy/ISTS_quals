#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi

# make backup dirs, hide them urself
mkdir -p /docker_backups

packages=(
  software-properties-common 
  coreutils 
  net-tools 
  build-essential 
  libssl-dev 
  procps 
  lsof 
  tmux 
  nftables 
  jq 
  tar 
  bash 
  sudo 
  openssl 
  util-linux 
  passwd 
  gnupg 
  findutils 
  sshd
  ssh
  grep 
  gawk 
  sed 
  wget 
  gzip 
  login 
  cron 
  systemd 
  openssh-client 
  mount 
  acl 
  inetutils-ping 
  lsb-release 
  iproute2
  zsh
)

for package in "${packages[@]}"; do
  apt install -y --reinstall "$package"
done

#stop sshd
systemctl stop ssh
systemctl disable ssh
systemctl stop sshd
systemctl disable sshd
apt purge -y openssh-server

#install tools that you want/need
apt install -y vim
apt install -y nmap
apt install -y auditd
apt install debsums -y
systemctl enable auditd
systemctl start auditd

#delete and stop iptables legacy and iptables-nft
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -t raw -F
iptables -t raw -X
iptables-legacy -F
iptables-legacy -t nat -F
iptables-legacy -t mangle -F
iptables-legacy -t raw -F
iptables-legacy -X
iptables-nft -F
iptables-nft -t nat -F
iptables-nft -t mangle -F
iptables-nft -t raw -F
iptables-nft -X
systemctl stop iptables
systemctl disable iptables
systemctl stop iptables-legacy
systemctl disable iptables-legacy
systemctl stop iptables-persistent
systemctl disable iptables-persistent

# Define the blacklist configuration file
BLACKLIST_FILE="/etc/modprobe.d/blacklist.conf"
# Check if the file exists, create it if it doesn't
if [ ! -f "$BLACKLIST_FILE" ]; then
    echo "Creating blacklist configuration file at $BLACKLIST_FILE"
    sudo touch "$BLACKLIST_FILE"
fi

# Add the blacklist entries
echo "Blacklisting kernel modules..."
bash -c "cat >> $BLACKLIST_FILE <<EOF
blacklist ip_tables
blacklist iptable_nat
blacklist ip6_tables
blacklist iptable_mangle
blacklist iptable_raw
EOF"

depmod -a
apt install -y initramfs-tools
update-initramfs -u

# remove persitance rules
rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 
# make nftables the main rules
update-alternatives --set iptables /usr/sbin/iptables-nft
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
update-alternatives --set arptables /usr/sbin/arptables-nft
update-alternatives --set ebtables /usr/sbin/ebtables-nft
#get rid of all nft rules
nft flush ruleset


# Backup Docker data
systemctl stop docker
DOCKER_BACKUP_DIR="/docker_backups"
mkdir -p "$DOCKER_BACKUP_DIR"
cp -r /var/lib/docker "$DOCKER_BACKUP_DIR"
cp -r /etc/docker "$DOCKER_BACKUP_DIR"
cp -r $HOME/.docker/ "$DOCKER_BACKUP_DIR"
systemctl start docker
systemctl enable docker




#containers
for container in $(docker ps -aq); do
    CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$container" | cut -c2-)
    echo "Backing up container: $CONTAINER_NAME"

    # Export container image
    IMAGE_NAME=$(docker inspect --format='{{.Config.Image}}' "$container")
    if ! docker save "$IMAGE_NAME" > "$DOCKER_BACKUP_DIR/$CONTAINER_NAME-image.tar"; then
        echo "Error saving image for container: $CONTAINER_NAME" >&2
        continue
    fi

    # Export container metadata
    if ! docker inspect "$container" | jq '.[0] | {Name: .Name, Config: .Config, HostConfig: .HostConfig, NetworkSettings: .NetworkSettings}' > "$DOCKER_BACKUP_DIR/$CONTAINER_NAME-config.json"; then
        echo "Error exporting config for container: $CONTAINER_NAME" >&2
        continue
    fi
done

# volumes
VOLUME_BACKUP_DIR="$DOCKER_BACKUP_DIR/volumes"
mkdir -p "$VOLUME_BACKUP_DIR"
for volume in $(docker volume ls -q); do
    [ -n "$volume" ] || continue
    echo "Backing up volume: $volume"
    tar -czf "$VOLUME_BACKUP_DIR/$volume.tar.gz" -C "$(docker volume inspect --format '{{ .Mountpoint }}' "$volume")" .
done

#start docker
systemctl start docker
systemctl enable docker




#disable cron
systemctl stop cron
systemctl disable cron
chattr +i /etc/crontab
chattr +i /etc/cron.d
chattr +i /etc/cron.daily
chattr +i /etc/cron.hourly
chattr +i /etc/cron.monthly
chattr +i /etc/cron.weekly

#get rif of cups
systemctl stop cups
systemctl disable cups
systemctl stop cups.service cups.socket cups.path
systemctl disable cups.service cups.socket cups.path
apt remove --purge -y cups

#disable firewalld and ufw
systemctl disable --now firewalld
systemctl disable --now ufw



#setup nftables table input
nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0 \; }
# Allow established and related traffic
nft add rule ip filter input ct state established,related log accept
#allow rules input
#allow rules input
#allow rules input
#DNS
nft add rule ip filter input udp sport 53 accept
nft add rule ip filter input tcp sport 53 accept
#docker (HTTP)
nft add rule ip filter input tcp dport 80 accept
#HTTPS
nft add rule ip filter input tcp dport 443 accept
#docker api
nft add rule ip filter input tcp dport 2375 accept
nft add rule ip filter input tcp dport 2376 accept
#drop everything else
nft add rule ip filter input drop

#setup nftables table output
#setup nftables table output
#setup nftables table output
nft add chain ip filter output { type filter hook output priority 0 \; }
nft add rule ip filter output ct state established,related log accept
#allow rules output
#DNS
nft add rule ip filter output udp dport 53 accept
nft add rule ip filter output tcp dport 53 accept
#docker (HTTP)
nft add rule ip filter output tcp dport 80 accept
#HTTPS
nft add rule ip filter output tcp dport 443 accept
#docker api
nft add rule ip filter output tcp dport 2375 accept
nft add rule ip filter output tcp dport 2376 accept
#drop all other output
nft add rule ip filter output drop

#save the rules to a file and make it immutable
nft list ruleset > /nftables.conf
#ensure the nftables service loads the rules on boot
systemctl start nftables
systemctl enable nftables
nft flush table inet filter
nft delete table inet filter
nft -f nftables.conf







#make usefull aliases for all users
#show all the users so you can audit them DO NOT DELETE THE CORE ROOT USERS LIKE TOOR!!!!!!
curl -L -o /usr/local/bin/list_users.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/list_users.sh
chmod +x /usr/local/bin/list_users.sh
echo "alias listusers='/usr/local/bin/list_users.sh'" >> /etc/bash.bashrc
#looks for bad binaries
echo 'alias badbins="find / \( -perm -4000 -o -perm -2000 \) -type f -exec file {} \; 2>/dev/null | grep -v ELF"' >> /etc/bash.bashrc
#show bad or altered files
echo 'alias badfiles="debsums | grep -v 'OK$'"' >> /etc/bash.bashrc 
#alias's i like
echo "alias c='clear'" >> /etc/bash.bashrc 
#alias to look for reverse shells
curl -L -o /usr/local/bin/rev_shells.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/rev_shells.sh
chmod +x /usr/local/bin/rev_shells.sh
echo "alias revshells='/usr/local/bin/rev_shells.sh'" >> /etc/bash.bashrc
#commit the alias's
source /etc/bash.bashrc

#sharads line to make kernel modules require signatures, you need to reboot to get rid of any loaded kernel modules though
sed -i 's/\(vmlinuz.*\)/\1 module.sig_enforce=1 module.sig_unenforce=0/' /boot/grub/grub.cfg

#script done
echo "."
echo "."
echo "."
echo "."
echo "."
echo "Script complete! Please reboot for all changes to take effect."
