#!/bin/bash

TITAN_USER="titan"
SUPERVM_USER="supervm"
DEST="home"

echo "##---Smartalyse Controller Configuration--------"

#PATH = $PATH:/usr/local/sbin:/usr/sbin:/sbin
# Distro Functions
# ================

# Determine OS Vendor, Release and Update
# Tested with OS/X, Ubuntu, RedHat, CentOS, Fedora
# Returns results in global variables:

# ``os_VENDOR`` - vendor name: ``Ubuntu``, ``Fedora``, etc
# ``os_RELEASE`` - major release: ``14.04`` (Ubuntu), ``20`` (Fedora)
# ``os_UPDATE`` - update: ex. the ``5`` in ``RHEL6.5``
# ``os_PACKAGE`` - package type: ``deb`` or ``rpm``
# ``os_CODENAME`` - vendor's codename for release: ``snow leopard``, ``trusty``

os_VENDOR=""
os_RELEASE=""
os_UPDATE=""
os_PACKAGE=""
os_CODENAME=""

# GetOSVersion
GetOSVersion() {
    # Figure out which vendor we are
    if [[ -x "`which sw_vers 2>/dev/null`" ]]; then
        # OS/X
	os_VENDOR=`sw_vers -productName`
        os_RELEASE=`sw_vers -productVersion`
        os_UPDATE=${os_RELEASE##*.}
        os_RELEASE=${os_RELEASE%.*}
        os_PACKAGE=""
        if [[ "$os_RELEASE" =~ "10.7" ]]; then
            os_CODENAME="lion"
        elif [[ "$os_RELEASE" =~ "10.6" ]]; then
            os_CODENAME="snow leopard"
        elif [[ "$os_RELEASE" =~ "10.5" ]]; then
            os_CODENAME="leopard"
        elif [[ "$os_RELEASE" =~ "10.4" ]]; then
            os_CODENAME="tiger"
        elif [[ "$os_RELEASE" =~ "10.3" ]]; then
            os_CODENAME="panther"
        else
            os_CODENAME=""
        fi
    elif [[ -x $(which lsb_release 2>/dev/null) ]]; then
        os_VENDOR=$(lsb_release -i -s)
        os_RELEASE=$(lsb_release -r -s)
        os_UPDATE=""
        os_PACKAGE="rpm"
        if [[ "Debian,Ubuntu,LinuxMint" =~ $os_VENDOR ]]; then
            os_PACKAGE="deb"
        elif [[ "SUSE LINUX" =~ $os_VENDOR ]]; then
            lsb_release -d -s | grep -q openSUSE
            if [[ $? -eq 0 ]]; then
                os_VENDOR="openSUSE"
            fi
        elif [[ $os_VENDOR == "openSUSE project" ]]; then
            os_VENDOR="openSUSE"
        elif [[ $os_VENDOR =~ Red.*Hat ]]; then
            os_VENDOR="Red Hat"
        fi
        os_CODENAME=$(lsb_release -c -s)
    elif [[ -r /etc/redhat-release ]]; then
        # Red Hat Enterprise Linux Server release 5.5 (Tikanga)
        # Red Hat Enterprise Linux Server release 7.0 Beta (Maipo)
        # CentOS release 5.5 (Final)
        # CentOS Linux release 6.0 (Final)
        # Fedora release 16 (Verne)
        # XenServer release 6.2.0-70446c (xenenterprise)
        os_CODENAME=""
        for r in "Red Hat" CentOS Fedora XenServer; do
            os_VENDOR=$r
            if [[ -n "`grep \"$r\" /etc/redhat-release`" ]]; then
                ver=`sed -e 's/^.* \([0-9].*\) (\(.*\)).*$/\1\|\2/' /etc/redhat-release`
                os_CODENAME=${ver#*|}
                os_RELEASE=${ver%|*}
                os_UPDATE=${os_RELEASE##*.}
                os_RELEASE=${os_RELEASE%.*}
                break
            fi
            os_VENDOR=""
        done
        os_PACKAGE="rpm"
    elif [[ -r /etc/SuSE-release ]]; then
        for r in openSUSE "SUSE Linux"; do
            if [[ "$r" = "SUSE Linux" ]]; then
                os_VENDOR="SUSE LINUX"
            else
                os_VENDOR=$r
            fi

            if [[ -n "`grep \"$r\" /etc/SuSE-release`" ]]; then
                os_CODENAME=`grep "CODENAME = " /etc/SuSE-release | sed 's:.* = ::g'`
                os_RELEASE=`grep "VERSION = " /etc/SuSE-release | sed 's:.* = ::g'`
                os_UPDATE=`grep "PATCHLEVEL = " /etc/SuSE-release | sed 's:.* = ::g'`
                break
            fi
            os_VENDOR=""
        done
        os_PACKAGE="rpm"
    # If lsb_release is not installed, we should be able to detect Debian OS
    elif [[ -f /etc/debian_version ]] && [[ $(cat /proc/version) =~ "Debian" ]]; then
        os_VENDOR="Debian"
        os_PACKAGE="deb"
        os_CODENAME=$(awk '/VERSION=/' /etc/os-release | sed 's/VERSION=//' | sed -r 's/\"|\(|\)//g' | awk '{print $2}')
        os_RELEASE=$(awk '/VERSION_ID=/' /etc/os-release | sed 's/VERSION_ID=//' | sed 's/\"//g')
    fi
    	
}

# Translate the OS version values into common nomenclature
# Sets global ``DISTRO`` from the ``os_*`` values
DISTRO=""
GetDistro() {
    GetOSVersion
    if [[ "$os_VENDOR" =~ (Ubuntu) || "$os_VENDOR" =~ (Debian) ]]; then
        # 'Everyone' refers to Ubuntu / Debian releases by the code name adjective
        DISTRO=$os_CODENAME
    elif [[ "$os_VENDOR" =~ (Fedora) ]]; then
        # For Fedora, just use 'f' and the release
        DISTRO="f$os_RELEASE"
    elif [[ "$os_VENDOR" =~ (openSUSE) ]]; then
        DISTRO="opensuse-$os_RELEASE"
    elif [[ "$os_VENDOR" =~ (SUSE LINUX) ]]; then
        # For SLE, also use the service pack
        if [[ -z "$os_UPDATE" ]]; then
            DISTRO="sle${os_RELEASE}"
        else
            DISTRO="sle${os_RELEASE}sp${os_UPDATE}"
        fi
    elif [[ "$os_VENDOR" =~ (Red Hat) || \
        "$os_VENDOR" =~ (CentOS) || \
        "$os_VENDOR" =~ (OracleServer) ]]; then
        # Drop the . release as we assume it's compatible
        DISTRO="rhel${os_RELEASE::1}"
    elif [[ "$os_VENDOR" =~ (XenServer) ]]; then
        DISTRO="xs$os_RELEASE"
    else
        # Catch-all for now is Vendor + Release + Update
        DISTRO="$os_VENDOR-$os_RELEASE.$os_UPDATE"
    fi
    export DISTRO
}

# Exit after outputting a message about the distribution not being supported.
# exit_distro_not_supported [optional-string-telling-what-is-missing]
function exit_distro_not_supported {
    if [[ -z "$DISTRO" ]]; then
        GetDistro
    fi

    if [ $# -gt 0 ]; then
        die $LINENO "Support for $DISTRO is incomplete: no support for $@"
    else
        die $LINENO "Support for $DISTRO is incomplete."
    fi
}


# Distro-agnostic function to tell if a package is installed
# is_package_installed package [package ...]
function is_package_installed {
    if [[ -z "$@" ]]; then
        return 1
    fi

    if [[ -z "$os_PACKAGE" ]]; then
        GetOSVersion
    fi

    if [[ "$os_PACKAGE" = "deb" ]]; then
        dpkg -s "$@" > /dev/null 2> /dev/null
    elif [[ "$os_PACKAGE" = "rpm" ]]; then
        rpm --quiet -q "$@"
    else
        exit_distro_not_supported "finding if a package is installed"
    fi
}


is_package_installed sudo
if [ "$(whoami &2>/dev/null)" != "root" ] && [ "$(id -un &2>/dev/null)" != "root" ]
      then
      echo "You must be root to run this script!"
      echo "use 'sudo !!'"
      exit 1
fi

GetDistro
if [[ "$os_VENDOR" != "Ubuntu" ]] 
   then
   echo "Smartalyse supports only Ubuntu !"  		
fi


echo "#Smartalyse Controller: Disable root login over SSH"
echo "#Smartalyse Controller: Disabling root login for SSH"


#test if supervm user present or not.
if ! getent passwd $SUPERVM_USER >/dev/null; then
    echo "Creating a user called $SUPERVM_USER"
    #useradd -g $STACK_USER -s /bin/bash -d $DEST -m $SUPERVM_USER
else
   #su $SUPERVM_USER 
   pwd
fi



limit_Access_To_su() {
  dpkg-statoverride --update --add root sudo 4750 /bin/su
}


#function disable_root_login_ssh() {
#}

#run_ssh_on_port() {

#}

#reload_ssh_on_port() {
#
#}

#improve_ip_sec() {
#}

#install_package() {
#}

#disable_usb_driver_storage() {
#}

#enable_firewall() {
#}


#remove_gnome() {
#}

# Check if titan user is present or not. if not create one
# Add it into the admin group
# - configure sudo for $TITAN_USER

if ! getent passwd $TITAN_USER >/dev/null; then
   echo "Creating a user called $TITAN_USER"
   #useradd -g $TITAN_USER -s /bin/bash  -g sudo -d $DEST -m $TITAN_USER
   echo "Set Password for $TITAN_USER" 
   #passwd $TITAN_USER    
   
   echo "Giving $TITAN_USER user passwordless sudo privileges"
   # UEC images ``/etc/sudoers`` does not have a ``#includedir``, add one
   #grep -q "^#includedir.*/etc/sudoers.d" /etc/sudoers || echo "#includedir /etc/sudoers.d" >> /etc/sudoers 
   #(umask 226 && echo "$TITAN_USER ALL=(ALL) NOPASSWD:ALL" /etc/sudoers.d/50_titan_sh )
   echo "Confirm wheather titan works and have previlages" 

   limit_Access_To_su
fi






 

