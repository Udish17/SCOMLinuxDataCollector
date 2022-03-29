#! /bin/bash
#About:
#   This script is written for data collection from Linux machines which can help in troubleshooting SCOM UNIX/LINUX Agent (SCXAgent)
#Author : 
#   Udish Mudiar, Microsoft Customer Service Support Professional
#Feedback :
#   Email udmudiar@microsoft.com
#   Or the engineer you are working with


help()
{
    echo -e "\n about:   This shell script is used to collect basic information about the Operating System and SCOM Linux(SCX) Agent"
    echo -e "\t This is a read only script and does not make any changes to the system"
    echo -e "\n usage: $1 [OPTIONS]"
    echo -e "\n Options:"
    echo "  -o      :outputpath                      Specify the location where the data would be collected. If not specified the script will collect the data in the current working directory."
    echo "  -m      :scxmaintenanceaccount           Specify the SCX Maintenance Account. This will be used to check the sudo privilege for the account."
    echo "  -n      :scxmonitoringaccount            Specify the SCX Monitoring Account. This will be used to check the sudo privilege for the account."    
}

check_distro(){
    echo -e "Check distro. The script will proceed only for supported distro.....\n"
    echo -e "Check distro. The script will proceed only for supported distro.....\n" >> ${path}/scxdatacollector.log    
    if [ "$(uname)" = 'Linux' ]; then
        echo -e "\tDistro is Linux. Continuing.....\n"
        echo -e "\tDistro is Linux. Continuing.....\n" >> ${path}/scxdatacollector.log
    #elif [ condition ]; then
         # else if body
    else
        echo -e "\tDistro is not Linux. Exiting.....\n"
        echo -e "\tDistro is not Linux. Exiting....\n" >> ${path}/scxdatacollector.log
        exit
    fi  
}

check_parameters(){
    #checking the number of parameters passed
    #we expect either 1 or 2 parameters which are the SCOM mmaintenance and monitoring account
    #if the parameters passed are greater than 2 then it is advised that you recheck the SCOM Run As Account and Profiles for streamlining your configuration.
    #you can refer tot he below blog
    #https://udishtech.com/how-to-configure-sudoers-file-for-scom-monitoring/
    if [ $# == 1 ]; then
        echo -e "The argument for sudo is: $1.....\n"
        echo -e "The argument for sudo is: $1.....\n" >> ${path}/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        check_sudo_permission $1
    elif [ $# == 2 ]; then
        echo -e "The arguments for sudo are : $1 and $2.....\n"
        echo -e "The arguments for sudo are : $1 and $2.....\n" >> ${path}/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        check_sudo_permission $1 $2
    elif [ ! -n "${maint}" ] && [ ! -n "${mon}" ]; then
        echo -e "No SCOM Maintenance and Monitoring Account passed. Not collecting sudo details for the users....\n"
        echo -e "No SCOM Maintenance and Monitoring Account passed. Not collecting sudo details for the users....\n" >> ${path}/scxdatacollector.log
        read -p 'Do you want to stop the script and rerun with the SCOM Accounts (Y/N)? ' response
       if [[ "${response}" == "Y" ]]; then
           echo -e "Exiting script....\n"
           exit 3
       elif [[ "${response}" == "N" ]]; then
            echo -e "Continuing script. But not collecting sudo details for the users....\n"
            echo -e "Continuing script. But not collecting sudo details for the users....\n" >> ${path}/scxdatacollector.log
       fi       
    fi
}

check_dir() {
    pwd=`pwd`
    echo -e "Logs will be created in the output directory i.e. ${path} .....\n"
    echo -e "Logs will be created in the output directory i.e. ${path} .....\n" >> ${path}/scxdatacollector.log
    echo -e "Creating the directory strucuture to store the data from the collector.....\n"
    echo -e "Creating the directory strucuture to store the data from the collector.....\n" >> ${path}/scxdatacollector.log

    if [ -d "${path}/SCOMLinuxDataCollectorData" ]; then
        echo -e "\t Path ${path}/SCOMLinuxDataCollectorData is present. Removing and recreating the directory.....\n"
        echo -e "\t Path ${path}/SCOMLinuxDataCollectorData is present. Removing and recreating the directory.....\n" >> ${path}/scxdatacollector.log
        rm -rf ${path}/SCOMLinuxDataCollectorData
        create_dir "${path}/SCOMLinuxDataCollectorData"
    else
        echo -e "\t Path ${pwd} is not present in the current working directory. Creating the directory.....\n"
        echo -e "\t Path ${pwd} is not present in the current working directory. Creating the directory.....\n" >> ${path}/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData"
    fi 
    
    create_dir "${path}/SCOMLinuxDataCollectorData/logs"
    create_dir "${path}/SCOMLinuxDataCollectorData/certs"
    create_dir "${path}/SCOMLinuxDataCollectorData/network"    
    create_dir "${path}/SCOMLinuxDataCollectorData/scxdirectorystructure"
    create_dir "${path}/SCOMLinuxDataCollectorData/pam"
    create_dir "${path}/SCOMLinuxDataCollectorData/scxprovider"
    create_dir "${path}/SCOMLinuxDataCollectorData/configfiles"
}

create_dir(){        
    if [ -d $1 ]; then        
        echo -e "\t Path $1 exists. No action needed......\n"
        echo -e "\t Path $1 exists. No action needed......\n" >> ${path}/scxdatacollector.log
    else        
        echo -e "\t Path $1 does not exists. Proceed with creation.....\n"
        echo -e "\t Path $1 does not exists. Proceed with creation.....\n" >> ${path}/scxdatacollector.log
        mkdir -p $1
    fi
}

collect_os_details() {
    echo -e "Collecting OS Details.....\n"
    echo -e "\nCollecting OS Details.....\n" >> ${path}/scxdatacollector.log 
    collect_host_name
    collect_os_version
    collect_compute
    collect_disk_space
    collect_network_details
    collect_openssl_details
    collect_openssh_details sudo
    collect_crypto_details
    check_kerberos_enabled
    collect_selinux_details     
}

collect_host_name() {
    echo -e "\tCollecting HostName Details.....\n"
    echo -e "\tCollecting Hostname Details.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******HOSTNAME******"  > ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
    hostname >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    #below is what SCOM check while creating the self-signed certificate as CN
    echo -e "\n******HOSTNAME FOR CERTS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    nslookuphostname=`nslookup $(hostname) | grep '^Name:' | awk '{print $2}' | grep $(hostname)`
    if [ "${nslookuphostname}" ]; then      
        echo ${nslookuphostname} >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    else
        echo -e "Unable to resolve hostname from nslookup....." >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    fi    
}

collect_os_version(){
    echo -e "\tCollecting OS Details.....\n"
    echo -e "\tCollecting OS Details.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******OS VERSION******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt   
    cat /etc/*release >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt  
}

collect_compute(){
    echo -e "\tCollecting Memory and CPU for omi processes.....\n"
    echo -e "\tCollecting Memory and CPU for omi processes.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******MEM AND CPU FOR OMISERVER PROCESS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt  
    ps -C omiserver -o %cpu,%mem,cmd >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
    echo -e "\n******MEM AND CPU FOR OMIENGINE PROCESS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt  
    ps -C omiengine -o %cpu,%mem,cmd >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
    echo -e "\n******MEM AND CPU FOR OMIAGENT PROCESSES******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
    ps -C omiagent -o %cpu,%mem,cmd >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
}

collect_openssl_details() {
    echo -e "\tCollecting Openssl & Openssh Details.....\n"
    echo -e "\tCollecting Openssl & Openssh Details.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******OPENSSL & OPENSSH VERSION******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    ssh -V  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt  2>&1  
}

collect_openssh_details(){
    echo -e "\tCollecting SSH Details.....\n"
    echo -e "\tCollecting SSH Details.....\n" >> ${path}/scxdatacollector.log
    #checking Kex settings in sshd. We are interested in the sshd server settings.    
    echo -e "\n******SSH DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    echo -e "\n******KEY EXCHANGE ALGORITHIM (KEX) DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 sshd -T | grep -E ^kexalgorithms >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt    
    echo -e "\n******CIPHERS DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 sshd -T | grep ciphers>> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    echo -e "\n******MACS DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 sshd -T | grep macs >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    echo -e "\n******HOST KEY ALGORITHIMS DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    $1 sshd -T | grep keyalgorithms >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    #copy the sshd configuration file
    echo -e "\n******Copying sshd config file******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    cp /etc/ssh/sshd_config  ${path}/SCOMLinuxDataCollectorData/configfiles/sshd_config_copy
}

collect_disk_space(){
    echo -e "\tCollecting the file system usage.....\n"
    echo -e "\tCollecting the file system usage.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******FILE SYSTEM DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    df -h >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
}

check_kerberos_enabled(){
    #This is not a full proof method as there are 3rd party tools who uses different ways to enable Kerb auth. Need more testing.
    echo -e "\tChecking if Kerberos Authentication is enabled. This might not be 100% accurate....\n"
    echo -e "\tChecking if Kerberos Authentication is enabled. This might not be 100% accurate....\n" >> ${path}/scxdatacollector.log
    if [ -f "/etc/krb5.conf" ]; then
        isKerb=`cat /etc/krb5.conf | grep -E "^default_realm" | wc -l`
        if [ ${isKerb} = 1 ]; then
            echo -e "\t\t Kerberos Authentication is enabled. This might not be 100% accurate....\n"
            echo -e "\t\t Kerberos Authentication is enabled. This might not be 100% accurate....\n" >> ${path}/scxdatacollector.log    
        else
            echo -e "\t\t Kerberos Authentication is not enabled. This might not be 100% accurate....\n"
            echo -e "\t\t Kerberos Authentication is not enabled. This might not be 100% accurate....\n" >> ${path}/scxdatacollector.log 
        fi  
    else
        echo -e "\t\t Kerberos Authentication is not enabled. This might not be 100% accurate....\n"
        echo -e "\t\t Kerberos Authentication is not enabled. This might not be 100% accurate....\n" >> ${path}/scxdatacollector.log
    fi    
}

collect_network_details(){
    echo -e "\tCollecting the network details.....\n"
    echo -e "\tCollecting the network details.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******IP ADDRESS DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/network/ipdetails
    ip addr show >> ${path}/SCOMLinuxDataCollectorData/network/ipdetails
    echo -e "\n******NETSTAT DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/network/ipdetails
    #netstat is a deprecated utility.
    #netstat -anp >> ${path}/SCOMLinuxDataCollectorData/network/netstatdetails
    ss >> ${path}/SCOMLinuxDataCollectorData/network/netstatdetails
}

check_sudo_permission(){    
    account_1=$(echo $1)
    account_2=$(echo $2)

   if (( $# == 1 )); then
        echo -e "Checking the sudo permissions for the account ${account_1}...\n"
        echo -e "Checking the sudo permissions for the account ${account_1}.....\n" >> ${path}/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        echo -e "******SUDO DETAILS FOR ${account_1}*****\n" > ${path}/SCOMLinuxDataCollectorData/sudo/${account_1}        
        sudo -l -U ${account_1} >> ${path}/SCOMLinuxDataCollectorData/sudo/${account_1}
   elif (( $# == 2 )); then
        echo -e "Checking the sudo permissions for the account ${account_1} and ${account_2}...\n"
        echo -e "Checking the sudo permissions for the account ${account_1} and ${account_2}...\n" >> ${path}/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        echo -e "******SUDO DETAILS FOR ${account_1}*****\n" > ${path}/SCOMLinuxDataCollectorData/sudo/${account_1}
        sudo -l -U ${account_1} >> ${path}/SCOMLinuxDataCollectorData/sudo/${account_1}
        echo -e "******SUDO DETAILS FOR ${account_2}*****\n" > ${path}/SCOMLinuxDataCollectorData/sudo/${account_2}
        sudo -l -U ${account_2} >> ${path}/SCOMLinuxDataCollectorData/sudo/${account_2}
   fi    
}

collect_crypto_details(){
    echo -e "\tCollecting Crypto details.....\n"
    echo -e "\tCollecting Crypto details.....\n" >> ${path}/scxdatacollector.log
    if [ "$(which update-crypto-policie 2>/dev/null)" ]; then
        echo -e "\t\t Crypto binary found. Collecting the status....\n" >> ${path}/scxdatacollector.log
        echo -e "*****CRYPTO SETTINGS******\n" >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
        update-crypto-policies --show >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    else
        echo -e "\t\t Crypto binary not found....\n" >> ${path}/scxdatacollector.log
    fi  
}

collect_selinux_details(){
    echo -e "\tCollecting SELinux details.....\n"
    echo -e "\tCollecting SELinux details.....\n" >> ${path}/scxdatacollector.log
    if [ "$(which sestatus 2>/dev/null)" ]; then
        echo -e "\t\t SELInux is installed. Collecting the status....\n" >> ${path}/scxdatacollector.log
        echo -e "\n*****SELinux SETTINGS******\n" >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
        sestatus >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    else
        echo -e "\t\t SELinux is not installed....\n" >> ${path}/scxdatacollector.log
    fi 
}

detect_installer(){
    # If DPKG lives here, assume we use that. Otherwise we use RPM.
    echo -e "Checking installer should be rpm or dpkg.....\n" >> ${path}/scxdatacollector.log 
    type dpkg > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        installer=dpkg
        echo -e "\tFound dpkg installer....\n" >> ${path}/scxdatacollector.log
        check_scx_installed $installer $1
    else
        installer=rpm
        echo -e "\tFound rpm installer......\n" >> ${path}/scxdatacollector.log        
        check_scx_installed $installer $1
    fi
}

check_scx_installed(){
    echo -e "Checking if SCX is installed.....\n"
    echo -e "Checking if SCX is installed.....\n" >> ${path}/scxdatacollector.log
    #we will check if the installer is rpm or dpkg and based on that run the package command.  
    if [ "$installer" = "rpm" ]; then
        scx=`rpm -qa scx 2>/dev/null`   
        if [ "$scx" ]; then
            echo -e "\t SCX package is installed. Collecting SCX details.....\n"
            echo -e "\t SCX package is installed. Collecting SCX details.....\n" >> ${path}/scxdatacollector.log        
            #calling function to gather more information about SCX
            collect_scx_details $2        
        else
            echo -e "SCX package is not installed. Not collecting any further details.....\n" >> ${path}/scxdatacollector.log   
        fi   
    #we will assume if not rpm then dpkg.
    else
        scx=`dpkg -s scx 2>/dev/null`   
        if [ "$scx" ]; then
            echo -e "\t SCX package is installed. Collecting SCX details.....\n"
            echo -e "\t SCX package is installed. Collecting SCX details.....\n" >> ${path}/scxdatacollector.log        
            #calling function to gather more information about SCX
            collect_scx_details $2        
        else
            echo -e "SCX package is not installed. Not collecting any further details.....\n" >> ${path}/scxdatacollector.log   
        fi
    fi
    
    
}

collect_scx_details(){
    scxversion=`scxadmin -version`
    scxstatus=`scxadmin -status`
    #netstat is a deprecated utility
    #netstat=`netstat -anp | grep :1270`
    netstat=`ss -lp | grep -E ":opsmgr|:1270"`
    omiprocesses=`ps -ef | grep [o]mi | grep -v grep`
    omidstatus=`systemctl status omid`     
    echo -e "*****SCX VERSION******\n" > ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "${scxversion}\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "*****SCX STATUS******\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "${scxstatus}\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "*****SCX PORT STATUS******\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "${netstat}\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "*****OMI PROCESSES******\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "${omiprocesses}\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "*****OMID STATUS******\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "${omidstatus}\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt

    #unable to figure out the redirection for now
    #if the omiserver is stopped then we need to check the status by running the utility
    #omiserverstatus=`/opt/omi/bin/omiserver` 
    #echo -e "omiserver status:\n $omiserverstatus\n" >> ${path}/scxdatacollector.log

    collect_scx_config_files
    collect_omi_scx_logs
    collect_omi_scx_certs
    collect_scx_directories_structure $1
    collect_omi_pam
    collect_scx_provider_status
    check_omi_core_files
}

collect_scx_config_files(){
    echo -e "\t Copying config files.....\n"
    echo -e "\t Copying config files.....\n" >> ${path}/scxdatacollector.log
    cp -f /etc/opt/omi/conf/omiserver.conf ${path}/SCOMLinuxDataCollectorData/configfiles/omiserver_copy.conf
}

collect_omi_scx_logs(){
    echo -e "\t Collecting details of OMI and SCX logs.....\n"
    echo -e "\t Collecting details of OMI and SCX logs.....\n" >> ${path}/scxdatacollector.log
    omilogsetting=`cat /etc/opt/omi/conf/omiserver.conf | grep -i loglevel`
    echo -e "*****OMI LOG SETTINGS******\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "$omilogsetting \n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    scxlogsetting=`scxadmin -log-list`
    echo -e "*****SCX LOG SETTINGS******\n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt
    echo -e "$scxlogsetting \n" >> ${path}/SCOMLinuxDataCollectorData/SCXDetails.txt    
 
    echo -e "\t Copying OMI and SCX logs.....\n"
    echo -e "\t Copying OMI and SCX logs.....\n" >> ${path}/scxdatacollector.log
    count1=`ls -1 /var/opt/omi/log/*.log  2>/dev/null | wc -l`
    if [ ${count1} != 0 ]; then
      echo -e "\t\t Found .log files in path /var/opt/omi/log. Copying the logs.. \n" >> ${path}/scxdatacollector.log
      cp -f /var/opt/omi/log/*.log ${path}/SCOMLinuxDataCollectorData/logs
    else
      echo -e "\t\t No .log files found in path /var/opt/omi/log. No action needed....\n" >> ${path}/scxdatacollector.log
    fi

    count2=`ls -1 /var/opt/omi/log/*.trc  2>/dev/null | wc -l`
    if [ ${count2} != 0 ]; then
        echo -e "\t\t Found .trc files in path /var/opt/omi/log. Copying the logs.. \n" >> ${path}/scxdatacollector.log
        cp -f /var/opt/omi/log/*.trc ${path}/SCOMLinuxDataCollectorData/logs
    else
        echo -e "\t\t No .trc files found in path /var/opt/omi/log. No action needed.... \n" >> ${path}/scxdatacollector.log
    fi

    count3=`ls -1 /var/opt/microsoft/scx/log/*.log  2>/dev/null | wc -l`
    if [ ${count3} != 0 ]; then
        echo -e "\t\t Found .log files in path /var/opt/microsoft/scx/log/*.log. Copying the logs.. \n" >> ${path}/scxdatacollector.log
        cp -f /var/opt/microsoft/scx/log/*.log ${path}/SCOMLinuxDataCollectorData/logs
    else
        echo -e "\t\t No .log files found in path /var/opt/microsoft/scx/log/*.log. No action needed.... \n" >> ${path}/scxdatacollector.log
    fi    
}

collect_omi_scx_certs(){
    echo -e "\t Collecting SCX cert details.....\n"
    echo -e "\t Collecting SCX cert details.....\n" >> ${path}/scxdatacollector.log

    #checking omi certs
    if [ -d "/etc/opt/omi/ssl/" ]; then
      echo -e "\t \t Path /etc/opt/omi/ssl exists. Dumping details.....\n" >> ${path}/scxdatacollector.log
      #dumping the list of files as the soft links can be broken at times of the permissions might be messed
      echo -e "\n******OMI CERTS STRUCTURE******\n" >> ${path}/SCOMLinuxDataCollectorData/certs/certlist.txt
      ls -l /etc/opt/omi/ssl/ >> ${path}/SCOMLinuxDataCollectorData/certs/certlist.txt            

      cert=`ls /etc/opt/omi/ssl/`      
      omipubliccertsoftlink=`find /etc/opt/omi/ssl | grep omi.pem`
      
      #checking the omi.pem
        if [ -f ${omipubliccertsoftlink} ]; then
            echo -e "\t \t omi public cert exists.....\n" >> ${path}/scxdatacollector.log
        else
            echo -e "\t \t omi public cert does not exists.....\n" >> ${path}/scxdatacollector.log
        fi          
    else
      echo -e "\t \t Path /etc/opt/omi/ssl does not exists.....\n" >> ${path}/scxdatacollector.log
    fi

    #checking scx certs
    if [ -d "/etc/opt/microsoft/scx/ssl/" ]; then
        echo -e "\t \t Path /etc/opt/microsoft/scx/ssl/ exists. Dumping details.....\n" >> ${path}/scxdatacollector.log
        echo -e "\n******SCX CERT STRUCTURE******\n" >> ${path}/SCOMLinuxDataCollectorData/certs/certlist.txt
        ls -l /etc/opt/microsoft/scx/ssl/ >> ${path}/SCOMLinuxDataCollectorData/certs/certlist.txt

        scxpubliccertsoftlink=`find /etc/opt/microsoft/scx/ssl | grep scx.pem`
        #checking the scx.pem
        #dumping scx.pem as SCOM uses it.
        if [ -f ${scxpubliccertsoftlink} ]; then
            echo -e "\t \t scx public cert exists..Dumping details.....\n" >> ${path}/scxdatacollector.log
            openssl x509 -in /etc/opt/microsoft/scx/ssl/scx.pem -text > ${path}/SCOMLinuxDataCollectorData/certs/certdetails_long.txt
            openssl x509 -noout -in /etc/opt/microsoft/scx/ssl/scx.pem  -subject -issuer -dates > ${path}/SCOMLinuxDataCollectorData/certs/certdetails_short.txt
        else
            echo -e "\t \t scx public cert does not exists.....\n" >> ${path}/scxdatacollector.log
        fi
    else
        echo -e "\t \t Path Path /etc/opt/microsoft/scx/ssl/ does not exists.....\n" >> ${path}/scxdatacollector.log
    fi  
}

collect_scx_directories_structure(){
    echo -e "\t Collecting SCX DirectoryStructure.....\n"
    echo -e "\t Collecting SCX DirectoryStructure.....\n" >> ${path}/scxdatacollector.log    
    $1 ls -lR /var/opt/microsoft/ >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/var-opt-microsoft
    $1 ls -lR /var/opt/omi >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/var-opt-omi
    $1 ls -lR /opt/omi/ >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/opt-omi
    $1 ls -lR /etc/opt/microsoft/ >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/etc-opt-microsoft
    $1 ls -lR /etc/opt/omi >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/etc-opt-omi
}

collect_omi_pam(){
    echo -e "\t Collecting omi PAM details.....\n"
    echo -e "\t Collecting omi PAM details.....\n" >> ${path}/scxdatacollector.log
    if [ -f /etc/opt/omi/conf/pam.conf ]; then
        # PAM configuration file found; use that
        cp /etc/opt/omi/conf/pam.conf ${path}/SCOMLinuxDataCollectorData/pam/pam.conf
    elif [ -f /etc/pam.d/omi ]; then
        cp /etc/pam.d/omi ${path}/SCOMLinuxDataCollectorData/pam/omi
    fi
}

collect_scx_provider_status(){
   echo -e "\t Collecting SCX Provider Details.....\n"
   echo -e "\t Collecting SCX Provider Detail.....\n" >> ${path}/scxdatacollector.log
   if [ -d "/etc/opt/omi/conf/omiregister" ]; then
      echo -e "\t\t omiregister directory found. Collecting more details.....\n" >> ${path}/scxdatacollector.log
      cp /etc/opt/omi/conf/omiregister/root-scx/* ${path}/SCOMLinuxDataCollectorData/scxprovider
   else
      echo -e "\t\t omiregister directory not found......\n" >> ${path}/scxdatacollector.log
   fi

   echo -e "\t\t Query the omi cli and dumping details for one class from each identity (root, req, omi).....\n" >> ${path}/scxdatacollector.log
   #We cam think of dumping all the class information if required.
   #However, we need to keep in mind if the provider is hung then we can to kill the query after sometime. That logic has to be built later.
   /opt/omi/bin/omicli ei root/scx SCX_UnixProcess >> ${path}/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus
   /opt/omi/bin/omicli ei root/scx SCX_Agent >> ${path}/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus
   /opt/omi/bin/omicli ei root/scx SCX_OperatingSystem >> ${path}/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus
}

check_omi_core_files(){
   echo -e "\t Check for core files in SCX directory /var/opt/omi/run/.....\n"
   echo -e "\t Check for core files in SCX directory /var/opt/omi/run/......\n" >> ${path}/scxdatacollector.log

   corefilescount=`ls -1 /var/opt/omi/run/core* 2>/dev/null | wc -l`
    if [ ${corefilescount} != 0 ]; then
      echo -e "\t\t Found core files in path /var/opt/omi/run/. Copying the core files.. \n" >> ${path}/scxdatacollector.log
      cp -f /var/opt/omi/run/core* ${path}/SCOMLinuxDataCollectorData/logs
    else
      echo -e "\t\t No core files found in path /var/opt/omi/run/. No action needed....\n" >> ${path}/scxdatacollector.log
    fi

}

archive_logs () {
   echo -e "\nSuccessfully completed the SCOM Linux Data Collector.....\n" >> ${path}/scxdatacollector.log
   if [ -f "${path}/SCOMLinuxDataCollectorData.tar.gz" ]; then
      echo -e "\nFile SCOMLinuxDataCollectorData.tar.gz already exist. Cleaning up before new archive.....\n"
      echo -e "\nFile SCOMLinuxDataCollectorData.tar.gz already exist. Cleaning up before new archive.....\n"  >> ${path}/scxdatacollector.log
      rm -rf ${path}/SCOMLinuxDataCollectorData.tar.gz

   fi
   echo -e "Moving the scxdatacollector.log file to SCOMLinuxDataCollectorData. Archiving and zipping SCOMLinuxDataCollectorData. Clean up other data...."
   echo -e "Moving the scxdatacollector.log file to SCOMLinuxDataCollectorData. Archiving and zipping SCOMLinuxDataCollectorData. Clean up other data...." >> ${path}/scxdatacollector.log
   echo -e "\n $(date) Successfully completed the SCOM Linux Data Collector steps. Few steps remaining....\n" >> ${path}/scxdatacollector.log
   mv ${path}/scxdatacollector.log ${path}/SCOMLinuxDataCollectorData
   tar -cf ${path}/SCOMLinuxDataCollectorData.tar ${path}/SCOMLinuxDataCollectorData  
 
   gzip ${path}/SCOMLinuxDataCollectorData.tar
   rm -rf ${path}/SCOMLinuxDataCollectorData.tar
   rm -rf ${path}/SCOMLinuxDataCollectorData
}

#this function fetches the maximum information
sub_main_root(){    
    check_dir $path
    collect_os_details
    check_sudo_permission $maint $mon
    detect_installer
    #This has to be the last function call in the script
    archive_logs
}

#this function fetches the less information
sub_main_non_root(){
    check_dir $path
    collect_os_details
    check_sudo_permission $maint $mon
    detect_installer sudo
    #This has to be the last function call in the script
    archive_logs
}

main(){
    echo -e "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    #clearing the scxdatacollector.log file to start with
    #using sudo out-of-box even if the user is root to avoid permission denied on the intial log file creation.
    sudo echo "" > ${path}/scxdatacollector.log
    
    if [ ! -n "${path}"  ]; then          
        #echo -e "Log Collection Path is NULL. Setting Path to current working directory......\n"
        echo -e "Log Collection Path is NULL. Setting Path to current working directory......\n" >> ${path}/scxdatacollector.log
        path=`pwd`
    fi

    #Currently supporting SCX 2016+ versions    
    echo -e "Starting the SCOM Linux Data Collector.....\nDisclaimer: Currently supporting SCX 2016+ versions\n"
    echo -e "$(date) Starting the SCOM Linux Data Collector.....\n" > ${path}/scxdatacollector.log
    echo -e "The arguments passed are: \n Path = ${path} \n Maint = ${maint} \n Mon = ${mon} \n"
    echo -e "The arguments passed are: \n Path = ${path} \n Maint = ${maint} \n Mon = ${mon} \n" >> ${path}/scxdatacollector.log
    
    #checking the distro. Will only continue in supported distro
    check_distro

    #fetching the user under which the script is running.    
    user=`whoami`
    echo -e "Script is running under user: ${user}.....\n"
    echo -e "Script is running under user: ${user}.....\n" >> ${path}/scxdatacollector.log
    if [ $user == 'root' ]; then
         echo -e "\t User is root. Collecting maximum information.....\n" 
         sub_main_root $path $maint $mon    
    else
         echo -e "\t User is non root. Collecting information based on the level of privilege.....\n"
         sub_main_non_root $path $maint $mon
    fi 
}

############################################################
# Script execution starts from here.                       #
############################################################


############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts "ho:m:n:" option; do
   case $option in
      h) # display Help      
         help
         exit;;
      o) # Enter log collection path
         path=$OPTARG
         ;;
      m) # Enter log collection path
         maint=$OPTARG
         ;;
      n) # Enter log collection path
         mon=$OPTARG
         ;;
     \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done

#function calls
main $path $maint $mon

echo -e "\nSuccessfully completed the SCOM Linux Data Collector.....\n"
echo -e "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"