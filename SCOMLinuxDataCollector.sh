#! /bin/sh

#Author : Udish Mudiar(udmudiar@microsoft.com), Microsoft Customer Service Support Professional
#This script is written for data collection from Linux machines which can help in troubleshooting SCOM UNIX/LINUX Agent (SCXAgent)

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

CheckParamteres(){
    #checking the number of parameters passed
    #we expect either 1 or 2 parameters which are the SCOM mmaintenance and monitoring account
    #if the parameters passed are greater than 2 then it is advised that you recheck the SCOM Run As Account and Profiles for streamlining your configuration.
    #you can refer tot he below blog
    #https://udishtech.com/how-to-configure-sudoers-file-for-scom-monitoring/
    if [ $# == 1 ]; then
        echo -e "The argument is: $1.....\n"
        echo -e "The argument is: $1.....\n" >> ${path}/scxdatacollector.log
        CreateDir "${path}/SCOMLinuxDataCollectorData/sudo"
        CheckSudoPermission $1
    elif [ $# == 2 ]; then
        echo -e "The arguments are : $1 and $2.....\n"
        echo -e "The arguments are : $1 and $2.....\n" >> ${path}/scxdatacollector.log
        CreateDir "${path}/SCOMLinuxDataCollectorData/sudo"
        CheckSudoPermission $1 $2
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

CheckDir() {
    pwd=`pwd`
    echo -e "Logs will be created in the current working directory i.e. ${pwd} .....\n"
    echo -e "Logs will be created in the current working directory i.e. ${pwd} .....\n" >> ${path}/scxdatacollector.log
    echo -e "Creating the directory strucuture to store the data from the collector.....\n"
    echo -e "Creating the directory strucuture to store the data from the collector.....\n" >> ${path}/scxdatacollector.log

    if [ -d "${path}/SCOMLinuxDataCollectorData" ]; then
        echo -e "\t Path ${pwd} is present in the current working directory. Removing and recreating the directory.....\n"
        echo -e "\t Path ${pwd} is present in the current working directory. Removing and recreating the directory.....\n" >> ${path}/scxdatacollector.log
        rm -rf ${path}/SCOMLinuxDataCollectorData
        CreateDir "${path}/SCOMLinuxDataCollectorData"
    else
        echo -e "\t Path ${pwd} is not present in the current working directory. Creating the directory.....\n"
        echo -e "\t Path ${pwd} is not present in the current working directory. Creating the directory.....\n" >> ${path}/scxdatacollector.log
        CreateDir "${path}/SCOMLinuxDataCollectorData"
    fi 
    
    CreateDir "${path}/SCOMLinuxDataCollectorData/logs"
    CreateDir "${path}/SCOMLinuxDataCollectorData/certs"
    CreateDir "${path}/SCOMLinuxDataCollectorData/network"    
    CreateDir "${path}/SCOMLinuxDataCollectorData/scxdirectorystructure"
    CreateDir "${path}/SCOMLinuxDataCollectorData/pam"
    CreateDir "${path}/SCOMLinuxDataCollectorData/scxprovider"
    CreateDir "${path}/SCOMLinuxDataCollectorData/configfiles"
}

CreateDir(){    
    
    if [ -d $1 ]; then        
        echo -e "\t Path ${path} exists. No action needed......\n"
        echo -e "\t Path ${path} exists. No action needed......\n" >> ${path}/scxdatacollector.log
    else        
        echo -e "\t Path ${path} does not exists. Proceed with creation.....\n"
        echo -e "\t Path ${path} does not exists. Proceed with creation.....\n" >> ${path}/scxdatacollector.log
        mkdir -p $1
    fi
}

CollectOSDetails() {
    echo -e "Collecting OS Details.....\n"
    echo -e "\nCollecting OS Details.....\n" >> ${path}/scxdatacollector.log 
    CollectHostName
    CollectOSVersion
    CollectCompute
    CollectDiskSpace
    CollectNetworkDetails
    CollectOpensslDetails
    CollectSSHDetails
    CollectCryptoDetails
    CheckIsKerberosEnabled
    CollectSELinuxDetails     
}

CollectHostName() {
    echo -e "\tCollecting HostName Details.....\n"
    echo -e "\tCollecting Hostname Details.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******HOSTNAME******"  > ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
    hostname >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    #below is what SCOM check while creating the self-signed certificate as CN
    echo -e "\n******HOSTNAME FOR CERTS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    nslookuphostname=`nslookup $(hostname) | grep '^Name:' | awk '{print $2}' | grep $(hostname)`
    if [ "${nslookuphostname}" ]; then      
        ${nslookuphostname} >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    else
        echo -e "Unable to resolve hostname from nslookup....." >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    fi    
}

CollectOSVersion(){
    echo -e "\tCollecting OS Details.....\n"
    echo -e "\tCollecting OS Details.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******OS VERSION******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt   
    cat /etc/*release >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt  
}

CollectCompute(){
    echo -e "\tCollecting Memory and CPU for omi processes.....\n"
    echo -e "\tCollecting Memory and CPU for omi processes.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******MEM AND CPU FOR OMISERVER PROCESS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt  
    ps -C omiserver -o %cpu,%mem,cmd >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
    echo -e "\n******MEM AND CPU FOR OMIENGINE PROCESS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt  
    ps -C omiengine -o %cpu,%mem,cmd >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
    echo -e "\n******MEM AND CPU FOR OMIAGENT PROCESSES******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
    ps -C omiagent -o %cpu,%mem,cmd >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt 
}

CollectOpensslDetails() {
    echo -e "\tCollecting Openssl & Openssh Details.....\n"
    echo -e "\tCollecting Openssl & Openssh Details.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******OPENSSL & OPENSSH VERSION******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    ssh -V  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt  2>&1  
}

CollectSSHDetails(){
    echo -e "\tCollecting SSH Details.....\n"
    echo -e "\tCollecting SSH Details.....\n" >> ${path}/scxdatacollector.log
    #checking Kex settings in sshd. We are interested in the sshd server settings.    
    echo -e "\n******SSH DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    echo -e "\n******KEY EXCHANGE ALGORITHIM (KEX) DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    sshd -T | grep -E ^kexalgorithms >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt    
    echo -e "\n******CIPHERS DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    sshd -T | grep ciphers>> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    echo -e "\n******MACS DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    sshd -T | grep macs >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    echo -e "\n******HOST KEY ALGORITHIMS DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    sshd -T | grep keyalgorithms >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
}

CollectDiskSpace(){
    echo -e "\tCollecting the file system usage.....\n"
    echo -e "\tCollecting the file system usage.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******FILE SYSTEM DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
    df -h >> ${path}/SCOMLinuxDataCollectorData/OSDetails.txt
}

CheckIsKerberosEnabled(){
    #This is not a full proof method as there are 3rd party tools who uses different ways to enable Kerb auth. Need more testing.
    echo -e "\tChecking if Kerberos Authentication is enabled. This might not be 100% accurate....\n"
    echo -e "\tChecking if Kerberos Authentication is enabled. This might not be 100% accurate....\n" >> ${path}/scxdatacollector.log
    isKerb=`cat /etc/krb5.conf | grep -E "^default_realm" | wc -l`
    if [ ${isKerb} == 1 ]; then
        echo -e "\t\t Kerberos Authentication is enabled. This might not be 100% accurate....\n"
        echo -e "\t\t Kerberos Authentication is enabled. This might not be 100% accurate....\n" >> ${path}/scxdatacollector.log    
    else
        echo -e "\t\t Kerberos Authentication is not enabled. This might not be 100% accurate....\n"
        echo -e "\t\t Kerberos Authentication is not enabled. This might not be 100% accurate....\n" >> ${path}/scxdatacollector.log 
    fi
    
}

CollectNetworkDetails(){
    echo -e "\tCollecting the network details.....\n"
    echo -e "\tCollecting the network details.....\n" >> ${path}/scxdatacollector.log
    echo -e "\n******IP ADDRESS DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/network/ipdetails
    ip addr show >> ${path}/SCOMLinuxDataCollectorData/network/ipdetails
    echo -e "\n******NETSTAT DETAILS******"  >> ${path}/SCOMLinuxDataCollectorData/network/ipdetails
    netstat -anp >> ${path}/SCOMLinuxDataCollectorData/network/netstatdetails
}

CheckSudoPermission(){    
    account_1=$(echo $1)
    account_2=$(echo $2)

   if (( $# == 1 )); then
        echo -e "Checking the sudo permissions for the account ${account_1}...\n"
        echo -e "Checking the sudo permissions for the account ${account_1}.....\n" >> ${path}/scxdatacollector.log
        echo -e "******SUDO DETAILS FOR ${account_1}*****\n" > ${path}/SCOMLinuxDataCollectorData/sudo/${account_1}
        sudo -l -U ${account_1} >> ${path}/SCOMLinuxDataCollectorData/sudo/${account_1}
   elif (( $# == 2 )); then
        echo -e "Checking the sudo permissions for the account ${account_1} and ${account_2}...\n"
        echo -e "Checking the sudo permissions for the account ${account_1} and ${account_2}...\n" >> ${path}/scxdatacollector.log
        echo -e "******SUDO DETAILS FOR ${account_1}*****\n" > ${path}/SCOMLinuxDataCollectorData/sudo/${account_1}
        sudo -l -U ${account_1} >> ${path}/SCOMLinuxDataCollectorData/sudo/${account_1}
        echo -e "******SUDO DETAILS FOR ${account_2}*****\n" > ${path}/SCOMLinuxDataCollectorData/sudo/${account_2}
        sudo -l -U ${account_2} >> ${path}/SCOMLinuxDataCollectorData/sudo/${account_2}
   fi    
}

CollectCryptoDetails(){
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

CollectSELinuxDetails(){
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

CheckIsSCXInstalled(){
    echo -e "Checking if SCX is installed.....\n"
    echo -e "Checking if SCX is installed.....\n" >> ${path}/scxdatacollector.log
    scx=`rpm -qa scx`   
    if [ $scx ]; then
        echo -e "\t SCX package is installed. Collecting SCX details.....\n"
        echo -e "\t SCX package is installed. Collecting SCX details.....\n" >> ${path}/scxdatacollector.log        
        #calling function to gather more information about SCX
        CollectSCXDetails         
    else
        echo -e "SCX package is not installed. Not collecting any further details.....\n" >> ${path}/scxdatacollector.log   
    fi
}

CollectSCXDetails(){
    scxversion=`scxadmin -version`
    scxstatus=`scxadmin -status`
    netstat=`netstat -anp | grep :1270`
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

    CollectSCXConfigFiles
    CollectOmiScxLogsDetails
    CollectCertDetails
    CollectSCXDirectoryStructure
    CollectOmiPam
    CollectSCXProviderDetails
    CheckforCoreFiles
}

CollectSCXConfigFiles(){
    echo -e "\t Copying config files to the current directory.....\n"
    echo -e "\t Copying config files to the current directory.....\n" >> ${path}/scxdatacollector.log
    cp -f /etc/opt/omi/conf/omiserver.conf ${path}/SCOMLinuxDataCollectorData/configfiles/omiserver_copy.conf
}

CollectOmiScxLogsDetails(){
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

CollectCertDetails(){
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

CollectSCXDirectoryStructure(){
    echo -e "\t Collecting SCX DirectoryStructure.....\n"
    echo -e "\t Collecting SCX DirectoryStructure.....\n" >> ${path}/scxdatacollector.log
    ls -lR /var/opt/microsoft/ >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/var-opt-microsoft
    ls -lR /var/opt/omi >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/var-opt-omi
    ls -lR /opt/omi/ >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/opt-omi
    ls -lR /etc/opt/microsoft/ >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/etc-opt-microsoft
    ls -lR /etc/opt/omi >> ${path}/SCOMLinuxDataCollectorData/scxdirectorystructure/etc-opt-omi
}

CollectOmiPam(){
    echo -e "\t Collecting omi PAM details.....\n"
    echo -e "\t Collecting omi PAM details.....\n" >> ${path}/scxdatacollector.log
    if [ -f /etc/opt/omi/conf/pam.conf ]; then
        # PAM configuration file found; use that
        cp /etc/opt/omi/conf/pam.conf ${path}/SCOMLinuxDataCollectorData/pam/pam.conf
    elif [ -f /etc/pam.d/omi ]; then
        cp /etc/pam.d/omi ${path}/SCOMLinuxDataCollectorData/pam/omi
    fi
}

CollectSCXProviderDetails(){
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

CheckforCoreFiles(){
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

ArchiveLogs () {
   echo -e "\nSuccessfully completed the SCOM Linux Data Collector.....\n" >> ${path}/scxdatacollector.log
   echo -e "Moving the scxdatacollector.log file to SCOMLinuxDataCollectorData. Archiving and zipping SCOMLinuxDataCollectorData. Clean up other data....\n"
   echo -e "Moving the scxdatacollector.log file to SCOMLinuxDataCollectorData. Archiving and zipping SCOMLinuxDataCollectorData. Clean up other data....\n" >> ${path}/scxdatacollector.log
   mv ${path}/scxdatacollector.log ${path}/SCOMLinuxDataCollectorData
   tar cf ${path}/SCOMLinuxDataCollectorData.tar ${path}/SCOMLinuxDataCollectorData
   gzip ${path}/SCOMLinuxDataCollectorData.tar
   rm -rf ${path}/SCOMLinuxDataCollectorData.tar
   rm -rf ${path}/SCOMLinuxDataCollectorData
}

#this function fetches the maximum information
SubMainRoot(){
    CheckParamteres $maint $mon
    CheckDir
    CollectOSDetails
    CheckIsSCXInstalled
    #This has to be the last function call in the script
    ArchiveLogs
}

#this function fetches the less information
SubMainNonRoot(){
    CheckParamteres "$@"
    CheckDir    
    CollectHostName
    CollectOSDetails
    CollectCompute
    CollectDiskSpace
    CollectNetworkDetails
    CollectOpensslDetails
    CollectSSHDetails
    CollectCryptoDetails 
    CheckIsKerberosEnabled 
    CheckIsSCXInstalled
}

Main(){

    if [ ! -n "${path}"  ]; then
        path=`pwd`   
        echo -e "Log Collection Path is NULL. Setting Path to current working directory......\n"
        echo -e "Log Collection Path is NULL. Setting Path to current working directory......\n" > ${path}/scxdatacollector.log                                 
    fi

    #Currently supporting SCX 2016+ versions
    echo -e "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    echo -e "Starting the SCOM Linux Data Collector.....\nDisclaimer: Currently supporting SCX 2016+ versions\n"
    echo -e "Starting the SCOM Linux Data Collector.....\n" > ${path}/scxdatacollector.log
    echo -e "The arguments passed are: \n Path = ${path} \n Maint = ${maint} \n Mon = ${mon} \n"
    echo -e "The arguments passed are: \n Path = ${path} \n Maint = ${maint} \n Mon = ${mon} \n" > ${path}/scxdatacollector.log
    

    #fetching the user under which the script is running.    
    user=`whoami`
    echo -e "Script is running under user: ${user}.....\n"
    echo -e "Script is running under user: ${user}.....\n" >> ${path}/scxdatacollector.log
    if [ $user == 'root' ]; then
         echo -e "\t User is root. Collecting maximum information.....\n"
         
         
         SubMainRoot $path $maint $mon    
    else
         echo -e "\t User is non root. Collecting less information.....\n"
         SubMainNonRoot "$@"
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
Main $path $maint $mon

echo -e "\nSuccessfully completed the SCOM Linux Data Collector.....\n"
echo -e "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"