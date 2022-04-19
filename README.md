# SCOM Linux Data Collector

The SCOM Linux Data Collector is a shell script which can be run on Linux Distribution to collect information about the Operating System and the SCOM Linux Agent.\
This tool can be helpful to figure out problems one might encounter during SCOM Linux Agent Installation and Monitoring.\
The tool is Read-Only and does not change the state of the executed machine.

**Usage:  [OPTIONS]**

 Options:\
  -o &emsp; `:outputpath` &emsp; `Specify the location of collection. If not specified, it will collect the data in the current working directory.`\
  -m &emsp; `:scxmaintenanceaccount` &emsp;`Specify the SCX Maintenance Account. This will be used to check the sudo privilege for the account.`\
  -n &emsp; `:scxmonitoringaccount` &emsp;`Specify the SCX Monitoring Account. This will be used to check the sudo privilege for the account.`

**Example**

`\# bash SCOMLinuxDataCollector.sh -o [output directory] -m [scom maintenance account] -n [scom monitoring account]`\
e.x: `\# bash SCOMLinuxDataCollector.sh -o /tmp -m scxmaint -n scxmon`

**Output**

The output will be a zipped file with the name **SCOMLinuxDataCollectorData.tar.gz**

