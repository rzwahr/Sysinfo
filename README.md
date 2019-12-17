How to use Sysinfo
==================

Sysinfo repository site is https://github.com/rzwahr/Sysinfo

1.  Download the zip file from Github at <https://github.com/rzwahr/sysinfo>  
    Click the green “clone or download” button, then click Download Zip.

2.  Extract the zip file and rename the unzipped folder from Sysinfo-master to
    Sysinfo. You will copy this folder to your destination from where you want
    to run the script, typically the server desktop.

3.  Copy and paste this folder to the servers desktop. You will need to run this
    script from a domain controller since it uses the ActiveDirectory module
    that is typically only installed on Domain Controllers.

4.  Open up the Sysinfo folder and double-click the Powershell.lnk shortcut.
    This will launch a Powershell console session with the proper permissions.

5.  At the Powershell prompt, type:  
      
    C:\\\> .\\get-sysinfo.ps1

6.  Press Enter, and the script will run. It should output the following files
    in the Sysinfo directory  
      
    - One file per each server named *Servername-sysinfo.txt*  
    - One file named *Workstations.txt*

7.  Copy and paste the above-mentioned files from the Sysinfo folder to the
    destination where you wish to store them on your PC.

8.  Close the Sysinfo folder, then right click the Sysinfo folder icon on the
    desktop, hold down shift then click Delete. This will permanently delete the
    folder.
