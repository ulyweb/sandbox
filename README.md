# Windows Sandbox (WSB)
Microsoft Windows Sandbox
Windows Sandbox (WSB) offers a lightweight, isolated desktop environment for safely running applications




### The Correct Method: Using a Sandbox Configuration File

To enable networking and clipboard redirection, create a plain text file with a `.wsb` extension (for example, `MySandbox.wsb`). This file tells the Sandbox how to configure itself on startup.

#### 1\. Create the Configuration File

Open a text editor like Notepad and paste the following code:

```xml
<Configuration>
  <Networking>Enable</Networking>
  <ClipboardRedirection>Enable</ClipboardRedirection>
</Configuration>
```

#### 2\. Save the File

Save the file with a **`.wsb`** extension. For example, save it as `MySandbox.wsb`.

#### 3\. Run the Sandbox

Double-click the `MySandbox.wsb` file. The Microsoft Sandbox will launch with networking and clipboard redirection enabled.


-----



### The Registry Method (Not Recommended) ⚠️

If you still prefer to modify the registry, here are the keys you'd need to change. **Be aware that editing the registry can have unintended consequences, and changes may not persist across Sandbox sessions.**

#### 1\. Networking

To enable networking, you'd modify the following registry key:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Sandbox
```

Within this key, you'd look for a DWORD value named `AllowNetwork`. To enable networking, set its value to `1`. If the key or value doesn't exist, you'll need to create it.

#### 2\. Clipboard Redirection

For clipboard redirection, the key is the same:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Sandbox
```

Here, you'd look for a DWORD value named `AllowClipboardRedirection`. Set its value to `1` to enable it. Again, if it doesn't exist, you'd have to create it.

-----

````
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Sandbox" /v AllowNetwork /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Sandbox" /v AllowClipboardRedirection  /t REG_DWORD /d 1 /f
````

  * **Temporary and Safe:** The changes are only active for that specific Sandbox session, preserving the security of your main system.
  * **Easy to Use:** It's a simple text file you can share with others or modify as needed.
  * **Avoids System-Wide Changes:** You don't risk altering other system settings or policies.
