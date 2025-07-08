# Process Setup
The screenshot below shows a suspended notepad.exe process (highlighted in gray within Process Hacker), which has been successfully created. Memory has been allocated within the address space of notepad.exe, and the decrypted shellcode has been written into this allocated region. This prepares the process, and specifically its main thread, for Asynchronous Procedure Call (APC) injection. An APC has been queued to the suspended main thread, and upon resuming the thread, the APC will execute, triggering the injected shellcode.
![image](https://github.com/user-attachments/assets/324fe81e-b4c4-4210-bc0d-3179b81c11aa)

# Resuming Thread
In the screenshot below, the thread has been resumed and a call back to our netcat listener has been received. 
![image](https://github.com/user-attachments/assets/6a4c5d30-9955-412b-8a5f-3981c19ecdf3)
