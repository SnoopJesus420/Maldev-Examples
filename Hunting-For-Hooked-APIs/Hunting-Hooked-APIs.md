# Intro
A quick overview on hutning for API calls that might be hooked by security solutions. 

# Hunting For Hooked APIs
One way to identify which APIs are hooked by security solutions is to open regular programs such as notepad.exe in a debugger. <br>
In doing so, we can we can look for calls to APIs that have odd looking assembly instructions. 

# Unhooked API Calls
Below is an example of what an unhooked API would look like:
```asm
mov r10,rcx
mov eas,3B
```

# Hooked API
Below is an example of a suspicious jmp instruction:
```asm
jmp 7FFDF7010462
```
Assembly instructions formatted this way that are associated with API calls (in a debugger) typically mean that they're hooked by a security solution. 
