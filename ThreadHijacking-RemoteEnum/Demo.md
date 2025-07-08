# DEMO TIME!!!

## Initial Enumeration
![image](https://github.com/user-attachments/assets/d7745ff8-ddac-4ebd-bb03-78c7f32c812d)

## Allocating Memory and Changing RIP
![image](https://github.com/user-attachments/assets/607455bb-fcec-45f3-bbf2-e56d5da6bba0)
As you can see in the thread stack, the next instruction that will be executed is the base address of where our shellcode is allocated. <br> 
Bonus chalupa points if you can guess what might be wrong the next instruction in the main thread >:)

## Call Back
![image](https://github.com/user-attachments/assets/b726096b-15db-41e4-90ea-0f81157da0ee)
Looking at the thread stack again, shows the allocated memory is gone because it was executed, which gives us a call back to our netcat listener.

