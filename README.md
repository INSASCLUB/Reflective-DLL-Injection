### What is Reflective DLL Injection?

DLL (Dynamic-link library) are the Microsoft’s implementation of the shared library concept and provide a mechanism for shared code and data, allowing a developer of shared code/data to upgrade functionality without requiring applications to be re-linked or re-compiled.

DLLs may be explicitly loaded at run-time, a process referred to simply as run-time dynamic linking by Microsoft, and its code is usually shared among all the processes that use the same DLL.

This method can also used to perform a DLL injection, that inserts code in the context of another process by causing the other process to load and execute code.

The code is inserted in the form of a DLL, since DLLs are meant to be loaded at run time.
Running code in the context of another process provides adversaries many benefits, such as access to the process’s memory and permissions.
