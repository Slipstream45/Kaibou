# Kaibou


![image](https://user-images.githubusercontent.com/55631460/210168822-30fe5514-e4a8-43b8-890d-1cc6c80e3206.png)

Kaibou is a security tool which finds out security configurations the target binary was compiled with, for example if ASLR is enabled or not or if DEP is enabled.
In addition to this it also lists the sections on which we have what permissions, Read-Write-Execute.
To run the python file you'd need the "pefile" python module. This can be done by running `pip install pefile` and then running the tool as `Kaibou.py <C:\Path\to\Target\Binary.exe`
This project was inspired by checksec which does similar stuff on Linux ELF bins.
