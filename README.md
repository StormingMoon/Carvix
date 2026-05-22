# Carvix
High Speed and Efficient Memory Dump Carving Tool 
While Binwalk is a good extractor it has flaws such as not really being a good RE tool since
it carves a lot of windows specific files and unnecessary data 
Carvix is specialized for carving specific data and unique dlls and jars and assets from MemoryDumps
# Usage
```cmd
Carvix.py yourdmp.dmp -o carved_output --keep-rejects --extract-all-jar-entries
```
# Supported formats
Jar
DLL
PNG,JPG,WEBP and other media 
# Indevelopment
One thing this wont carve outright is encrypted java classes ex (Provided.Space)
also all pull requests and issues are encouraged
