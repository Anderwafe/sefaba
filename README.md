# Stupid Elf File Actions By Anderwafe

This project is an attempt to create reader and writer of elf files. Maybe in the future it will be a part of dynamic linker, or another stuff.

Currently, only ELF Header structures is supported, for ELF32 and ELF64. Single .c file contains structures, arrays for working with elf files, and simple example of how to use it right now. `a.out` file is standart gcc output file without `-o` flag specified.
