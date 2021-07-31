rm -r test
mkdir test
cd test
mkdir nested
cd nested
mkdir nested
cd ..
cd. > main.cc
printf "#include <stdio.h>\nint main(){int* p = NULL; printf(\"%%d\\\n\", *p);return 0;};\n" > main.cc
copy main.cc nested/main.cc
copy main.cc nested/nested/main.cc
cd ..
