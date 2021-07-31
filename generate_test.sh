rm -r test
mkdir test
cd test
mkdir nested
cd nested
mkdir nested
cd ..
touch main.cc
printf "#include <stdio.h>\nint main(){int* p = NULL; printf(\"%%d\\\n\", *p);return 0;};\n" > main.cc
cp main.cc nested/main.cc
cp main.cc nested/nested/main.cc
cd ..
