make clean
rm testfile.check
make
cp gatorcrypt testfile.check
./gatorcrypt testfile.check -l
rm testfile.check
./gatordec testfile.check.uf -l
diff testfile.check gatorcrypt
make clean
rm testfile.check