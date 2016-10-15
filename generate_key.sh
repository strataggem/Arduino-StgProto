dd if=/dev/urandom of=$1 bs=16 count=1 > /dev/null 2>&1
echo "Your key as hex is"
cat $1|xxd -p -g 1
echo "Use the following key in Arduino IDE"
xxd -i $1
