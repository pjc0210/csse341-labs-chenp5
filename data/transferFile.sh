#/bin/bash
ROSE_USER="chenp5"
LAB_NUM=0
FILENAME=""
PATH_TO_GIT_REPO="csse341-labs-chenp5"
read -p "Enter lab number: " LAB_NUM 

read -p "Enter filename: " FILENAME

if (( LAB_NUM < 10 )); then
    LAB_NUM="0$LAB_NUM"
fi


scp netsec:~/${PATH_TO_GIT_REPO}/${LAB_NUM}_lab${LAB_NUM}/volumes/${FILENAME} ~/${FILENAME}
if [ $? -ne 0 ]; then
    echo "Error: scp failed to copy ${FILENAME}" >&2
    exit $?
fi
mv ~/${FILENAME} /mnt/c/Users/${ROSE_USER}/Downloads/ > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "Failed to move ${FILENAME} maybe its open in a program?" >&2
    exit $?
fi
