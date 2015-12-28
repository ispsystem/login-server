#!/bin/sh

if [ -z "${log}" ]; then
	log=/tmp/ssh.log
fi
if [ -z "${logdir}" ]; then
	logdir=/tmp/sshlogs
fi

test -d ${logdir} || mkdir -p ${logdir}

if [ -n "${keyfile}" ]; then
	keyopt="-i ${keyfile}"
fi

shift #removing -c
set $@ #redefine
if [ "${1}" = "go" ]; then
	IP_ADDR="${2}"
	shift 2
else
	IP_ADDR="${1}"
	shift
fi


remoteip=`echo $SSH_CONNECTION | cut -d " " -f 1` 

COMMAND="$@"
echo "`date` :: ${remoteip} : ${USER} :: ${SSH_CONNECTION} :: LOGIN  to ${IP_ADDR}" >> ${log}
echo "`date` :: ${remoteip} : ${USER} :: ${SSH_CONNECTION} :: RUN $@ on ${IP_ADDR}" >> ${log}
ssh -o StrictHostKeyChecking=no ${keyopt} root@"${IP_ADDR}" $@ | tee -a ${logdir}/${remoteip}
echo "`date` :: ${remoteip} : ${USER} :: ${SSH_CONNECTION} :: LOGOUT to ${IP_ADDR}" >> ${log}
