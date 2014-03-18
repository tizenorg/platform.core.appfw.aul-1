source /etc/tizen-platform.conf
usage()
{
	echo "---------------------------------"
	echo "aul_service_test.sh service_name"
	echo "---------------------------------"
}

if [ -z $1 ] 
then
	echo "service name is NULL"
	usage
	exit
fi

sqlite3 $TZ_SYS_DB/.mida.db "insert into system_svc(svc_name) values ('$1')"
