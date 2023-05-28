# check Encoding
lang_check=`locale -a 2>/dev/null | grep "en_US" | egrep -i "(utf8|utf-8)"`
if [ "$lang_check" = "" ];
then 
	lang_check="C"
fi

LANG="$lang_check"
LC_ALL="$lang_check"
LANGUAGE="$lang_check"
export LANG
export LC_ALL
export LANGUAGE

# 루트 권한 실행 여부 확인
if [ "`id | grep \"uid=0\"`" = "" ];
then
	echo "";
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-";
	echo "";
	echo "This script must be run as root";
	echo "";
	echo "진단 스크립트는root권한으로 실행해야 합니다.";
	echo"";
	echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-";
	echo"";
	exit 1;
fi

# netstat와systemctl 명령어 존재 여부 확인
if [ "`command -v netstat 2>/dev/null`" != "" ] || [ "`which netstat 2>/dev/null`" != "" ];
then
	port_cmd="netstat"
else
	port_cmd="ss"
fi

if [ "`command -v systemctl 2>/dev/null`" != "" ] || ["`which systemctl 2>/dev/null`" != "" ];
then
	systemctl_cmd="systemctl"
fi

RESULT_FILE="vuln_`date +\"%Y%m%d%H%M\"`.txt"
GOOD_FILE="./result/good.txt"
BAD_FILE="./result/bad.txt"
CHECK_FILE="./result/check.txt"
# 색깔 환경 변수 설정



RED="\033[1;31m"
PURPLE="\033[1;35m"
GREEN="\033[1;32m"
BG_BLUE="\033[0;44;37m"
COLOR_END="\033[0m"


# 결과 저장할 디렉토리 생성
dirname="./result"
if [ -d $dirname ];then
	echo "result 디렉토리 존재"
else
	echo "result 디렉토리 생성"
	mkdir result
fi

# 결과 판단 함수 정하기

result(){
	if [ $1 -eq 0 ];then
		echo -e "$GREEN[+] [ U-$2 ] 결과값 : 양호$COLOR_END" >> $RESULT_FILE 2>&1
		echo -e "[+] [ U-$2 ] 결과값 : 양호" >> $GOOD_FILE 2>&1
	elif [ $1 -eq 1 ];then
		echo -e "$RED[-] [ U-$2 ] 결과값 : 취약 $COLOR_END" >> $RESULT_FILE 2>&1
		echo -e "[-] [ U-$2 ] 결과값 : 취약" >> $BAD_FILE 2>&1
	else 
		echo -e "$PURPLE[?] [ U-$2 ] 결과값 : 검토 $COLOR_END" >> $RESULT_FILE 2>&1
		echo -e "[?] [ U-$2 ] 결과값 : 검토" >> $CHECK_FILE 2>&1
	fi
}
# 2_8


echo "[Start Script]"
echo "=============Linux Security Check Script Start=============" > $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

echo -e "$RED 1. 계정 관리 $COLOR_END" >> $RESULT_FILE 2>&1

#################################################################
# -주요 정보 통신 기반 시설 계정 관리 U-01 root 계정 원격접속 제한
#################################################################
echo "[ U-01 ] : Check"
echo -e "$BG_BLUE [U-01 root 계정 원격 접속 제한 START] $COLOR_END" >> $RESULT_FILE 2>&1

echo "1. SSH" >> $RESULT_FILE 2>&1
echo "1-1. SSH Process Check" >> $RESULT_FILE 2>&1

get_ssh_ps=`ps -ef | grep -v "grep" | grep "sshd"`

if [ "$get_ssh_ps" != "" ];then
	echo "$get_ssh_ps" >> $RESULT_FILE 2>&1
else
	echo -e "NOt Found Process" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1


# 3_8


echo "1-2. SSH Service Check" >> $RESULT_FILE 2>&1
if [ "$systemctl_cmd" != "" ];
then
	get_ssh_service=`$systemctl_cmd list-units --type service | egrep '(ssh|sshd)\.service' | sed -e 's/^*//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$get_ssh_service" != "" ]; then
		echo "$get_ssh_service" >> $RESULT_FILE 2>&1
	else
		echo "Not Found Service" >> $RESULT_FILE 2>&1
	fi
else
	echo "Not Found systemctl command" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

echo "1-3. SSH Port Check" >> $RESULT_FILE 2>&1
if [ "$port_cmd" != "" ];
then
	get_ssh_port=`$port_cmd -na | grep "tcp" | grep "LISTEN" | grep ':22[ \t]'`
	if [ "$get_ssh_port" != "" ];
	then
		echo "$get_ssh_port" >>$RESULT_FILE 2>&1
	else
		echo "Not Found port" >>$RESULT_FILE 2>&1
	fi
else
	echo "Not Found Port Command" >>$RESULT_FILE 2>&1
fi



# 4_8


if [ "$get_ssh_ps" != "" ] || [ "get_ssh_service" != "" ] || [ "$get_ssh_port" != "" ];
then
	echo "" >> $RESULT_FILE 2>&1
	echo "1-4. SSH Configuration File Check" >> $RESULT_FILE 2>&1
	if [ -f "/etc/ssh/sshd_config" ];
	then
		get_ssh_conf=`cat /etc/ssh/sshd_config | egrep -v '^#|^$' | grep "PermitRootLogin"`
		if [ "$get_ssh_conf" != "" ];
		then
			echo "/etc/ssh_sshd_config : $get_ssh_conf" >> $RESULT_FILE 2>&1
			get_conf_check=`echo "$get_ssh_conf" | awk '{ print $2 }'`
			if [ "$get_conf_check" = "no" ];
			then
				ssh_flag=1
			else
				ssh_flag=0
			fi
		else
			ssh_flag=1
			echo "/etc/ssh/sshd_config : Not Found PermitRootLogin Configuration" >> $RESULT_FILE 2>&1
		fi
	else
		ssh_flag=2
		echo "Not Found SSH Configuration FIle" >>$RESULT_FILE 2>&1
	fi
	echo "" >> $RESULT_FILE 2>&1
else
	ssh_flag=1
fi


# 5_8


echo "2. Telnet" >> $RESULT_FILE 2>&1
echo "2-1. Telnet Process Check" >> $RESULT_FILE 2>&1
get_telnet_ps=`ps -ef | grep -v "grep" | grep "telnet"`
if [ "$get_telnet_ps" != "" ];
then
	echo "$get_telnet_ps" >> $RESULT_FILE 2>&1
else
	echo "Not Found Process" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

echo "2-2. Telnet Service Check" >> $RESULT_FILE 2>&1
if [ "$systemctl_cmd" != "" ];
then
	get_telnet_service=`$systemctl_cmd list-units --type service | egrep '(telnet|telnetd)\.service' | sed -e 's/^ *//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$get_telnet_service" != "" ]; then
		echo "$get_telnet_service" >> $RESULT_FILE 2>&1
	else
		echo "Not Found Service" >>$RESULT_FILE 2>&1
	fi
else
	echo "Not Found systemctl Command" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1




# 6_8


echo "2-3. Telnet Port Check" >> $RESULT_FILE 2>&1

if [ "$port_cmd" != "" ];
then
	get_telnet_port=`$port_cmd -na | grep "tcp" | grep "LISTEN" | grep ':23[ \t]'`
	if [ "$get_telnet_port" != "" ];
	then
		echo "$get_telnet_port" >> $RESULT_FILE 2>&1
	else
		echo "Not Found port" >> $RESULT_FILE 2>&1
	fi
else
	echo "Not Found Port Command" >> $RESULT_FILE 2>&1
fi

if [ "$get_telnet_ps" != "" ] || [ "$get_telnet_service" != "" ] || [ "$get_telnet_port" != "" ];
then
	telnet_flag=0
	echo "" >> $RESULT_FILE 2>&1
	echo "2.4 Telnet Configuration Check" >> $RESULT_FILE 2>&1
	if [ -f "/etc/pam.d/remote" ];
	then
		pam_file="/etc/pam.d/remote"
	elif [ -f "/etc/pam.d/login" ];
	then
		pam_file="/etc/pam.d/login"
	fi
	if [ "$pam_file" != "" ];
	then 
		echo "- $pam_file" >> $RESULT_FILE 2>&1
		get_conf=`cat $pam_file | egrep -v '^#|^$' | grep "pam_securetty.so"`
		if [ "$get_conf" != "" ];
		then	
			echo "$get_conf" >> $RESULT_FILE 2>&1
			if [ -f "/etc/securetty" ];
			then
				echo "- /etc/securetty" >> $RESULT_FILE 2>&1
				echo "`cat /etc/securetty`" >> $RESULT_FILE 2>&1
				get_pts=`cat /etc/securetty | grep -v '^#|^$' | grep "^[ \t]*pts"`
				if [ "$get_pts" = "" ];
				then
					telnet_flag=1
				fi
			else
				echo "Not Found Telnet TTY Configuration File" >> $RESULT_FILE 2>&1	
			fi
		else
			echo "$pam_file :Not Found pam_securetty.so Configuration" >> $RESULT_FILE 2>&1
		fi
	else
		telnet_flag=2
		echo "Not Found Telnet Pam Configuration File" >> $RESULT_FILE 2>&1
	fi
else
	telnet_flag=1
fi


# 8_8


# 취약 :0, 양호 : 1, 검토 :2
if [ $ssh_flag -eq 1 ] && [ $telnet_flag -eq 1 ];
then
	result 0 01
elif [ $ssh_flag -eq 0 ] || [ $telnet_flag -eq 0 ];
then
	result 1 01
elif [ $ssh_flag -eq 2 ] || [ $telnet_flag -eq 2 ];
then
	result 2 01
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
####################################################################
# U-02 패스워드 복잡성 설정
####################################################################
echo "[ U-02 ] : Check"
echo -e "$BG_BLUE [ U-02 패스워드 복잡성 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] /etc/pam.d/system-auth 의 내용을 불러옵니다." >> $RESULT_FILE 2>&1
cracklib_chk=`cat /etc/pam.d/system-auth | grep -v "#" | grep pam_cracklib.so`
if [[ $cracklib_chk  != "" ]];then
	# 정상적으로 설정 파일이 있음
	retry=`cat /etc/pam.d/system-auth | grep pam_cracklib.so | awk -F" {3}" '{ print $3 }' | sed -e 's/ /\n/g' | grep retry | awk -F"=" '{ print $2 }'`
	minlen=`cat /etc/pam.d/system-auth | grep pam_cracklib.so | awk -F" {3}" '{ print $3 }' | sed -e 's/ /\n/g' | grep minlen | awk -F"=" '{ print $2 }'`
	lcredit=`cat /etc/pam.d/system-auth | grep pam_cracklib.so | awk -F" {3}" '{ print $3 }' | sed -e 's/ /\n/g' | grep lcredit | awk -F"=" '{ print $2 }'`
	ucredit=`cat /etc/pam.d/system-auth | grep pam_cracklib.so | awk -F" {3}" '{ print $3 }' | sed -e 's/ /\n/g' | grep minlen | awk -F"=" '{ print $2 }'`
	dcredit=`cat /etc/pam.d/system-auth | grep pam_cracklib.so | awk -F" {3}" '{ print $3 }' | sed -e 's/ /\n/g' | grep minlen | awk -F"=" '{ print $2 }'`
	ocredit=`cat /etc/pam.d/system-auth | grep pam_cracklib.so | awk -F" {3}" '{ print $3 }' | sed -e 's/ /\n/g' | grep minlen | awk -F"=" '{ print $2 }'`
	if [[ $retry -le 5 && $minlen -ge 8 && $lcredit -eq -1 &&  $ucredit -eq -1 && $dcredit -eq -1 && $ocredit -eq -1 ]]; then
		echo "  [+] 복잡성 설정이 정상입니다. " >> $RESULT_FILE 2>&1
		result 0 02
	else
		echo "  [-] 복잡성 설정을 변경해야 합니다." >> $RESULT_FILE 2>&1
		list=`cat /etc/pam.d/system-auth | grep pam_cracklib.so | awk -F" {3}" '{ print $3 }' | sed -e 's/ /\n/g' -e 's/\n\n//g'`
		echo $list >> $RESULT_FILE 2>&1
		result 1 02
	fi
else
	echo "  [-] /etc/pam.d/system-auth 설정파일이 없습니다." >> $RESULT_FILE 2>&1
	result 1 02
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
####################################################################
# -주요 정보 통신 기반 시설 관리 U-46 Password 정책 확인
####################################################################
echo "[ U-46 ] : Check"
echo -e "$BG_BLUE [U-46 패스워드 최소 길이 설정 확인 ] $COLOR_END" >> $RESULT_FILE 2>&1
echo "2.1 비밀 번호 최소 길이 8글자 이상 설정" >> $RESULT_FILE 2>&1
pass_length=`cat /etc/login.defs | grep "PASS_MIN_LEN" | grep -v "#" |awk '{print $2}'`

# 비밀번호 최소 길이 8글자 이상
echo " [*] 현재 설정된 길이 : $pass_length" >> $RESULT_FILE 2>&1
if [ $pass_length -gt 7 ];then
	echo "  [+] 비밀번호 최소 길이가 8글자 이상 설정" >> $RESULT_FILE 2>&1
	result 0 46
else 
	echo "  [-] 비밀번호 최소 길이 8글자 이상 설정 필요" >> $RESULT_FILE 2>&1
	result 1 46
fi
echo "" >> $RESULT_FILE 2>&1
# 비밀번호 기간 만료 경고 7일 설정
echo "2.2 비밀 번호 기간 만료 경고 7일 전 확인" >> $RESULT_FILE 2>&1
pass_alert=`cat /etc/login.defs |grep "PASS_WARN_AGE" | grep -v "#" | awk '{print $2}'`
echo " [*] 현재 설정된 만료 경고일 : $pass_alert" >> $RESULT_FILE 2>&1
if [ $pass_alert -eq 7 ];then
	echo "  [+] 비밀번호 기간 만료 경고 7일전 양호" >> $RESULT_FILE 2>&1
else
	echo "  [-] 비밀번호 기간 만료 경고 7일 설정 필요" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
####################################################################
# U-47 패스워드 최대 사용 기간 설정
####################################################################
echo "[ U-47 ] : Check"
# 비밀번호 최대 사용 기간 60일
echo -e "$BG_BLUE [ U-47  비밀 번호 최대 사용 기간 확인 ] $COLOR_END" >> $RESULT_FILE 2>&1
pass_max=`cat /etc/login.defs | grep "PASS_MAX_DAYS" | grep -v "#" | awk '{print $2}'`
echo " [*] 현재 설정된 최대 사용 기간 :$pass_max" >> $RESULT_FILE 2>&1
if [ $pass_max -le 60 ]; then
	echo "  [+] 패스워드 최대 사용 기간 60일 이하 양호" >> $RESULT_FILE 2>&1
	result 0 47
else 
	echo "  [-] 패스워드 최대 사용 기간 60일 이하 설정 필요" >>$RESULT_FILE 2>&1
	result 1 47

fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
####################################################################
# U-48 패스워드 최소 사용기간 설정
####################################################################
echo "[ U-48 ] : Check"
# 패스워드 최소 사용 기간
echo -e "$BG_BLUE [ U-48 비밀 번호 최소 사용 기간 확인 $COLOR_END" >> $RESULT_FILE 2>&1
pass_min=`cat /etc/login.defs | grep "PASS_MIN_DAYS" | grep -v "#" | awk '{print $2}'`
echo " [*] 현재설정된 최소 사용 기간 : $pass_min" >> $RESULT_FILE 2>&1
if [ $pass_min -ge 1 ]; then
	echo "  [+] 비밀번호 최소 사용기간 1일 이상 양호" >> $RESULT_FILE 2>&1
	result 0 48
else
	echo "  [-] 비밀번호 최소 사용기간 1일 설정 필요" >> $RESULT_FILE 2>&1
	result 1 48

fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
#####################################################################
# U-03 계정 잠금 임계값 설정
#####################################################################
echo "[ U-03 ] : Check"
echo -e "$BG_BLUE [ U-03 계정 잠금 임계값 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1
deny_check(){
    deny_flag=0

# 로컬 로그인 설정 확인
    system_val=`cat system-auth | grep $pam_file | awk '{ print $4 }' | sed 's/deny=//g'`
    if [ $system_val -le 5 ];then
        echo -e "  [+] 현재 설정된 로컬 로그인 잠금 임계값 : $system_val" >> $RESULT_FILE 2>&1
    else
        echo -e "  [-] 현재 설정된 로컬 로그인 잠금 임계값 : $system_val" >> $RESULT_FILE 2>&1
        deny_flag+=1
    fi

    # 원격 로그인 설정 확인
    password_val=`cat password-auth | grep $pam_file | awk '{ print $4 }' | sed 's/deny=//g'`
    if [ $system_val -le 5 ];then
        echo -e "  [+] 현재 설정된 로컬 로그인 잠금 임계값 : $system_val" >> $RESULT_FILE 2>&1
    else
        echo -e "  [-] 현재 설정된 로컬 로그인 잠금 임계값 : $system_val" >> $RESULT_FILE 2>&1
        deny_flag+=1
    fi
    
    if [ $deny_flag -ne 0 ];then
        result 1 03
    else
        result 0 03
	fi
}

# 사용중인 모듈 확인
pam_file=pam_tally.so
if [ -f /etc/pam.d/$pam_file ]; then
	echo -e " [*] 잠금 임계값 설정 모듈 : $pam_file" >> $RESULT_FILE 2>&1
	deny_check
elif [ -f /etc/pam.d/pam_tally2.so ]; then
	pam_file=pam_tally2.so
	echo -e " [*] 잠금 임계값 설정 모듈 : $pam_file" >> $RESULT_FILE 2>&1
	deny_check
else
	echo -e " [-] PAM 설정 파일이 없습니다." >> $RESULT_FILE 2>&1
	result 1 03
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
#####################################################################
# U-04 비밀번호 파일 보호
#####################################################################
echo "[ U-04 ] : Check"
echo -e "$BG_BLUE [ U-04 비밀번호 파일 보호 ]$COLOR_END">> $RESULT_FILE 2>&1

shadow=`ls /etc | grep -x "shadow"| wc -l`
passwd_wc=`cat /etc/passwd | awk -F":" '{ print $1 }'| wc -l`
shadow_wc=`cat /etc/passwd | awk -F":" '{ print $2 }'| grep x | wc -l`


if [ $shadow -eq 1 ]; then
	echo -e " [+] /etc/shadow 파일이 존재합니다." >> $RESULT_FILE 2>&1
	if [ $passwd_wc -eq $shadow_wc ];then
		echo -e " [+] 모든 계정의 비밀번호가 보호되고 있습니다." >> $RESULT_FILE 2>&1
		result 0 04
	else
		echo -e " [-] 적절한 보호가 필요한 계정이 있습니다." >> $RESULT_FILE 2>&1
		result 2 04
	fi
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#####################################################################
# U-44 ROOT 이외의 UID가 0 금지
#####################################################################
echo "[ U-44 ] : Check"
echo -e "$BG_BLUE [ U-44 root 이외 UID 에 '0'설정 금지 ] $COLOR_END" >> $RESULT_FILE 2>&1
uid=`cat /etc/passwd | awk -F":" '$3==0 { print $1 }' | grep -v root`
if [[ $uid !=  "" ]];then
	echo " [-] root 이외에 UID가 0인 계정이 존재합니다." >> $RESULT_FILE 2>&1
	result 1 44
else
	echo " [+] root 이외에 UID가 0인 계정이 없습니다." >> $RESULT_FILE 2>&1
	result 0 44
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
#####################################################################
# U-45 root 계정 su 제한
#####################################################################
echo -e "$BG_BLUE [ U-45 root 계정 su 제한 ]$COLOR_END">> $RESULT_FILE 2>&1
# 1. wheel 그룹 내에 구성원이 존재 하는지 확인(공통)
grp_wheel=`cat /etc/group | grep wheel | awk -F":" '{ print $4 }'`

if [[ $grp_wheel != "" ]];then
    echo " [+] wheel 그룹의 su 가능한 사용자 목록 : $grp_wheel" >> $RESULT_FILE 2>&1
	# Wheel 모듈 사용 여부 확인
	pam_use=`cat /etc/pam.d/su | grep -v "#" | grep pam_wheel.so | sed 's/\t/:/g' | awk -F":" '{ print $4 }'`
	if [[ $pam_use != "" ]]; then
		echo " [+] pam_wheel.so 정상 설정 상태입니다." >> $RESULT_FILE 2>&1
		result 0 45
	else
		# Wheel 모듈 미사용시
		perm_val=`stat -c '%a' /usr/bin/su`
		sid_perm=`echo "$perm_val" | awk '{ print substr($0, 1, 1) }'`
		own_perm=`echo "$perm_val" | awk '{ print substr($0, 2, 1) }'`
		grp_perm=`echo "$perm_val" | awk '{ print substr($0, 3, 1) }'`
		oth_perm=`echo "$perm_val" | awk '{ print substr($0, 4, 1) }'`

		if [ "$sid_perm" -eq 4 ] && [ "$own_perm" -eq 7 ] && [ "$grp_perm" -eq 5 ] && [ "$oth_perm" -eq 0]; then
			echo " [+] /usr/bin/su 권한 설정 4750 입니다." >> $RESULT_FILE 2>&1
			result 0 45
		else 
			echo " [-] /usr/bin/su 권한 변경 필요, 현재 권한 : $perm_val" >> $RESULT_FILE 2>&1
			result 1 45
		fi

	fi

else 
    echo " [-] wheel 그룹에 SU를 허가할 사용자를 추가하세요!! " >> $RESULT_FILE 2>&1
	result 1 45
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
#####################################################################
#U-49 불필요한 계정 제거 
#####################################################################
echo "[ U-49 ] : CHeck"
echo -e "$BG_BLUE [U-49 불필요한 계정 확인 및 제거] $COLOR_END" >> $RESULT_FILE 2>&1
account=`cat /etc/passwd`
echo "$account">> $RESULT_FILE 2>&1
result 2 49

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#####################################################################
# U-50 관리자 그룹에 최소한의 계정 포함
#####################################################################
echo "[ U-50 ] : Check"
echo -e "$BG_BLUE [U-50 관리자 그룹에 최소한의 계정 포함 ] $COLOR_END" >> $RESULT_FILE 2>&1

group=`cat /etc/group | grep root | awk -F":" '{ print $4 }' | grep -v 'root'`

if [[ $group != "" ]]; then
	echo " [?] root 그룹에 다른 사용자가 포함되어 있습니다." >> $RESULT_FILE 2>&1
	group=`cat /etc/group | grep root`
	echo $group >> $RESULT_FILE 2>&1
	result 2 50
else
	echo " [+] root 그룹의 소속 계정이 root 만 존재합니다." >> $RESULT_FILE 2>&1
	group=`cat /etc/group | grep root`
	echo $group >>$RESULT_FILE 2>&1
	result 0 50
fi
	

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#####################################################################
# U-51 계정이 존재하지 않는 gid 금지
#####################################################################
echo "[ U-51 ] : Check"
echo -e "$BG_BLUE [ U-51 계정이 존재하지 않는 GID 금지 ] $COLOR_END" >> $RESULT_FILE 2>&1

gshadow=`cat /etc/gshadow`
echo "$gshadow" >> $RESULT_FILE 2>&1
result 2 51


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#####################################################################
# U-52 동일한 UID 금지
#####################################################################
echo "[ U-52 ] : Check"
echo -e "$BG_BLUE [ U-52 동일한 UID 금지 ] $COLOR_END" >> $RESULT_FILE 2>&1

unique=`cat /etc/passwd | awk -F":" '{ print $3 }' | uniq -d`
if [[ $unique != "" ]];then
	echo -e " [-] UID가 중복되는 계정이 있습니다!! $COLOR_END" >> $RESULT_FILE 2>&1
	echo "중복되는 UID : $unique" >> $RESULT_FILE 2>&1
else
	echo -e " [+] 중복되는 UID가 없습니다. $COLOR_END" >> $RESULT_FILE 2>&1
	result 0 52
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#####################################################################
# U-53 사용자 SHELL 점검
#####################################################################
echo "[ U-53 ] : Check"
echo -e "$BG_BLUE [ U-53 사용자 Shell 점검 ] $COLOR_END" >> $RESULT_FILE 2>&1

echo "$account" >> $RESULT_FILE 2>&1
result 2 53

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


#####################################################################
# U-54 Session Timeout 시간 설정
#####################################################################
echo "[ U-54 ] : Check"
echo -e "$BG_BLUE [ U-54 Session Timeout 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1
tm=`cat /etc/profile | grep -i tmout= | awk -F"=" '{ print $2 }'`
if [ $tm -le 600 ];then
	echo " [+] 타임 아웃 시간 설정값 : $tm, 양호" >> $RESULT_FILE 2>&1
	result 0 54
else
	echo " [-] 타임 아웃 시간 설정값 : $tm, 재설정 필요" >> $RESULT_FILE 2>&1
	result 1 54
fi
echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


echo -e "$RED 2. 파일 및 디렉터리 관리 $COLOR_END" >> $RESULT_FILE 2>&1
#####################################################################
# U-05 ROOT 홈, 패스 디렉터리 권한 및 패스 설정
#####################################################################
echo "[ U-05 ] : Check"
echo -e "$BG_BLUE [ U-05 홈, 패스 디렉토리 권한 및 패스 설정 ]$COLOR_END" >> $RESULT_FILE  2>&1

path=`echo $PATH | egrep '(\./|::/)'`
if [[ $path != "" ]];then
	echo " [-] . 혹은 ::로 시작하는 환경 변수가 포함되어있습니다." >> $RESULT_FILE 2>&1
	result 1 05
else
	echo " [+] . 혹은 ::로 시작하는 환경 변수가 없습니다." >> $RESULT_FILE 2>&1
	result 0 05
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
#####################################################################
# U-06 파일 및 디렉토리 소유자 설정
#####################################################################
echo "[ U-06 ] : Check "
echo -e "$BG_BLUE [ U-06 파일 및 디렉토리 소유자 설정 ]$COLOR_END" >> $RESULT_FILE 2>&1

nouser=`find / -nouser -print 2>/dev/null`
nogroup=`find / -nogroup -print 2>/dev/null`

if [[ $nouser != "" || $nogroup != "" ]];then
	echo " [-] 소유자 및 소유 그룹이 없는 파일이나 디렉토리가 있습니다." >> $RESULT_FILE 2>&1
	echo " [-] 해당 파일 및 디렉토리 : $nouser \n $nogroup " >> $RESULT_FILE 2>&1
	result 1 06
else 
	echo " [+] 소유자 및 소유 그룹이 없는 파일이나 디렉토리가 없습니다." >> $RESULT_FILE 2>&1
	result 0 06
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
#####################################################################
# -주요 정보 통신 기반 시설 계정 관리 U-07 /etc/passwd 소유자 및 권한
####################yy#################################################
echo "[ U-07 ] : CHeck"
echo -e "$BG_BLUE [ U-07 /etc/passwd 파일 소유자 및 권한 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1
if [ -f "/etc/passwd" ]; then
	ls -l /etc/passwd >>$RESULT_FILE 2>&1
	permission_val=`stat -c '%a' /etc/passwd`
	owner_val=`stat -c '%U' /etc/passwd`
	owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
	group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
	other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
	if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 4 ] && [ "$owner_val" = "root" ]; then
		result 0 07
	else
		result 1 07
	fi
else
	echo "Not FOund /etc/passwd file" >>$RESULT_FILE 2>&1
	result 1 7
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
##########################################################################
# U-08 /etc/shadow 파일 소유자 및 권한 설정
##########################################################################
echo "[ U-08 ] : Check"
echo -e "$BG_BLUE [ U-08 /etc/shadow 파일 소유자 및 권한 설정  ] $COLOR_END" >> $RESULT_FILE 2>&1

#1. /etc/shadow 파일 소유자 점검
shadow_owner=`stat -c '%U' /etc/shadow`
shadow_perm=`stat -c '%a' /etc/shadow`

if [[ $shadow_owner == 'root' ]];then
    if [[ $shadow_perm -eq 400 ]];then
        echo -e " [+] /etc/shadow 소유자 $shadow_owner, 권한 $shadow_perm으로 정상" >> $RESULT_FILE 2>&1
        result 0 08
    else 
        echo " [-] /etc/shadow 소유자 $shadow_owner, 권한 $shadow_perm, 취약" >> $RESULT_FILE 2>&1
        result 1 08
    fi  
else
    echo " [-] /etc/shadow 소유자 $shadow_owner, 권한 $shadow_perm, 취약" >> $RESULT_FILE 2>&1
    result 1 08
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

####################################################################################################
# U-09 /etc/hosts 파일 소유자 및 권한 설정
####################################################################################################
echo "[ U-09 ] : Check"
echo -e "$BG_BLUE [ U-09 /etc/hosts 파일 소유자 및 권한 설정 ]$COLOR_END" >> $RESULT_FILE 2>&1

# 1. /etc/hosts 권한 설정
hosts=`ls -l /etc/hosts`
permission_val=`stat -c '%a' /etc/hosts`
owner_val=`stat -c '%U' /etc/hosts`
owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`

echo "[*] /etc/hosts 파일 정보 확인" >> $RESULT_FILE 2>&1
echo " [*] $hosts" >> $RESULT_FILE 2>&1

if [[ $owner_perm_val -le 6 && $group_perm_val -eq 0 && $other_perm_val -eq 0 && $owner_val == 'root' ]];then
	echo "  [+] /etc/hosts 파일 권한 : $permission_val, 소유자 : $owner_val 양호" >> $RESULT_FILE 2>&1
	result 0 09
else
	echo "  [-] /etc/hosts 파일 권한 : $permission_val, 소유자 : $owner_val 취약" >> $RESULT_FILE 2>&1
	result 1 09
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

####################################################################################################
# U-10 /etc/(x)inetd.conf 파일 소유자 및 권한 설정
####################################################################################################

echo "[ U-10 ] : Check"
echo -e "$BG_BLUE [ U-10 /etc/(x)inetd.conf 파일의 소유자 및 권한 확인 ] $COLOR_END" >> $RESULT_FILE 2>&1

# 1. /etc/xinetd.conf 권한 설정
inetd_perm=`stat -c '%a' /etc/xinetd.conf`
inetd_own=`stat -c '%U' /etc/xinetd.conf`
inet_path=/etc/xinetd.d/
inetd_flag=0
echo " [*] /etc/xinetd.conf의 권한은 $inetd_perm 이고, 소유자는 $inetd_own 이다." >> $RESULT_FILE 2>&1
if [ $inetd_perm -ne 600 ];then
	echo "  [-] /etc/xinetd.conf의 권한을 600으로 변경 필요(취약)"  >> $RESULT_FILE 2>&1
	result 1 10
else
	echo "  [+] /etc/xinetd.conf의 권한이 600으로 양호합니다" >> $RESULT_FILE 2>&1
	inetd_flag=$((inetd_flag+1))
fi

if [[ $inetd_own -ne "root" ]];then
	echo "  [-] /etc/xinetd.conf의 소유자를 root로 변경 필요(취약)" >> $RESULT_FILE 2>&1
	result 1 10
else
	echo "  [+] /etc/xinetd.conf의 소유자가 root로 양호합니다" >> $RESULT_FILE 2>&1
	inetd_flag=$((inetd_flag+1))
fi

# 2. /etc/xinetd.d/* 아래의 파일 권한 확인
echo " [*] /etc/xinetd.d/* 파일의 권한 확인" >> $RESULT_FILE 2>&1
wc_xinetd=`ls /etc/xinetd.d >> xinetd_list.txt && cat xinetd_list.txt | grep -v "xinetd_list.txt" | wc -l`
wc_flag=0
wc_xinetd=$((2*$wc_xinetd))
cat ./xinetd_list.txt | grep -v xinetd_list.txt | while read file
do
	perm=`stat -c '%a' $inet_path$file`
	owner=`stat -c '%U' $inet_path$file`
	if [ $perm -ne 600 ]; then
		echo "  [-] $file 권한이  $perm 입니다. 600으로 변경하세요(취약)" >> $RESULT_FILE 2>&1
		flag=1
	else
		echo "  [+] $file 권한이  $perm 입니다.(양호)" >> $RESULT_FILE 2>&1
	fi

	if [[ $owner -ne "root" ]]; then
		echo "  [-] $file 소유자가 $owner 입니다. root로 변경하세요(취약)" >> $RESULT_FILE 2>&1
		flag=1
	else
		echo "  [+] $file 소유자가 $owner 입니다.(양호)" >> $RESULT_FILE 2>&1
	fi
done
if [ $wc_flag -eq 0 ];then
	result 0 10
else
	result 1 10
fi

rm -f xinetd_list.txt
echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


#####################################################################
# U-11 /etc/syslog.conf 파일의 소유자 및 권한 변경
#####################################################################
echo "[ U-11 ] : Check"
echo -e "$BG_BLUE [ U-11 /etc/rsyslog.conf ] $COLOR_END" >> $RESULT_FILE 2>&1
sys_perm=`stat -c '%a' /etc/rsyslog.conf`
sys_owner=`stat -c '%U' /etc/rsyslog.conf`

echo " [*] /etc/rsyslog.conf의 권한은 $sys_perm 이고, 소유자는 $sys_owner 이다." >> $RESULT_FILE 2>&1

if [ $sys_perm -eq 640 ];then
	if [[ $sys_owner == 'root' ]];then
		result 0 11
	else
		echo "  [-] /etc/rsyslog.conf의 소유자를 root로 변경해주세요! (취약)" >> $RESULT_FILE 2>&1
		result 1 11
	fi
else
	echo "  [-] /etc/rsyslog.conf의 권한을 640으로 변경해주세요!(취약)" >> $RESULT_FILE 2>&1
	result 1 11
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
########################################################################
# U-12 /etc/services 파일 권한 및 사용자 설정
##########################################################################
echo "[ U-12 ] : Check"
echo -e "$BG_BLUE [ U-12 /etc/services 파일 권한 및 사용자 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1

service_own=`stat -c '%U' /etc/services`
service_perm=`stat -c '%a' /etc/services`

echo " [*] /etc/services의 권한은 $service_perm 이고, 소유자는 $service_own 이다." >> $RESULT_FILE 2>&1

if [ $sys_perm -eq 644 ];then
    if [[ $sys_owner == 'root' ]];then
        result 0 12
    else
        echo "  [-] /etc/services의 소유자를 root로 변경해주세요! (취약)" >> $RESULT_FILE 2>&1
        result 1 12
    fi  
else
    echo "  [-] /etc/services의 권한을 644으로 변경해주세요!(취약)" >> $RESULT_FILE 2>&1
    result 1 12
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
###################################################################################################
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리 | U-13 SUID, SGID, Sticky Bit 설정 및 권한 설정
####################################################################################################
echo "[ U-13 ] : Check"
echo -e "$BG_BLUE [ U-13 SUID, SGID, Sticky bit 설정 및 권한 설정 START ] $COLOR_END" >> $RESULT_FILE 2>&1
FILES="/sbin/dump sbin/restore /sbin/unix_chkpwd /usr/bin/newgrp /usr/sbin/traceroute /usr/bin/at /usr/bin/lpq /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd /usr/sbin/lpc /usr/sbin/lpc-lpd /usr/bin/lprm /usr/bin/lprm-lpd /home/kisec/symtest/sym4"

count=0

for file_chk in $FILES; do
	if [ -f "$file_chk" ]; then
		#echo "FILE CHECK : $file_chk"
		perm_chk=`ls -alL $file_chk | awk '{ print $1 }' | grep -i 's'`
		link_chk=`ls -al $file_chk | awk '{ print $1 }' | grep -i 'l'`
		#echo "perm_chk :$perm_chk"
		#echo "link_chk :$link_chk"
		echo "`ls -al $file_chk`" >> $RESULT_FILE 2>&1
		if [ "$link_chk" != "" ]; then
			syn_flag=1
			while [ $syn_flag -eq 1 ]
			do
				echo "Symbolic Link : `ls -alL $file_chk`" >> $RESULT_FILE 2>&1

				link_file=`readlink $file_chk`
				#echo "link_file : $link_file"
				if [ "$link_file" == "" ];then
					syn_flag=0
					#echo "ENd of this link :$file_chk"
				elif [ "$link_file" != "" ];then
					#echo "MOre Link file : $link_file"
					file_chk=`readlink $link_file`
					if [ "$file_chk" == "" ];then
						syn_flag=0
					fi
					echo "Symbolic Link : `ls -alL $link_file`" >> $RESULT_FILE 2>&1
				fi
			done
		fi
		if [ "$perm_chk" != "" ] || [ "$link_chk" != "" ]; then
			count=`expr $count + 1`
		fi
	fi
done

echo "총 취약한 파일 갯수 : $count" >> $RESULT_FILE 2>&1

if [ $count -eq 0 ]; then
	result 0 13
else
	result 1 13
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##########################################################################
# U-14 사용자, 시스템 시작 파일 및 환경 파일 소유자 및 권한 설정
##########################################################################
echo "[ U-14 ] : Check"
echo -e "$BG_BLUE [ U-14 사용자, 시스템 시작 파일 및 환경 파일 소유자 및 권한 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1

env_file=".bash_profile .bash_logout .bashrc"
flag=0
ls /home >> user_list.txt

cat ./user_list.txt | grep -v 'user_list.txt' | while read user
do
	echo " [*] 현재 $user 홈 디렉터리를 확인 중입니다." >> $RESULT_FILE 2>&1
	for file in $env_file
	do
		stat_user=`stat -c '%U' /home/$user/$file`
		if [[ $stat_user == $user || $stat_user == 'root' ]];then
			echo "  [+] $file 의 소유자는 $stat_user 입니다.(양호)" >> $RESULT_FILE 2>&1
		else
			echo "  [-] $file 의 소유자는 $stat_user 입니다, $user 로 변경해주세요(취약)" >> $RESULT_FILE 2>&1
			flag=1
		fi
	done
done

rm -f user_list.txt
etc_profile_user=`stat -c '%U' /etc/profile`
if [ $flag -eq 0 ];then
	if [[ $etc_profile_user == 'root' ]];then
		result 0 14
	else 
		flag=1
		result 1 14
	fi
else
	result 1 14
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##########################################################################
# U-15 world writable 파일 점검
##########################################################################
echo "[ U-15 ] : Check"
echo -e "$BG_BLUE [ U-15 World writable 파일 점검 ] $COLOR_END" >> $RESULT_FILE 2>&1


world=`find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null`

if [[ $world != "" ]];then
	echo " [-] 취약한 파일은 아래와 같습니다, 권한 설정을 변경해주세요!!(취약)" >> $RESULT_FILE 2>&1
	echo "$world" > ./result/U15.txt
	result 1 15
else
	echo " [+] 취약한 파일이 없습니다.(양호)" >> $RESULT_FILE 2>&1
	result 0 15
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
#########################################################################
# U-16 /dev에 존재하지 않는 device 파일 점검
##########################################################################
echo "[ U-16 ] : Check"
echo -e "$BG_BLUE [ U-16 /dev에 존재하지 않는 device 파일 점검 ] $COLOR_END" >> $RESULT_FILE 2>&1
dev_file=`find /dev -type f -exe ls -l {} \; 2>/dev/null`
if [[ $dev_file != "" ]];then
	echo " [-] 의심되는 파일이 존재 합니다.(취약)" >> $RESULT_FILE 2>&1
	echo "  $dev_file">> $RESULT_FILE 2>&1
	result 1 16
else
	echo " [+] 의심되는 파일이 없습니다.(양호)" >> $RESULT_FILE 2>&1
	result 0 16
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##########################################################################
# U-17 $HOME/.rhosts, hosts.equiv 사용 금지
##########################################################################
echo "[ U-17 ] : Check"
echo -e "$BG_BLUE [ U-17 $HOME/.rhosts, hosts.equiv 사용 금지 $COLOR_END" >> $RESULT_FILE 2>&1
filename1=/etc/hosts.equiv
filename2=~/.rhosts

# 1. service disable 확인
service=`systemctl list-unit-files | grep rsh.socket | awk '{ print $2 }'`

if [ $service == 'enabled' ];then
	file_check1=`find $filename1 -user root -perm 600 2>/dev/null`
	file_check2=`find $filename2 -user root -perm 600 2>/dev/null`
	if [ -n $file_check1 ] && [ -n $file_check2 ];then
		config1=`cat $filename1 | grep "+"`
		config2=`cat $filename2 | grep "+"`
		if [ -n $config1 ] && [ -n $config2 ];then
			echo " [+] rcommand 서비스 미사용 혹은 적정 설정 사용(양호)" >> $RESULT_FILE 2>&1
			result 0 17
		else
			echo " [-] rcommand 서비스 사용 혹은 미흡 설정 사용(취약)" >> $RESULT_FILE 2>&1
			result 1 17
		fi
	else
		echo " [-] rcommand 서비스 사용 혹은 미흡 설정 사용(취약)" >> $RESULT_FILE 2>&1
		result 1 17
	fi
else
	echo " [-] rcommand 서비스 사용 혹은 미흡 설정 사용(취약)" >> $RESULT_FILE 2>&1
	result 1 17
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##########################################################################
# U-18 접속 IP 및 포트 제한
##########################################################################
echo "[ U-18 ] : Check"
echo -e "$BG_BLUE [ U-18 접속 IP 및 포트 제한 ] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] TCP Wrapper, Iptables, Ipfilter 파일 설정을 확인하고 개별 사용 IP 필요" >> $RESULT_FILE 2>&1
echo " [*] 1) TCP Wrapper" >> $RESULT_FILE 2>&1
echo " [*]   - /etc/hosts.deny" >> $RESULT_FILE 2>&1
echo " [*]   - /etc/hosts.allow" >> $RESULT_FILE 2>&1
echo " [*] 2) iptables" >> $RESULT_FILE 2>&1
echo " [*]   - iptables -L" >> $RESULT_FILE 2>&1
echo " [*] 3) IPfilter" >> $RESULT_FILE 2>&1
echo " [*]   - /etc/ipf/ipf.conf" >> $RESULT_FILE 2>&1
echo " [*] 4) TCP Wrapper" >> $RESULT_FILE 2>&1
echo " [*]   - inetadm -p" >> $RESULT_FILE 2>&1

result 2 18

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##########################################################################
# U-55 hosts.lpd 파일 소유자 및 권한 설정
##########################################################################

echo "[ U-55 ] : Check"
echo -e "$BG_BLUE [ U-55 hosts.lpd 파일 소유자 및 권한 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1

if [ ! -f /etc/hosts.lpd ]; then
	echo " [+] /etc/hosts.lpd 파일이 없습니다. (양호)" >> $RESULT_FILE 2>&1
	result 0 55
else
	lpd_owner=`stat -c '%U' /etc/hosts.lpd`
	lpd_perm=`stat -c '%a' /etc/hosts.lpd`
	if [[ $lpd_perm -eq 600 && $lpd_owner != 'root' ]];then
		" [+] /etc/hosts.lpd 파일 사용, 소유자 및 권한 설정 양호(양호)" >> $RESULT_FILE 2>&1
		result 0 55
	else
		" [-] /etc/hosts.lpd 파일 사용, 소유자 및 권한 설정 미흡(취약)" >> $RESULT_FILE 2>&1
		result 1 55
	fi
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##########################################################################
# U-56 umask 설정 관리
##########################################################################
echo "[ U-56 ] : Check"
echo -e "$BG_BLUE [ U-56 UMASK 설정 관리 ] $COLOR_END" >> $RESULT_FILE 2>&1

cat /etc/profile | grep -E ' umask [0-9]{3}$' | cut -c 11-13 >> umask.txt
flag=0
cnt=0
cat umask.txt | while read mask
do
	if [ $cnt -eq 0 ];then
		echo " [*] 일반 사용자 UMASK : $mask " >> $RESULT_FILE 2>&1
		if [ $mask -ge 022 ];then
			echo " [+] UMASK 값은 $mask 로 양호합니다." >> $RESULT_FILE 2>&1
			flag=1
		else 
			echo " [-] UMASK 값은 $mask 로 취약합니다." >> $RESULT_FILE 2>&1
		fi
		cnt=1
	elif [ $cnt -eq 1 ];then
		echo " [*] root 사용자 UMASK : $mask " >> $RESULT_FILE 2>&1
		break
	fi
done

rm -f umask.txt

if [ $flag -eq 1 ];then
	result 0 56
else
	result 1 56
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##########################################################################
# U-57 홈 디렉토리 소유자 및 권한
##########################################################################
echo "[ U-57 ] : Check"
echo -e "$BG_BLUE [ U-57 홈디렉토리 소유자 및 권한 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1

cat /etc/passwd | awk -F":" '{ print $1 }' >> passwd_user.txt
ls /home >> user_list.txt
cat user_list.txt | while read user
do
	for passwd_user in `cat passwd_user.txt`
	do
		home=`cat /etc/passwd | grep -E "^$user" | awk -F":" '{ print $6 }'`
		if [[ $user == $passwd_user ]]; then
			echo " [*] 사용자 $user 의 홈 디렉토리는 $home 입니다." >> $RESULT_FILE 2>&1
			perm=`ls -ald $home`
			echo " [*] 해당 홈 디렉토리의 권한 및 사용자는 아래와 같습니다." >> $RESULT_FILE 2>&1
			echo "  $perm" >> $RESULT_FILE 2>&1
			echo "" >> $RESULT_FILE 2>&1
		fi
	done
done


result 2 57

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##########################################################################
# U-58 홈 디렉토리로 지정한 디렉토리의 존재 관리
##########################################################################
echo "[ U-58 ] : Check"
echo -e "$BG_BLUE [ U-58 홈 디렉토리로 지정한 디렉토리의 존재 관리 ] $COLOR_END" >> $RESULT_FILE 2>&1

cat user_list.txt | while read user
do
	for user in `cat passwd_user.txt`
	do
		home=`cat /etc/passwd | grep -E "^$user" | awk -F":" '{ print $6 }'`
		if [[ $home == "/" ]]; then
			echo " [*] $user 사용자의 홈 디렉토리가 없습니다.(취약)" >> $RESULT_FILE 2>&1
			echo "  [-] 세부 사용자 정보 확인 " >> $RESULT_FILE 2>&1
			misuser=`cat /etc/passwd | grep -E "^$user"`
			echo "   $misuser" >> $RESULT_FILE 2>&1
		fi
	done
done


rm -f passwd_user.txt
rm -f user_list.txt

result 2 58

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##########################################################################
# U-59 숨겨진 파일 및 디렉토리 검색 및 제거
##########################################################################
echo "[ U-59 ] : Check"
echo -e "$BG_BLUE [ U-59 숨겨진 파일 및 디렉토리 검색 및 제거 ] $COLOR_END" >> $RESULT_FILE 2>&1
hidden_file=`find / -type f -name ".*" 2>/dev/null`
hidden_dir=`find / -type f -name ".*" 2>/dev/null`
flag=0
echo "숨김 파일 목록------------------------" > ./result/U59.txt
echo $hidden_file >> ./result/U59.txt
echo "">> ./result/U59.txt
echo "숨김 디렉토리 목록--------------------" >> ./result/U59.txt
echo $hidden_dir >> ./result/U59.txt

if [[ $hidden_file != "" ]];then
	echo " [*] 숨겨진 파일이 존재합니다.(검토)" >> $RESULT_FILE 2>&1
	flag=1
else
	echo " [*] 숨겨진 파일이 없습니다.(양호)" >> $RESULT_FILE 2>&1
fi

if [[ $hidden_dir != "" ]];then
	echo " [*] 숨겨진 디렉터리가 존재합니다.(검토)" >> $RESULT_FILE 2>&1
	flag=1
else
	echo " [*] 숨겨진 디렉터리가 없습니다.(양호)" >> $RESULT_FILE 2>&1
fi

if [ $flag -eq 1 ];then
	result 2 59
else
	result 0 50
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
echo -e "$RED 3. 서비스 관리 $COLOR_END" >> $RESULT_FILE 2>&1
##########################################################################
# U-19 Finger 서비스 비활성화
##########################################################################
echo "[ U-19 ] : Check"
echo -e "$BG_BLUE [ U-19 Finger 서비스 비활성화 ] $COLOR_END" >> $RESULT_FILE 2>&1
flag=0
echo "[*] finger process check" >> $RESULT_FILE 2>&1
get_ps=`ps -ef | grep -v 'grep' | grep finger`
if [ "$get_ps" != "" ];then
	echo "$get_ps" >> $RESULT_FILE 2>&1
	flag=1
else
	echo " [+] finger 프로세스가 실행중이 아닙니다." >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1
echo "[*] finger service check" >> $RESULT_FILE 2>&1
get_service=`systemctl list-units --type service finger 2>/dev/null`
if [ "$get_service" != "" ]; then
	echo "$get_service" >> $RESULT_FILE 2>&1
	flag=1
else
	echo " [+] finger 서비스가 실행중이 아닙니다." >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1

finger_disable=`cat /etc/xinetd.d/finger | sed -e 's/[ \t]*//g' | grep disable | awk -F"=" '{ print $2 }'`
if [[ $finger_disable != "no" ]]; then
	echo "  [-] finger 서비스가 사용 가능한 상태입니다, 설정 파일을 변경해주세요 " >> $RESULT_FILE 2>&1
	flag=1
else
	echo "  [+] finger 서비스 사용 불가 상태입니다.(양호)" >> $RESULT_FILE 2>&1
fi

if [ $flag -eq 1 ];then
	result 1 19
else
	result 0 19
fi
echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
##########################################################################
# - 주요 정보 통신 기반 시설 |서비스관리 | U-20 Anonynmous FTP 비활성화
##########################################################################

echo "[ U-20 ] : Check"
echo -e "$BG_BLUE [ U-20 Anonymous FTP 비활성화 START ] $COLOR_END" >> $RESULT_FILE 2>&1
FTP=1
vsftp_flag=0
protfp_flag=0

echo "1. FTP Process CHeck" >> $RESULT_FILE 2>&1
get_ps=`ps -ef | grep -v 'grep' | grep 'ftpd' | grep -v 'tftp'`
if [ "$get_ps" != "" ];then
	echo "$get_ps" >> $RESULT_FILE 2>&1
	if [ "`echo \"$get_ps\" | grep 'vsftp'`" != "" ];then
		vsftp_flag=1
	elif [ "`echo \"$get_ps\" | grep 'proftp'`" != "" ];then
		proftp_flag=1
	fi
else
	echo "NOt FOund Process" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

echo "2. FTP Service Check" >> $RESULT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
	get_service=`$systemctl_cmd list-units --type service | grep 'ftpd\.service' | sed -e 's/^ *//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$get_service" != "" ]; then
		echo "$get_service" >> $RESULT_FILE 2>&1
	else
		echo "Not Found Service" >> $RESULT_FILE 2>&1
	fi
else
	echo "Not Found systemctl command" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

echo "3. FTP Port Check" >> $RESULT_FILE 2>&1
if [ "$port_cmd" != "" ];then
	get_port=`$port_cmd -na | grep "tcp" | grep "LISTEN" | grep ":21[ \t]"`
	if [ "$get_port" != "" ];then
		echo "$get_port" >> $RESULT_FILE 2>&1
	else
		echo "Not FOund Port" >> $RESULT_FILE 2>&1
	fi
else
	echo "Not Found POrt Command" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1
if [ "$get_ps" != "" ] || [ "$get_service" != "" ] || [ "$get_port" != "" ]; then
	# 여기까지만 보면 FTP=1이고 vsftpd도 1일 수도 있으니까 경우의 수를 나눠준다.
	if [ $vsftp_flag -eq 1 ]; then
	if [ -f "/etc/vsftpd/vsftpd.conf" ]; then
			conf_file="/etc/vsfptd/vsfptd.conf"
			conf_chk=`cat "/etc/vsftpd/vsftpd.conf" | grep -v '^#' | grep 'anonymous_enable'`
		elif [ -f "/etc/vsftpd.conf" ]; then
		    conf_file="/etc/vsftpd.conf"
			conf_chk=`cat "/etc/vsftpd.conf" | grep -v '^#' | grep 'anonymous_enable'`
		fi
		if [ "$conf_chk" != "" ]; then
			conf_chk_tmp=`echo "$conf_chk" | awk -F"=" '{ print $2 }' | grep -i 'no'`
			echo "4. FTP Anonymous Configuration Check" >> $RESULT_FILE 2>&1
            echo "COnfiguration FILE : $conf_file" >> $RESULT_FILE 2>&1
			echo "$conf_chk" >> $RESULT_FILE 2>&1
			if [ "$conf_chk_tmp" = "" ];then
				FTP=0
			fi
		fi
	elif [ $proftp_flag -eq 1 ]; then
		conf_file="/etc/proftpd.conf"
		conf_chk=`cat /etc/proftpd.conf | sed -e 's/^[ \t]*//g' | egrep "^User[ 	]*ftp|^UserAlias"`
		echo "4. FTP Anonymous Configuration Check" >> $RESULT_FILE 2>&1
		echo "COnfiguration FILE : $conf_file" >> $RESULT_FILE 2>&1
		if [ "$conf_chk" != "" ]; then
			echo "$conf_chk" >> $RESULT_FILE 2>&1
			FTP=0
		fi
	else
		if [ -f "/etc/passwd" ]; then
			user_chk=`cat /etc/passwd | grep ftp`
			if [ "$user_chk" != "" ]; then
				FTP=0
			fi
		fi
	fi
fi
if [ $FTP -eq 1 ]; then
	result 0 20
else
	result 1 20
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##########################################################################
# U-21 r계열 서비스 비활성화
##########################################################################
echo "[ U-21 ] : Check"
echo -e "$BG_BLUE [U-21 r계열 서비스 비활성화] $COLOR_END" >> $RESULT_FILE 2>&1
xinet_dir="/etc/xinetd.d"
flag=0


echo " [*] r 계열 서비스 사용 여부 점검" >> $RESULT_FILE 2>&1
if [ ! -f $xinet_dir/rsh ]; then
	echo "  [+] rsh 서비스 미사용" >> $RESULT_FILE 2>&1
else
	echo "  [?] rsh 서비스 사용" >> $RESULT_FILE 2>&1
	rsh=`cat $xinet_dir/rsh | sed -e 's/[ \t]*//g' | grep disable | awk -F"=" '{ print $2 }'`
	if [[ $rsh == "no" ]];then
		echo "  [+] rsh 서비스 disable 설정 양호" >> $RESULT_FILE 2>&1
	else	
		echo "  [-] rsh 서비스 disable 설정 미흡" >> $RESULT_FILE 2>&1
		flag=1
	fi
fi

if [ ! -f $xinet_dir/rexec ]; then
	echo "  [+] rexec 서비스 미사용" >> $RESULT_FILE 2>&1
else
	echo "  [?] rexec 서비스 사용" >> $RESULT_FILE 2>&1
	rexec=`cat $xinet_dir/rexec | sed -e 's/[ \t]*//g' | grep disable | awk -F"=" '{ print $2 }'`
	if [[ $rexec == "no" ]];then
		echo "  [+] rxec 서비스 disable 설정 양호" >> $RESULT_FILE 2>&1
	else
		echo "  [-] rexe 서비스 disable 설정 미흡" >> $RESULT_FILE 2>&1
		flag=1
	fi
fi

if [ ! -f $xinet_dir/rlogin ]; then
	echo "  [+] rlogin 서비스 미사용" >> $RESULT_FILE 2>&1
else
	echo "  [-] rlogin 서비스 사용" >> $RESULT_FILE 2>&1	
	rlogin=`cat $xinet_dir/rlogin | sed -e 's/[ \t]*//g' | grep disable | awk -F"=" '{ print $2 }'`
	if [[ $rlogin == "no" ]];then
		echo "  [+] rlogin 서비스 disable 설정 양호" >> $RESULT_FILE 2>&1
	else
		echo "  [-] rlgoin 서비스 disable 설정 미흡" >> $RESULT_FILE 2>&1
		flag=1
	fi
fi

echo " [*] rsh : $rsh, rlogin : $rlogin, rexec : $rexec" >> $RESULT_FILE 2>&1

if [ $flag -eq 1 ];then
	result 1 21
else
	result 0 21
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-22 cron 파일 소유자 및 권한 설정
##############################################################################
echo "[ U-22 ] : Check"
echo -e "$BG_BLUE [U-22 Cron 파일 소유자 및 권한 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] /usr/bin/crontab 권한 750 설정 확인 " >> $RESULT_FILE 2>&1
flag=0

crontab_perm=`stat -c '%a' /usr/bin/crontab`
crontab_sid_perm=`echo "$crontab_perm" | awk '{ print substr($0, 1, 1) }'`
crontab_own_perm=`echo "$crontab_perm" | awk '{ print substr($0, 2, 1) }'`
crontab_grp_perm=`echo "$crontab_perm" | awk '{ print substr($0, 3, 1) }'`
crontab_oth_perm=`echo "$crontab_perm" | awk '{ print substr($0, 4, 1) }'`
if [ $crontab_own_perm -le 7 ] && [ $crontab_grp_perm -le 5 ] && [ $crontab_oth_perm -eq 0 ]; then
	echo "  [+] crontab 파일 권한이 750 이하입니다.(양호)" >> $RESULT_FILE 2>&1
else
	echo "  [-] crontab 파일 권한이 부적절합니다.(취약)" >> $RESULT_FILE 2>&1
	flag=1
fi
echo " [*] cron 관련 파일 소유자 및 권한 설정" >> $RESULT_FILE 2>&1
ls -al /etc | awk -F" " '{ print $9 }' | grep -E '^cron.*' >> cronlist.txt
cron_path="/etc/"
cat cronlist.txt | while read word
do
	cron_own=`stat -c '%U' $cron_path$word`
	cron_perm=`stat -c '%a' $cron_path$word`
	cron_own_perm=`echo "$cron_perm" | awk '{ print substr($0, 1, 1) }'`
	cron_grp_perm=`echo "$cron_perm" | awk '{ print substr($0, 2, 1) }'`
	cron_oth_perm=`echo "$cron_perm" | awk '{ print substr($0, 3, 1) }'`
	if [ $cron_own_perm -le 6 ] && [ $cron_grp_perm -le 4 ] && [ $cron_oth_perm -eq 0 ];then
		if [[ $cron_own == 'root' ]]; then
			echo "  [+] $cron_path$word 의 권한 및 소유자 설정이 양호합니다." >> $RESULT_FILE 2>&1
		else
			echo "  [-] $cron_path$word 의 권한 및 소유자 설정이 미흡합니다." >> $RESULT_FILE 2>&1
			flag=1
		fi
	else
		echo "  [-] $cron_path$word 의 권한 설정이 미흡합니다." >> $RESULT_FILE 2>&1
		flag=1
	fi
done

if [ $flag -ne 0 ];then
	result 1 22
else
	result 0 22
fi
rm -f cronlist.txt

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-23 DoS 공격에 취약한 서비스 비활성화
##############################################################################
echo "[ U-23 ] : Check"
echo -e "$BG_BLUE [U-23 DoS 공격에 취약한 서비스 비활성화] $COLOR_END" >> $RESULT_FILE 2>&1
xinet_dir="/etc/xinetd.d"
flag=0


dos_function(){
	echo " [*] $1 서비스 사용 여부 점검" >> $RESULT_FILE 2>&1
	if [ ! -f $xinet_dir/$1 ];then
		echo " [+] $1 서비스 미사용 " >> $RESULT_FILE 2>&1
	else
		echo " [?] $1 서비스 사용" >> $RESULT_FILE 2>&1
		svc_flag=`cat $xinet_dir/$1 | sed -e 's/[ \t]*//g' | grep diable | awk -F"=" '{ print $2 }'`
		if [[ $svc_flag == "no" ]];then
			echo "  [+] $1 서비스 disable 설정 양호" >> $RESULT_FILE 2>&1
		else
			echo "  [-] $1 서비스 disable 설정 미흡" >> $RESULT_FILE 2>&1
			flag=1
		fi
	fi
}

dos_function echo
dos_function discard
dos_function daytime
dos_function chargen

if [ $flag -eq 1 ];then
	echo "  [-] DoS 취약 서비스 사용 중!(취약)" >> $RESULT_FILE 2>&1
	result 1 23
else
	echo "  [+] DoS 취약 서비스 미사용(양호) " >> $RESULT_FILE 2>&1
	result 0 23
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-24 NFS 서비스 비활성화
##############################################################################
echo "[ U-24 ] : Check"
echo -e "$BG_BLUE [U-24 NFS 서비스 비활성화] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] NFS서비스 데몬 확인" >> $RESULT_FILE 2>&1
nfs_ps=`ps -ef | egrep "nfs|statd|lockd" | grep -v "grep"`

if [[ $nfs_ps != "" ]];then
	echo "  [?] NFS 서비스 식별, 프로세스 확인 필요" >> $RESULT_FILE 2>&1
	echo "   $nfs_ps" >> $RESULT_FILE 2>&1
	nfs_script=`ls -al /etc/rc.d/rc*.d/* | grep nfs`
	echo "  [?] NFS 시동 스크립트 확인, 존재 시 이름 변경필요" >> $RESULT_FILE 2>&1
	echo "   $nfs_script" >> $RESULT_FILE 2>&1
	result 2 24
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-25 NFS 접근 통제
##############################################################################
echo "[ U-25 ] : Check"
echo -e "$BG_BLUE [U-25 NFS 서비스 접근 통제] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] /etc/exports 파일 내부 접근 통제 필요" >> $RESULT_FILE 2>&1
if [ -f /etc/exports ];then
	echo "  [?] /etc/exports 내용 확인" >> $RESULT_FILE 2>&1
	exports=`cat /etc/exports`
	echo "    $exports" >> $RESULT_FILE 2>&1
fi

result 2 25

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-26 automountd 제거
##############################################################################
echo "[ U-26 ] : Check"
echo -e "$BG_BLUE [U-26 automountd 제거 ] $COLOR_END" >> $RESULT_FILE 2>&1
ps_auto=`ps -ef | egrep "automount|autofs" | grep -v "grep"`
if [[ $ps_auto != "" ]];then
	echo " [*] automountd 가 현재 실행중입니다." >> $RESULT_FILE 2>&1
	echo "  $ps_auto" >> $RESULT_FILE 2>&1
	ls_auto=`ls -al /etc/rc.d/rc*.d/* | egrep "automount|autofs"`
	echo " [*] automountd 시동 스크립트 확인" >> $RESULT_FILE 2>&1
	echo "  $ls_auto"
	result 2 26
else
	result 0 26
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
# U-27 RPC 서비스 확인
##############################################################################
echo "[ U-27 ] : Check"
echo -e "$BG_BLUE [U-27 RPC 서비스 비활성화 확인] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] RPC 서비스 설정 상태 확인" >> $RESULT_FILE 2>&1
flag=0

dos_function rpc*



if [ $flag -eq 1 ];then
	echo "  [-] RPC 서비스 사용 가능(취약)" >> $RESULT_FILE 2>&1
	result 1 27
else
	echo "  [+] RPC 서비스 미사용(양호)" >> $RESULT_FILE 2>&1
	result 0 27
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-28 NIS, NIS+ 점검
##############################################################################
echo "[ U-28 ] : Check"
echo -e "$BG_BLUE [U-28 NIS, NIS+ 점검 ] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] NIS, NIS+ 서비스 실행 여부 점검" >> $RESULT_FILE 2>&1
ps_nis=`ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v "grep"`
if [[ $ps_nis != "" ]];then
	echo "  [?] NIS, NIS+ 프로세스 실행 중" >> $RESULT_FILE 2>&1
	ls_nis=`ls -al /etc/rc.d/rc*.d/* | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"`
	echo " [*] NIS, NIS+ 시동 스크립트 확인" >> $RESULT_FILE 2>&1
	echo "   $ps_nis"
	result 1 28
else
	result 0 28
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-29 tftp, talk 서비스 비활성화
##############################################################################
echo "[ U-29 ] : Check"
echo -e "$BG_BLUE [U-29 tftp, talk 서비스 비활성화] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] tftp, talk 서비스 실행 여부 점검" >> $RESULT_FILE 2>&1
flag=0

dos_function tftp
dos_function talk
dos_function ntalk

if [ $flag -eq 1 ];then
	result 1 29
else 
	result 0 29
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-30 Sendmail 버전 점검
##############################################################################
echo "[ U-30 ] : Check"
echo -e "$BG_BLUE [U-31 Sendmail 버전 점검] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] Sendmail 서비스 실행 여부 점검" >> $RESULT_FILE 2>&1
ps_send=`ps -ef | grep "sendmail" | grep -v "grep"`
if [[ $ps_send != "" ]];then
	echo "  [-] Sendmail 서비스 실행 중(취약)" >> $RESULT_FILE 2>&1
else
	echo "  [+] Sendmail 서비스 미실행 중 (양호)" >> $RESULT_FILE 2>&1
fi

echo "  [?] Sendmail 서비스의 버전을 확인 후, 홈페이지에서 취약점을 패치하세요" >> $RESULT_FILE 2>&1

result 2 31

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-31 스팸 메일 릴레이 제한
##############################################################################
echo "[ U-31 ] : Check"
echo -e "$BG_BLUE [U-31 스팸 메일 제한] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] 스팸 메일 제한" >> $RESULT_FILE 2>&1
relay=`cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied" | sed -e 's/[ \t]//g' | cut -c 1 `
if [[ $relay == 'R' ]];then
	echo " [+] 릴레이 제한 설정 양호" >> $RESULT_FILE 2>&1
	echo " [*] 추가적인 /etc/mail/access 파일을 참고해서 접근 통제 확인" >> $RESULT_FILE 2>&1
	result 2 31
else
	echo " [-] 릴레이 제한 설정 미흡" >> $RESULT_FILE 2>&1
	result 1 31
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-32 일반 사용자의 Sendmail 실행 방지
##############################################################################
echo "[ U-32 ] : Check"
echo -e "$BG_BLUE [U-32 일반 사용자의 Sendmail 실행 방지]$COLOR_END" >> $RESULT_FILE 2>&1
qrun=`grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions | grep restrictqrun`
if [[ $ps_send != "" && $qrun == "" ]];then
	echo " [-] SMTP 서비스 사용 중, 설정파일 변경 필요" >> $RESULT_FILE 2>&1
	result 1 32
else
	echo " [+] SMTP 서비스 미사용, 설정 파일 변경 미필요" >> $RESULT_FILE 2>&1
	result 0 32
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-33 DNS 보안 버전 패치
##############################################################################
echo "[ U-33 ] : Check"
echo -e "$BG_BLUE [U-33 DNS 보안 버전 패치"$COLOR_END >> $RESULT_FILE 2>&1
echo " [+] 사용 환경에 따라 서비스 중지 여부 결정 및 버전 확인 필요" >> $RESULT_FILE 2>&1
ps_dns=`ps -ef | grep named | grep -v 'grep'`
ver_dns=`named -v`
echo "  [?] DNS 실행 여부 확인" >> $RESULT_FILE 2>&1
echo "   $ps_dns" >> $RESULT_FILE 2>&1
echo "  [?] DNS 버전 확인" >> $RESULT_FILE 2>&1
echo "   $ver_dns" >> $RESULT_FILE 2>&1

result 2 33

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
# - 주요 정보 통신 기반 시설 | 서비스 관리 | U-34 DNS Zone Transfer 설정
##############################################################################
echo "[ U-34 ] : Check"
echo -e "$BG_BLUE [U-34 DNS Zone Transfer 설정 START] $COLOR_END" >> $RESULT_FILE 2>&1
DNS=1
get_ps=`ps -ef | grep -v 'grep' | grep 'named'`
if [ -f "/etc/named.conf" ] && [ "$get_ps" != "" ]; then
	first=`cat /etc/named.conf | sed -e 's/^ *//g' -e 's/^	*//g' | egrep -v '^$|^//|^#'`
	second=`echo "$first" | awk -F"\n" 'BEGIN{count=0} { for(i=1;i<=NF;i++ ) { if($i ~ /\/\*/) count=1; if(count==0) print $i; if($i ~ /\*\//) count=0; }}'`
	result=`echo "$second" | awk 'BEGIN{count=0} { for(i=1;i<=NF;i++) { if($i ~ /allow-transfer/) count=1; if(count==1) printf "%s ", $i; if(count==1 && $i ~ /}/) { count=0; printf "\n" }}}'`
	if [ "$result" = "" ] || [ "`echo \"$result\" | grep \"any;\"`" != "" ]; then
		DNS=0
	fi
	echo "$result" >> $RESULT_FILE 2>&1
fi

if [ $DNS -eq 1 ]; then
	result 0 34
else
	result 1 34
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-35 웹서비스 디렉토리 리스팅 제거
##############################################################################
echo "[ U-35 ] : Check"
echo -e "$BG_BLUE [U-35 웹 서비스 디렉토리 리스팅 제거]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] /etc/httpd/conf/httpd.conf 설정 확인" >> $RESULT_FILE 2>&1
if [[ -d /etc/httpd ]];then
	follow=`cat /etc/httpd/conf/httpd.conf | grep "Options Indexes" | awk -F" " '{ print $3 }'`
	if [[ $follow != "" ]];then
		echo "  [+] Indexes 설정 양호, 설정값 : $follow " >> $RESULT_FILE 2>&1
		result 0 35
	else
		echo "  [-] Indexes 설정 미흡(취약)" >> $RESULT_FILE 2>&1
		result 1 35
	fi
fi

echo "">> $RESULT_FILE 2>&1
echo "">> $RESULT_FILE 2>&1


##############################################################################
# U-36 웹서비스 웹 프로세스 권한 제한
##############################################################################
echo "[ U-36 ] : Check"
echo -e "$BG_BLUE [U-36 웹서비스 웹 프로세스 권한 제한]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] 실행 계정 확인" >> $RESULT_FILE 2>&1
user_account=`cat /etc/httpd/conf/httpd.conf | egrep "User" | grep -v '#' | grep -v LogFormat |awk -F" " '{ print $2 }'`
grp_account=`cat /etc/httpd/conf/httpd.conf | egrep "Group" | grep -v '#' | grep -v LogFormat |awk -F" " '{ print $2 }'`

if [[ $user_account != 'root' && $grp_account != 'root' ]];then
	echo "  [+] User : $user_account, Group : $grp_account" >> $RESULT_FILE 2>&1
	result 0 36
else
	echo "  [+] User : $user_account, Group : $grp_account" >> $RESULT_FILE 2>&1
	result 1 36
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
# U-37 웹 서비스 상위 디렉토리 접근 금지
##############################################################################
echo "[ U-37 ] : Check"
echo -e "$BG_BLUE [U-37 웹 서비스 상위 디렉토리 접근 금지]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] AllowOverride 설정을 확인합니다." >> $RESULT_FILE 2>&1
flag=0
cat /etc/httpd/conf/httpd.conf | grep AllowOverride | grep -v "#" | awk -F" " '{ print $2 }' >> override.txt
cat override.txt | while read line
do
	line_md=${line,,}
	if [[ $line_md == "none" ]];then
		echo "  [+] AllowOverride 설정값이 $line 입니다.(양호)" >> $RESULT_FILE 2>&1
	else
		echo "  [-] AllowOverride 설정값이 $line 이므로, 변경해주세요(취약)" >> $RESULT_FILE 2>&1
		flag=1
	fi
done
rm -rf override.txt

if [ $flag -eq 1 ];then
	result 1 37
else 
	result 0 37
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
# U-38 웹서비스 불필요한 파일 제거
##############################################################################
echo "[ U-38 ] : Check"
echo -e "$BG_BLUE [U-38 웹 서비스 불필요한 파일 제거]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] Apache 와 관련된 메뉴얼 파일 탐색 ">> $RESULT_FILE 2>&1
etc_http=`find /etc/httpd -name *manual`
var_http=`find /var/www -name *manual`

if [[ $etc_http != "" || $var_http != "" ]];then
	echo "  [-] manual 파일이 존재합니다.(취약)" >> $RESULT_FILE 2>&1
	echo "   $etc_http" >> $RESULT_FILE 2>&1
	echo "   $var_http" >> $RESULT_FILE 2>&1
	result 1 38
else
	echo "  [+] manual 파일이 존재하지 않습니다.(양호)" >> $RESULT_FILE 2>&1
	result 0 38
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
# U-39 웹 서비스 링크 사용 금지
##############################################################################
echo "[ U-39 ] : Check"
echo -e "$BG_BLUE [U-39 웹 서비스 링크 사용 금지]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] AllowOverride의 설정 확인" >> $RESULT_FILE 2>&1
follow=`cat /etc/httpd/conf/httpd.conf | grep "Options Indexes" | awk -F" " '{ print $3 }'`
if [[ $follow == "" ]];then
	echo "  [+] AllowOverride에 FollowSymLInks 설정이 없습니다.(양호)">> $RESULT_FILE 2>&1
	result 0 39
else
	if [[ $follow == "-FollowSymLinks" ]];then
		echo "  [+] AllowOverride에 $follow 로 설정되어있습니다.(양호)" >> $RESULT_FILE 2>&1
		result 0 39
	else
		echo "  [-] AllowOverride의 $follow 설정을 변경해야 합니다.(취약)" >> $RESULT_FILE 2>&1
		result 1 39
	fi
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
# U-40 웹서비스 파일 업로드 및 다운로드 제한
##############################################################################
echo "[ U-40 ] : Check"
echo -e "$BG_BLUE [U-40 웹서비스 파일 업로드 및 다운로드 제한] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] LimitRequestBody 파일 사이즈 용량 확인" >> $RESULT_FILE 2>&1
limit=`cat /etc/httpd/conf/httpd.conf | grep LimitRequestBody | grep -v "#" | awk -F" " '{ print $2 }'`

if [[ $limit == "" ]];then
	echo "  [-] LimitRequestBody 설정값 추가 필요" >> $RESULT_FILE 2>&1
	result 1 40
else
	if [ $limit -le 5000000 ];then
		echo "  [+] LimitRequestBody 설정값 : $limit 으로, 양호" >> $RESULT_FILE 2>&1
		result 0 40
	else
		echo "  [-] LimitRequestBody 설정값 : $limit 으로, 5MB 이하로 설정 필요(취약)" >> $RESULT_FILE 2>&1
		result 1 40
	fi
fi

echo "">> $RESULT_FILE 2>&1
echo "">> $RESULT_FILE 2>&1


##############################################################################
# U-41 웹 서비스 영역의 분리
##############################################################################
echo "[ U-41 ] : Check"
echo -e "$BG_BLUE [U-41 웹 서비스 영역의 분리]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] DocumentRoot 디렉토리 확인" >> $RESULT_FILE 2>&1
root_dir=`cat /etc/httpd/conf/httpd.conf | grep '^DocumentRoot' | awk -F" " '{ print $2 }'`
if [[ $root_dir == '"/var/www/html"' ]];then
	echo "  [-] DocumentRoot 디렉토리가 $root_dir 으로, 변경해주세요!!(취약)" >> $RESULT_FILE 2>&1
	result 1 41
else
	echo "  [+] DocumentRoot 디렉토리가 $root_dir 으로, 양호합니다." >> $RESULT_FILE 2>&1
	result 0 41
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
#U-60 ssh 원격접속 허용
##############################################################################
echo "[ U-60 ] : Check"
echo -e "$BG_BLUE [U-60 SSH 원격 접속 허용]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] ssh를 설치하고 평소에 사용하는 지가 중요!!" >> $RESULT_FILE 2>&1
echo " [*] ssh 서비스 설정 파일 확인">> $RESULT_FILE 2>&1
ssh_cmd=`cat /etc/ssh/sshd_config`
if [[ $ssh_cmd != "" ]];then
	result 0 60
else
	result 1 60
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
#U-61 FTP 서비스 확인
##############################################################################
echo "[ U-61 ] : Check"
echo -e "$BG_BLUE [U-61 FTP 서비스 확인]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] FTP 서비스 활성여부 확인" >> $RESULT_FILE 2>&1
ps_ftp=`ps -ef | egrep 'ftp|vsftpd|proftp' | grep -v 'grep'`
if [[ $ps_ftp != "" ]]; then
	echo "  [-] 실행 중인 FTP 서비스 정보 확인 (취약)" >> $RESULT_FILE 2>&1
	echo "   $ps_ftp"
	result 1 61
else
	result 0 61
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
# U-62 FTP 계정 shell 제한
##############################################################################
echo "[ U-62 ] : Check"
echo -e "$BG_BLUE [U-62 FTP 계정 shell 제한]$COLOR_END" >> $RESULT_FILE 2>&1
ftp_shell=`cat /etc/passwd | grep ftp | awk -F":" '{ print $7 }'`

echo " [*] ftp 계정 사용 shell : $ftp_shell" >> $RESULT_FILE 2>&1
if [[ $ftp_shell == "/bin/false" || $ftp_shell == "/sbin/nologin" ]];then
	result 0 62
else
	echo "  [-] ftp 계정 shell 변경 필요!! " >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
#U-63 ftpusers 파일 소유자 및 권한 설정
##############################################################################
echo "[ U-63 ] : Check"
echo -e "$BG_BLUE [U-63 ftpusers 파일 소유자 및 권한 설정]$COLOR_END" >> $RESULT_FILE 2>&1
if [ -f "/etc/ftpusers" ] || [ -f "/etc/ftpd/ftpdusers" ];then
	echo " [*] ftp/proftp 서비스를 사용중입니다." >> $RESULT_FILE 2>&1
	ftp_ls=`ls -al /etc/ftpusers || ls -al /etc/ftpd/ftpusers`
	ftp_user=`stat -c '%a' /etc/ftpusers || stat -c '%a' /etc/ftpd/ftpusers`
	ftp_own=`echo $ftp_user | awk '{ print substr($0, 1, 1) }'`
	ftp_grp=`echo $ftp_user | awk '{ print substr($0, 2, 1) }'`
	ftp_oth=`echo $ftp_user | awk '{ print substr($0, 3, 1) }'`
	if [ $ftp_own -le 6 ] && [ $ftp_grp -le 4 ] && [ $ftp_oth -eq 0 ];then
		echo " [+] ftpusers 파일 정보 " >> $RESULT_FILE 2>&1
		echo "  $ftp_ls"
		result 0 63
	else
		echo " [-] ftpusers 권한 변경이 필요합니다, 현재 권한 : $ftp_user"
		result 1 63
	fi
elif [ -f "/etc/vsftpd/ftpusers" ] || [ -f "/etc/vsftpd/user_list" ] || [ -f "/etc/vsftpd.ftpusers" ] || [ -f "/etc/vsftpd.user_list" ];then
	echo " [*] vsftpd 서비스를 사용중입니다." >> $RESULT_FILE 2>&1
    ftp_ls=`ls -al /etc/vsftpd/ftpusers || ls -al /etc/vsftpd/user_list || ls -al /etc/vsftpd.ftpusers || ls -al /etc/vsftpd.user_list`
    ftp_user=`stat -c '%a' /etc/vsftpd/ftpusers || stat -c '%a' /etc/ftpd/user_list || stat -c '%a' /etc/vsftpd.ftpusers || stat -c '%a' /etc/vsftpd.user_list`
    ftp_own=`echo $ftp_user | awk '{ print substr($0, 1, 1) }'`
    ftp_grp=`echo $ftp_user | awk '{ print substr($0, 2, 1) }'`
    ftp_oth=`echo $ftp_user | awk '{ print substr($0, 3, 1) }'`
    if [ $ftp_own -le 6 ] && [ $ftp_grp -le 4 ] && [ $ftp_oth -eq 0 ];then
        echo " [+] ftpusers 파일 정보 " >> $RESULT_FILE 2>&1 
        echo "  $ftp_ls" >> $RESULT_FILE 2>&1
        result 0 63 
    else 
        echo " [-] ftpusers 권한 변경이 필요합니다, 현재 권한 : $ftp_user" >> $RESULT_FILE 2>&1
        result 1 63 
    fi  
else
	echo " [+] ftp 서비스를 미사용 중입니다." >> $RESULT_FILE 2>&1
	result 0 63
fi
echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
#U-64 ftpusers 파일 설정(FTP 서비스 ROOT 계정 접근 제한)
##############################################################################
echo "[ U-64 ] : Check"
echo -e "$BG_BLUE [U-64 ftpusers 파일 설정(ftp 서비스 root 계정 접근 제한)]$COLOR_END" >> $RESULT_FILE 2>&1
if [ -f "/etc/ftpusers" ] || [ -f "/etc/ftpd/ftpdusers" ];then
    echo " [*] ftp/proftp 서비스를 사용중입니다." >> $RESULT_FILE 2>&1 
    ftp_cat=`cat /etc/ftpusers || cat /etc/ftpd/ftpusers`
	echo " [*] root 계정을 등록 혹은 주석 해제 해주세요" >> $RESULT_FILE
elif [ -f "/etc/vsftpd/ftpusers" ] || [ -f "/etc/vsftpd/user_list" ] || [ -f "/etc/vsftpd.ftpusers" ] || [ -f "/etc/vsftpd.user_list" ];then
    echo " [*] vsftpd 서비스를 사용중입니다." >> $RESULT_FILE 2>&1 
    ftp_cat=`cat /etc/vsftpd/ftpusers || cat /etc/vsftpd/user_list || cat /etc/vsftpd.ftpusers || cat /etc/vsftpd.user_list`
        echo " [*] root 계정을 등록 혹은 주석 해제 해주세요 " >> $RESULT_FILE 2>&1  
else
    echo " [+] ftp 서비스를 미사용 중입니다." >> $RESULT_FILE 2>&1 
fi
result 2 64

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
##############################################################################
#U-65 at 서비스 권한 설정
##############################################################################
echo "[ U-65 ] : Check"
echo -e "$BG_BLUE [U-65 at 서비스 권한 설정]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] at 명령어 SUID 설정 확인" >> $RESULT_FILE 2>&1
flag=0
at_perm=`stat -c '%a' /usr/bin/at`
at_perm_suid=`echo $at_perm | awk '{ print substr($0, 1, 1) }'`
at_perm_own=`echo $at_perm | awk '{ print substr($0, 2, 1) }'`
at_perm_grp=`echo $at_perm | awk '{ print substr($0, 3, 1) }'`
at_perm_oth=`echo $at_perm | awk '{ print substr($0, 4, 1) }'`

if [ $at_perm_suid -eq 4 ];then
	echo "  [-] at 명령어의 SUID 설정을 제거하거나 유저를 관리해주세요!!" >> $RESULT_FILE 2>&1
	echo "  [-] at 명령어의 권한 : $at_perm" >> $RESULT_FILE 2>&1
fi
if [ $at_perm_own -le 7 ] && [ $at_perm_grp -le 5 ] && [ $at_perm_oth -eq 0 ];then
	echo "  [+] at 명령어의 현재 권한 설정은 정상입니다." >> $RESULT_FILE 2>&1
else
	echo "  [-] at 명령어의 권한을 변경해주세요!" >> $RESULT_FILE 2>&1
	flag=1
fi

echo " [*] at.allow, at.deny 설정 확인 " >> $RESULT_FILE 2>&1
echo " [*] 2개 파일의 접근권한 및 소유자 확인" >> $RESULT_FILE 2>&1
if [ -f /etc/at.allow ];then
	at_allow_perm=`stat -c '%a' /etc/at.allow`
	at_allow_own=`echo $at_allow_perm | awk '{ print substr($0, 1, 1) }'`
	at_allow_grp=`echo $at_allow_perm | awk '{ print substr($0, 2, 1) }'`
	at_allow_oth=`echo $at_allow_perm | awk '{ print substr($0, 3, 1) }'`
	if [ $at_allow_own -le 6 ] && [ $at_allow_grp -le 4 ] && [ $at_allow_oth -eq 0 ];then
		echo "  [+] at.allow 파일의 접근 권한 설정이 정상입니다." >> $RESULT_FILE 2>&1
	else
		echo "  [-] at.allow 파일의 접근 권한을 750으로 변경해주세요, 현재 : $at_allow_perm " >> $RESULT_FILE 2>&1
		flag=1
	fi
	at_allow_owner=`stat -c '%U' /etc/at.allow`
	if [[ $at_allow_owner == "root" ]];then
		echo "  [+] at.allow 파일의 소유가가 $at_allow_owner 으로 정상입니다" >> $RESULT_FILE 2>&1
	else
		echo "  [-] at.allow 파일의 소유자를 변경해주세요, 현재 : $at_allow_owner" >> $RESULT_FILE 2>&1
		flag=1
	fi
else 
	echo "  [-] at.allow 파일이 없습니다, 추가해주세요" >> $RESULT_FILE 2>&1
	flag=1
fi
if [ -f /etc/at.deny ];then
	at_deny_perm=`stat -c '%a' /etc/at.deny`
	at_deny_own=`echo $at_deny_perm | awk '{ print substr($0, 1, 1) }'`
	at_deny_grp=`echo $at_deny_perm | awk '{ print substr($0, 2, 1) }'`
	at_deny_oth=`echo $at_deny_perm | awk '{ print substr($0, 3, 1) }'`
	if [ $at_deny_own -le 6 ] && [ $at_deny_grp -le 4 ] && [ $at_deny_oth -eq 0 ];then
		echo "  [+] at.deny 파일의 접근 권한 설정이 정상입니다." >> $RESULT_FILE 2>&1
	else
		echo "  [-] at.deny 파일의 접근 권한을 변경해주세요, 현재 : $at_deny_perm" >> $RESULT_FILE 2>&1
		flag=1
	fi
	at_deny_owner=`stat -c '%U' /etc/at.deny`
	if [[ $at_deny_owner == "root" ]];then
		echo "  [+] at.deny 파일의 소유자가 $at_deny_owner 으로 정상입니다." >> $RESULT_FILE 2>&1
	else
		echo "  [-] at.deny 파일의 소유자를 변경해주세요, 현재 : $at_deny_owner" >> $RESULT_FILE 2>&1
		flag=1
	fi
else
	echo "  [-] at.deny 파일이 없습니다. 추가해주세요" >> $RESULT_FILE 2>&1
	flag=1
fi

if [ $flag -eq 1 ];then
	result 1 65
else
	result 0 65
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
#U-66 SNMP서비스 구동 점검
##############################################################################
echo "[ U-66 ] : Check"
echo -e "$BG_BLUE [U-66 SNMP 서비스 구동 점검 ] $COLOR_END">> $RESULT_FILE 2>&1
echo " [*] SNMP 서비스 구동 여부를 점검합니다. " >> $RESULT_FILE 2>&1
ps_snmp=`ps -ef | grep 'snmp' | grep -v 'grep'`

if [[ $ps_snmp != "" ]];then
	echo "  [-] SNMP 서비스를 중지시켜주세요!!(취약)" >> $RESULT_FILE 2>&1
	echo "   $ps_snmp"
	result 1 66
else
	echo "  [+] 구동중인  SNMP 서비스가 없습니다" >> $RESULT_FILE 2>&1
	result 0 66
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
#U-67 SNMP 서비스 Community String의 복잡성 설정
##############################################################################
echo "[ U-67 ] : Check"
echo -e "$BG_BLUE [U-67 SNMP 서비스 Community String의 복잡성 설정]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] 현재 SNMP 사용 여부 확인" >> $RESULT_FILE 2>&1
flag=0
ps_ef=`ps -ef | grep "snmp" | grep -v "grep"`
if [[ $ps_ef != "" ]];then
	echo "  [-] SNMP 서비스가 구동중입니다." >> $RESULT_FILE 2>&1
	echo "   $ps_ef"
fi
echo " [*] /etc/snmp/snmpd.conf 파일 Community String 설정" >> $RESULT_FILE 2>&1
snmp_conf=`cat /etc/snmp/snmpd.conf | grep "com2sec" | grep -v "#"`
comm_string=`cat /etc/snmp/snmpd.conf | grep "com2sec" | grep -v "#" | awk -F" " '{ print $4 }'`
if [[ $comm_string == "public" ]];then
	echo "   [-] Community String 이 기본 public 으로 설정되어있습니다." >> $RESULT_FILE 2>&1
	result 1 67
else
	echo "   [+] Community String 이 기본 값이 아닙니다, 현재 설정 : $comm_string ." >> $RESULT_FILE 2>&1
	result 0 67
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
#U-68 로그온 시 경고 메시지 제공
##############################################################################
echo "[ U-68 ] : Check"
echo -e "$BG_BLUE [ U-68 로그온 시 경고 메시지 제공]$COLOR_END" >> $RESULT_FILE 2>&1
flag=0

echo " [*] 서버 로그온 메시지 설정 :/etc/motd" >> $RESULT_FILE 2>&1
if [ -f /etc/motd ]; then
	motd=`cat /etc/motd`
	if [[ $motd != "" ]];then
		echo "  [+] 현재 설정된 경고 메시지 : $motd" >> $RESULT_FILE 2>&1
		
	else 
		echo "  [-] 경고 메시지를 설정하세요!! " >> $RESULT_FILE 2>&1
		flag=1
	fi
else
	echo "  [-] 경고 메시지를 설정하세요!! " >> $RESULT_FILE 2>&1
fi

echo " [*] Telnet 배너 설정" >> $RESULT_FILE 2>&1
if [ -f /etc/issue.net ];then
	telnet=`cat /etc/issue.net`
	if [[ $telnet != "" ]];then
		echo "  [+] 현재 설정된 배너 메시지 : $telnet" >> $RESULT_FILE 2>&1
	else
		echo "  [-] 배너를 설정해주세요 : $telnet" >> $RESULT_FILE 2>&1
		flag=1
	fi
else
	echo "  [-] 배너를 설정해주세요 : $telnet" >> $RESULT_FILE 2>&1
fi

echo " [*] FTP 배너 설정" >> $RESULT_FILE 2>&1
if [ -f /etc/vsftpd/vsftpd.conf ];then
	ftp=`cat /etc/vsftpd/vsftpd.conf | grep "ftpd_banner" | awk -F"=" '{ print $2 }'`
	if [[ $ftp != "" ]];then
		echo "  [+] 현재 설정된 배너 메시지 : $ftp" >> $RESULT_FILE 2>&1
	else
		echo "  [-] 배너를 설정해주세요 : $ftp" >> $RESULT_FILE 2>&1
		flag=1
	fi
else
	echo "  [-] 배너를 설정해주세요 : $ftp" >> $RESULT_FILE 2>&1
fi

echo " [*] SNMP 배너 설정" >> $RESULT_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ];then
	snmp=`cat /etc/mail/sendmail.cf | grep "GreetingMessage" | awk -F"=" '{ print }'`
	if [[ $snmp != "" ]];then
		echo "  [+] 현재 설정된 배너 메시지 : $telnet" >> $RESULT_FILE 2>&1
	else
		echo "  [-] 배너를 설정해주세요 : $snmp" >> $RESULT_FILE 2>&1
		flag=1
	fi
else
	echo "  [-] 배너를 설정해주세요 : $ftp" >> $RESULT_FILE 2>&1
fi

echo "[*] DNS 배너 설정" >> $RESULT_FILE 2>&1
if [ -f /etc/named.conf ];then
	dns=`cat /etc/named.conf`
	if [[ $dns != "" ]];then
		echo "  [+] 현재 설정된 배너 메시지 : $dns" >> $RESULT_FILE 2>&1
	else
		echo "  [-] 배너를 설정해주세요 : $dns" >> $RESULT_FILE 2>&1
		flag=1
	fi
else
	echo "  [-] 배너를 설정해주세요 : $dns" >> $RESULT_FILE 2>&1
fi

if [ $flag -eq 1 ];then
	result 1 68
else
	result 0 68
fi


echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
#U-69 NFS 설정 파일 접근 권한
##############################################################################
echo "[ U-69 ] : Check"
echo -e "$BG_BLUE [ U-69 ] NFS 설정 파일 접근 권한 ]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] NFS 소유자 및 권한 확인" >> $RESULT_FILE 2>&1
flag=0
nfs_perm=`stat -c '%a' /etc/exports`
nfs_owner=`stat -c '%U' /etc/exports`

nfs_own=`echo $nfs_perm | awk '{ print substr($0, 1, 1) }'`
nfs_grp=`echo $nfs_perm | awk '{ print substr($0, 2, 1) }'`
nfs_oth=`echo $nfs_perm | awk '{ print substr($0, 3, 1) }'`

echo "  [*] /etc/exports 파일의 소유자 : $nfs_owner, 권한 : $nfs_perm 입니다." >> $RESULT_FILE 2>&1
echo "  [*] 권장 소유자 : root, 권한 : 644 입니다." >> $RESULT_FILE 2>&1
if [[ $nfs_owner != "root" ]];then
	echo "   [-] 소유자를 root로 변경해주세요 !! " >> $RESULT_FILE 2>&1
	flag=1
else
	echo "   [+] 소유자가 $nfs_owner 으로 권고사항을 충족합니다" >> $RESULT_FILE 2>&1
	if [ $nfs_own -le 6 ] && [ $nfs_grp -le 4 ] && [ $nfs_oth -le 4 ];then
		echo "   [+] 권한이 644 이하로 설정되어있습니다." >> $RESULT_FILE 2>&1
	else
		echo "   [-] 권한이 644 이상으로 설정되어있습니다. 변경해주세요 " >> $RESULT_FILE 2>&1
		flag=1
	fi
fi

if [ $flag -eq 1 ];then
	result 1 69
else
	result 0 69
fi
		

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################################################
#U-34 expn, vrfy 명령어 제한
##############################################################################
echo "[ U-70 ] : Check"
echo -e "$BG_BLUE [U-70 expn, vrfy 명령어 제한 ] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] /etc/mail/sendmail.cf 설정 확인" >> $RESULT_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ];then
	option=`cat /etc/mail/sendmail.cf | grep 'PrivacyOptions=' | awk -F"=" '{ print $2 }'`
	echo " [*] PrivacyOptions의 설정 값 : $option" >> $RESULT_FILE 2>&1
	if [[ "$option" == *noexpn* ]];then
		if [[ "$option" == *novrfy* ]];then
			echo "  [+] nevrfy, noexpn의 설정이 양호합니다." >> $RESULT_FILE 2>&1
		else
			flag=1
		fi
	else
		flag=1
	fi
else
	echo "  [+] SNMP 서비스를 사용하지 않습니다." >> $RESULT_FILE 2>&1
	flag=0
fi

if [ $flag -eq 1 ];then
	result 1 34
else
	result 0 34
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################################################
#U-71 Apache 웹 서비스 정보 숨김
##############################################################################
echo "[ U-71 ] : Check"
echo -e "$BG_BLUE [U-71 Apache 웹 서비스 정보 숨김]$COLOR_END" >> $RESULT_FILE 2>&1
token=`cat /etc/httpd/conf/httpd.conf | grep ServerTokens`
sig=`cat /etc/httpd/conf/httpd.conf | grep ServerSignature`
token=${token,,}
sig=${sig,,}
flag=0

echo " [*] ServerTokens, ServerSignature 값 확인" >> $RESULT_FILE 2>&1
if [[ $token == "prod" ]];then
	if [[ $sig == "off" ]];then
		echo "  [+] ServerTokens : $token, ServerSignature : $sig " >> $RESULT_FILE 2>&1
	else
		flag=1
	fi
else
	flag=1
fi

if [[ $flag -eq 1 ]];then
	echo "  [-] 현재 설정된 값은 ServerTokens : $token, ServerSignature : $sig " >> $RESULT_FILE 2>&1
	echo "  [-] 각각 Prod와 off로 변경하세요 " >> $RESULT_FILE 2>&1
	result 1 71
else
	result 0 71
fi

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1



echo -e "$RED 4. 패치 관리 $COLOR_END" >> $RESULT_FILE 2>&1
##############################################################################
#U-42 최신 보안 패치 및 벤더 권고사항 적용
##############################################################################
echo "[ U-42 ] : Check"
echo -e "$BG_BLUE [U-42 최신 보안 패치 및 벤더 권고사항 적용 ] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] 아래의 사이트에 접속해서 해당 OS의 최신 패치를 적용하세요!!" >> $RESULT_FILE 2>&1
site="https://support.oracle.com"
echo "  $site" >> $RESULT_FILE 2>&1
result 2 42

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

echo -e "$RED 5. 로그 관리 $COLOR_END" >> $RESULT_FILE 2>&1
##############################################################################
# U-43 로그의 정기적 검토 및 보고
##############################################################################
echo "[ U-43 ] : Check"
echo -e "$BG_BLUE [U-43 로그의 정기적 검토 및 보고]$COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] 서버의 운영 환경에 적합한 정기적인 로그 검토 및 보고 체계가 필요합니다!!" >> $RESULT_FILE 2>&1
result 2 43

echo "" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1



##############################################################################
#U-72 정책에 따른 시스템 로깅 설정
##############################################################################
echo "[ U-72 ] : Check"
echo -e "$BG_BLUE [U-44 정책에 따른 시스템 로깅 설정 ] $COLOR_END" >> $RESULT_FILE 2>&1
echo " [*] /etc/rsyslog.conf 의 주요 로깅 설정 확인" >> $RESULT_FILE 2>&1
info=`cat /etc/rsyslog.conf | grep "*.info;mail.none;authpriv.none;cron.none" | awk -F" " '{ print $2 }'`
auth=`cat /etc/rsyslog.conf | grep "authpriv.\*" | grep -v '#' | awk -F" " '{ print $2 }'`
cron=`cat /etc/rsyslog.conf | grep "cron.\*" | awk -F" " '{ print $2 }'`
emerg=`cat /etc/rsyslog.conf | grep "\*.emerg" | awk -F" " '{ print $2 }'`
alert=`cat /etc/rsyslog.conf | grep "\*.alert" | awk -F" " '{ print $2 }'`
flag=0

if [[ $info == "/var/log/messages" ]];then
	echo "  [+] *.info;mail.none;authpriv.none;cron.none 의 설정이 $info 로, 양호합니다." >> $RESULT_FILE 2>&1
else
	echo "  [-] *.info;mail.none;authpriv.none;cron.none 의 설정이 $info 로, 취약합니다." >> $RESULT_FILE 2>&1
	flag=1
fi

if [[ $auth == "/var/log/secure" ]];then
	echo "  [+] authpriv.*의 설정이 $auth 로, 양호합니다." >> $RESULT_FILE 2>&1
else
	echo "  [-] authpriv.*의 설정이 $auth 로, 취약합니다." >> $RESULT_FILE 2>&1
	flag=1
fi

if [[ $cron == "/var/log/cron" ]];then
	echo "  [+] cron.*의 설정이 $cron 로, 양호합니다." >> $RESULT_FILE 2>&1
else
	echo "  [-] cron.*의 설정이 $cron 로, 취약합니다." >> $RESULT_FILE 2>&1
	flag=1
fi

if [[ $emerg == "\*" ]]; then
	echo "  [+] *.emerge의 설정이 $emerge 로, 양호합니다." >> $RESULT_FILE 2>&1
else
	echo "  [-] *.emerge의 설정이 $emerge 로, 취약합니다." >> $RESULT_FILE 2>&1
	flag=1
fi

if [[ $alert == "/dev/console" ]];then
	echo "  [+] *.alert의 설정이 $alert 로, 양호합니다." >> $RESULT_FILE 2>&1
else
	echo "  [-] *.alert의 설정이 $alert 로, 취약합니다." >> $RESULT_FILE 2>&1
	flag=1
fi

if [[ $flag -eq 1 ]];then
	result 1 72
else
	result 0 72
fi
	

