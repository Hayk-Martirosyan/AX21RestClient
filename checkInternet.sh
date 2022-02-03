if [[ "$(ping -c 20 $1 | grep '100% packet loss' )" != "" ]]; then
    echo "Internet isn't present"
    python3 RestClient.py -t $2 -p $3 --path system -f reboot -o reboot
fi
