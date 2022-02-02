if [[ "$(ping -c 20 8.8.8.8 | grep '100% packet loss' )" != "" ]]; then
    echo "Internet isn't present"
    python3 RestClient.py -t $1 -p $2
fi