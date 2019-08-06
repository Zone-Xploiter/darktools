clear
echo "please wait process installing module  external from python :)"
sleep 2
apt update && upgrade
sleep 2
apt install python
sleep 2
apt install python2
sleep 2
pip2 install requirements
sleep 2
pip2 install html2text
sleep 2
pip2 install requests
sleep 2
pip2 install mechanize
sleep 2
pip2 install bs4
sleep 2
chmod +x darktools.py
clear
echo "installing finish please enter python2 darktools.py"
echo ""
