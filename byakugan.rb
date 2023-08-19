#!/usr/bin/ruby

require 'httparty'

admins = ["admin/", "administrator/", "moderator/", "webadmin/", "adminarea/", "bb-admin/", "adminLogin/", "admin_area/", "panel-administracion/", "instadmin/", "memberadmin/", "administratorlogin/", "adm/", "account.asp", "admin/account.asp", "admin/index.asp", "admin/login.asp", "admin/admin.asp", "admin_area/admin.asp", "admin_area/login.asp", "admin/account.html", "admin/index.html", "admin/login.html", "admin/admin.html", "admin_area/admin.html", "admin_area/login.html", "admin_area/index.html", "admin_area/index.asp", "bb-admin/index.asp", "bb-admin/login.asp", "bb-admin/admin.asp", "bb-admin/index.html", "bb-admin/login.html", "bb-admin/admin.html", "admin/home.html", "admin/controlpanel.html", "admin.html", "admin/cp.html", "cp.html", "administrator/index.html", "administrator/login.html", "administrator/account.html", "administrator.html", "login.html", "modelsearch/login.html", "moderator.html", "moderator/login.html", "moderator/admin.html", "account.html", "controlpanel.html", "admincontrol.html", "admin_login.html", "panel-administracion/login.html", "admin/home.asp", "admin/controlpanel.asp", "admin.asp", "pages/admin/admin-login.asp", "admin/admin-login.asp", "admin-login.asp", "admin/cp.asp", "cp.asp", "administrator/account.asp", "administrator.asp", "login.asp", "modelsearch/login.asp", "moderator.asp", "moderator/login.asp", "administrator/login.asp", "moderator/admin.asp", "controlpanel.asp", "adminpanel.html", "webadmin.html", "pages/admin/admin-login.html", "admin/admin-login.html", "webadmin/index.html", "webadmin/admin.html", "webadmin/login.html", "user.asp", "user.html", "admincp/index.asp", "admincp/login.asp", "admincp/index.html", "admin/adminLogin.html", "adminLogin.html", "home.html", "adminarea/index.html", "adminarea/admin.html", "adminarea/login.html", "panel-administracion/index.html", "panel-administracion/admin.html", "modelsearch/index.html", "modelsearch/admin.html", "admin/admin_login.html", "admincontrol/login.html", "adm/index.html", "adm.html", "admincontrol.asp", "adminpanel.asp", "webadmin.asp", "webadmin/index.asp", "webadmin/admin.asp", "webadmin/login.asp", "admin/admin_login.asp", "admin_login.asp", "panel-administracion/login.asp", "adminLogin.asp", "admin/adminLogin.asp", "home.asp", "adminarea/index.asp", "adminarea/admin.asp", "adminarea/login.asp", "admin-login.html", "panel-administracion/index.asp", "panel-administracion/admin.asp", "modelsearch/index.asp", "modelsearch/admin.asp", "administrator/index.asp", "admincontrol/login.asp", "adm/admloginuser.asp", "admloginuser.asp", "admin2.asp", "admin2/login.asp", "admin2/index.asp", "adm/index.asp", "adm.asp", "affiliate.asp", "adm_auth.asp", "memberadmin.asp", "administratorlogin.asp", "siteadmin/login.asp", "siteadmin/index.asp", "account.cfm", "admin/account.cfm", "admin/index.cfm", "admin/login.cfm", "admin/admin.cfm", "admin_area/admin.cfm", "admin_area/login.cfm", "admin_area/index.cfm", "bb-admin/index.cfm", "bb-admin/login.cfm", "bb-admin/admin.cfm", "admin/home.cfm", "admin/controlpanel.cfm", "admin.cfm", "pages/admin/admin-login.cfm", "admin/admin-login.cfm", "admin-login.cfm", "admin/cp.cfm", "cp.cfm", "administrator/account.cfm", "administrator.cfm", "login.cfm", "modelsearch/login.cfm", "moderator.cfm", "moderator/login.cfm", "administrator/login.cfm", "moderator/admin.cfm", "controlpanel.cfm", "user.cfm", "admincp/index.cfm", "admincp/login.cfm", "admincontrol.cfm", "adminpanel.cfm", "webadmin.cfm", "webadmin/index.cfm", "webadmin/admin.cfm", "webadmin/login.cfm", "admin/admin_login.cfm", "admin_login.cfm", "panel-administracion/login.cfm", "adminLogin.cfm", "admin/adminLogin.cfm", "home.cfm", "adminarea/index.cfm", "adminarea/admin.cfm", "adminarea/login.cfm", "panel-administracion/index.cfm", "panel-administracion/admin.cfm", "modelsearch/index.cfm", "modelsearch/admin.cfm", "administrator/index.cfm", "admincontrol/login.cfm", "adm/admloginuser.cfm", "admloginuser.cfm", "admin2.cfm", "admin2/login.cfm", "admin2/index.cfm", "adm/index.cfm", "adm.cfm", "affiliate.cfm", "adm_auth.cfm", "memberadmin.cfm", "administratorlogin.cfm", "siteadmin/login.cfm", "siteadmin/index.cfm", "admin/account.php", "admin/index.php", "admin/login.php", "admin/admin.php", "admin_area/admin.php", "admin_area/login.php", "siteadmin/login.php", "siteadmin/index.php", "siteadmin/login.html", "admin_area/index.php", "bb-admin/index.php", "bb-admin/login.php", "bb-admin/admin.php", "admin/home.php", "admin/controlpanel.php", "admin.php", "admin/cp.php", "cp.php", "administrator/index.php", "administrator/login.php", "nsw/admin/login.php", "webadmin/login.php", "admin/admin_login.php", "admin_login.php", "administrator/account.php", "administrator.php", "pages/admin/admin-login.php", "admin/admin-login.php", "admin-login.php", "login.php", "modelsearch/login.php", "moderator.php", "moderator/login.php", "moderator/admin.php", "account.php", "controlpanel.php", "admincontrol.php", "rcjakar/admin/login.php", "webadmin.php", "webadmin/index.php", "webadmin/admin.php", "adminpanel.php", "user.php", "panel-administracion/login.php", "wp-login.php", "adminLogin.php", "admin/adminLogin.php", "home.php", "adminarea/index.php", "adminarea/admin.php", "adminarea/login.php", "panel-administracion/index.php", "panel-administracion/admin.php", "modelsearch/index.php", "modelsearch/admin.php", "admincontrol/login.php", "adm/admloginuser.php", "admloginuser.php", "admin2.php", "admin2/login.php", "admin2/index.php", "adm/index.php", "adm.php", "affiliate.php", "adm_auth.php", "memberadmin.php", "mod/", "adminpanel/", "cms/", "adminx/", "admin1.php", "admin1.html", "admin2.html", "yonetim.php", "yonetim.html", "yonetici.php", "yonetici.html", "ccms/", "ccms/login.php", "ccms/index.php", "maintenance/", "webmaster/", "configuration/", "configure/", "websvn/", "controlpanel/", "admin1.asp", "yonetim.asp", "yonetici.asp", "fileadmin/", "fileadmin.php", "fileadmin.asp", "fileadmin.html", "administration/", "administration.php", "administration.html", "sysadmin.php", "sysadmin.html", "phpmyadmin/", "myadmin/", "sysadmin.asp", "sysadmin/", "ur-admin.asp", "ur-admin.php", "ur-admin.html", "ur-admin/", "Server.php", "Server.html", "Server.asp", "Server/", "wp-admin/", "administr8.php", "administr8.html", "administr8/", "administr8.asp", "administratie/", "admins/", "admins.php", "admins.asp", "admins.html", "administrivia/", "Database_Administration/", "WebAdmin/", "useradmin/", "sysadmins/", "admin1/", "system-administration/", "administrators/", "pgadmin/", "directadmin/", "staradmin/", "ServerAdministrator/", "SysAdmin/", "administer/", "LiveUser_admin/", "sys-admin/", "typo3/", "panel/", "cpanel/", "cPanel/", "cpanel_file/", "platz_login/", "rcLogin/", "blogindex/", "formslogin/", "autologin/", "support_login/", "meta_login/", "manuallogin/", "simpleLogin/", "loginflat/", "utility_login/", "showlogin/", "memlogin/", "members/", "login-redirect/", "sub-login/", "wp-login/", "login1/", "dir-login/", "login_db/", "xlogin/", "smblogin/", "customer_login/", "UserLogin/", "login-us/", "acct_login/", "bigadmin/", "project-admins/", "phppgadmin/", "pureadmin/", "sql-admin/", "radmind/", "openvpnadmin/", "wizmysqladmin/", "vadmind/", "ezsqliteadmin/", "hpwebjetadmin/", "newsadmin/", "adminpro/", "Lotus_Domino_admin/", "bbadmin/", "vmailadmin/", "Indy_admin/", "ccp14admin/", "irc-macadmin/", "banneradmin/", "sshadmin/", "phpldapadmin/", "macadmin/", "administratoraccounts/", "admin4_account/", "admin4_colon/", "radmind-1/", "Super-admin/", "AdminTools/", "cmsadmin/", "SysAdmin2/", "globes_admin/", "cadmins/", "phpSQLiteAdmin/", "navSiteAdmin/", "server_admin_small/", "logo_sysadmin/", "server/", "database_administration/", "power_user/", "system_administration/", "ss_vms_admin_sm/", "manage/"]


def check_domain(host, admin)
  
  if host.include?("http")
     url = host << "/" << admin
  else
     url = "http://" << host << "/" << admin
  end
  
  response = HTTParty.get(url)
  if response.code == 200
    puts "Admin page found: #{url}"
  end
end

def banner

	puts """
                    ----------------------
                    Tool: byakugan.rb v1.0 
                    ----------------------
                    Author: Hearsecurity 
                    Github: https://github.com/hearsecurity 
                    Site: https://hearsectech.wordpress.com
                    --------------------------------

                    Usage: ruby byakugan.rb <domain>
	"""
end

if ARGV.empty?
	banner
else
  puts "\n"
  threads = []
 for admin in admins
   threads << -> (admin) { Thread.new { check_domain(ARGV[0].dup, admin) } }.(admin)
 end
  threads.each { |thr| thr.join }
end
