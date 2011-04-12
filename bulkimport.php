<?php
/**
 * User Bulk Import & Update for Active Directory Integration
 *
 * @package Active Directory Integration
 * @author Christoph Steindorff
 * @since 1.0.1
 */


if ( !defined('WP_LOAD_PATH') ) {

	/** classic root path if wp-content and plugins is below wp-config.php */
	$classic_root = dirname(dirname(dirname(dirname(__FILE__)))) . '/' ;
	
	if (file_exists( $classic_root . 'wp-load.php') )
		define( 'WP_LOAD_PATH', $classic_root);
	else
		if (file_exists( $path . 'wp-load.php') )
			define( 'WP_LOAD_PATH', $path);
		else
			exit("Could not find wp-load.php");
}

// let's load WordPress
require_once( WP_LOAD_PATH . 'wp-load.php');

// turn off possible output buffering
ob_end_flush();


// If the plugin class is not found, die.
if (!class_exists('ADIntegrationPlugin')) {
	die('ADI not installed.');
}


// If we have WordPress MU, die silently.
if (isset($wpmu_version) && $wpmu_version != '') {
	die();
}


// Extend the ADIntegrationPlugin class
class BulkImportADIntegrationPlugin extends ADIntegrationPlugin {

	/**
	 * Output debug informations
	 * 
	 * @param integer level
	 * @param string $notice
	 */
	protected function _log($level = 0, $info = '') {
		if ($level <= $this->_loglevel) {
			switch ($level) {
				case ADI_LOG_DEBUG: 
					$class = 'debug';
					$type  = '[DEBUG]  ';
					break;
				case ADI_LOG_INFO: 
					$class = 'info';
					$type  = '[INFO]   ';
					break;
				case ADI_LOG_NOTICE: 
					$class = 'notice';
					$type = '[NOTICE] ';
					break;
				case ADI_LOG_WARN: 
					$class = 'warn';
					$type = '[WARN]   ';
					break;
				case ADI_LOG_ERROR: 
					$class = 'error';
					$type = '[ERROR]  ';
					break;
				case ADI_LOG_FATAL: 
					$class = 'fatal';
					$type = '[FATAL]  ';
						break;
				default:
					$class = '';
					$type = '';
					
			}
			$output = '<span class="'.$class.'">'.$type;
			$output .= str_replace("\n","<br />         ",$info).'</span><br />';
			echo $output;
			
			if (WP_DEBUG) {
				if ($fh = @fopen($this->_logfile,'a+')) {
					fwrite($fh,$type . str_replace("\n","\n         ",$info) . "\n");
					fclose($fh);
				}
			}		
		}
	}
	
	
	/**
	 * Do Bulk Import
	 * 
	 * @param string $authcode
	 * @return bool true on success, false on error
	 */
	public function bulkimport($authcode)
	{
		global $wp_version;
		
		$this->setLogFile(dirname(__FILE__).'/import.log');
		
		$this->_log(ADI_LOG_INFO,"-------------------------------------\n".
								 "START OF BULK IMPORT\n".
								 date('Y-m-d / H:i:s')."\n".
								 "-------------------------------------\n");
		
		$time = time();
		$all_users = array();
		
		// Is bulk import enabled?
		if (!$this->_bulkimport_enabled) {
			$this->_log(ADI_LOG_INFO,'Bulk Import is disabled.');
			return false;
		}
		
		// DO we have the correct Auth Code?
		if ($this->_bulkimport_authcode !== $authcode) {
			$this->_log(ADI_LOG_ERROR,'Wrong Auth Code.');
			return false;
		}
		
		$ad_password = $this->_decrypt($this->_bulkimport_pwd);
		
		// Log informations
		$this->_log(ADI_LOG_INFO,"Options for adLDAP connection:\n".
					  "- base_dn: $this->_base_dn\n".
					  "- domain_controllers: $this->_domain_controllers\n".
					  "- ad_username: $this->_bulkimport_user\n".
					  "- ad_password: **not shown**\n".
					  "- ad_port: $this->_port\n".
					  "- use_tls: ".(int) $this->_use_tls."\n".
					  "- network timeout: ". $this->_network_timeout);
			
		// Connect to Active Directory
		try {
			$this->_adldap = @new adLDAP(array(
						"base_dn" => $this->_base_dn, 
						"domain_controllers" => explode(';', $this->_domain_controllers),
						"ad_username" => $this->_bulkimport_user, 		// Bulk Import User
						"ad_password" => $ad_password, 			  		// password
						"ad_port" => $this->_port,                		// AD port
						"use_tls" => $this->_use_tls,            		// secure?
						"network_timeout" => $this->_network_timeout	// network timeout
						));
		} catch (Exception $e) {
    		$this->_log(ADI_LOG_ERROR,'adLDAP exception: ' . $e->getMessage());
    		return false;
		}
		$this->_log(ADI_LOG_NOTICE,'adLDAP object created.');
		$this->_log(ADI_LOG_INFO,'Domain Controller: ' . $this->_adldap->get_last_used_dc());
		
		// Getting Bulk User Info
		// TODO delete this after successfull testing
		//$userinfo = $this->_adldap->user_info($this->_bulkimport_user, array('cn','dn'));
		//$this->_log(ADI_LOG_INFO,'Bulk User Info: ' . print_r($userinfo,true));
		
		// Let's give us some more time (60 minutes)
		$max_execution_time = ini_get('max_execution_time');
		if ($max_execution_time < 3600) {
			ini_set('max_execution_time', 3600);
		}
		if (ini_get('max_execution_time') < 3600) {
			$this->_log(ADI_LOG_ERROR,'Can not increase PHP configuration option "max_execution_time".');
			return false;
		}

		// get all users of the chosen security groups
		$groups = explode(";",$this->_bulkimport_security_groups);
		if (count($groups) < 1) {
			$this->_log(ADI_LOG_WARN,'No security group.');
			return false;
		}
		
		//$groups = array('Domänen-Benutzer'); 
		
		foreach ($groups AS $group) {
			// get all members of group
			$group = trim($group);
			if ($group != '')  {
				// do we have a groupid?
		        if (($pos = stripos($group,'id:')) !== false) {
        			$pgid = substr($group,$pos+3);
        			$members = $this->_adldap->group_members_by_primarygroupid($pgid, true);
		        } else {
					$members = $this->_adldap->group_members($group, true);
		        }
				if ($members) {
					$this->_log(ADI_LOG_INFO,count($members).' Members of group "'.$group.'".');
					$this->_log(ADI_LOG_DEBUG,'Members of group "'.$group.'": ' . implode(', ',$members));
					foreach ($members AS $user) {
						$all_users[$user] = $user;
					}
				} else {
					$this->_log(ADI_LOG_ERROR,'Error retrieving group members for group "'.$group.'".');
				}
			} else {
				$this->_log(ADI_LOG_WARN,'No group. Nothing to do.');
			} 
		}
		
		$elapsed_time = time() - $time;
		$this->_log(ADI_LOG_INFO,'Number of users to import/update: '.count($all_users).' (list generated in '. $elapsed_time .' seconds)');
	
		if (version_compare($wp_version, '3.1', '<')) {
			require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
		}
		
		
		// import all relevant users
		$added_users = 0;
		$updated_users = 0;
		foreach ($all_users AS $username) {
			
			$ad_username = $username;

	
			// getting user data
			$user = get_userdatabylogin($username);
			
			// role
			$user_role = $this->_get_user_role_equiv($ad_username); // important: use $ad_username not $username
	
			// userinfo from AD
			$this->_log(ADI_LOG_DEBUG, 'ATTRIBUTES TO LOAD: '.print_r($this->_all_user_attributes, true));
			$userinfo = $this->_adldap->user_info($ad_username, $this->_all_user_attributes);
			$userinfo = $userinfo[0];
			$this->_log(ADI_LOG_DEBUG,"USERINFO[0]: \n".print_r($userinfo,true));
			
			// get display name
			$display_name = $this->_get_display_name_from_AD($username, $userinfo);
		
			// Create new users or update them
			if (!$user OR ($user->user_login != $username)) {
				$user_id = $this->_create_user($ad_username, $userinfo, $display_name, $user_role, '', true);
				$added_users++;
			} else {
				$user_id = $this->_update_user($ad_username, $userinfo, $display_name, $user_role, '', true);
				$updated_users++;
			}
			
			// load user object
			if (!$user_id) {
				$user_id = username_exists($username);
				$this->_log(ADI_LOG_NOTICE,'user_id: '.$user_id);
			}
		}
		// Logging	
		$elapsed_time = time() - $time;
		$this->_log(ADI_LOG_INFO,$added_users . ' Users added.');
		$this->_log(ADI_LOG_INFO,$updated_users . ' Users updated.');
		$this->_log(ADI_LOG_INFO,'In '. $elapsed_time . ' seconds.');
		
		$this->_log(ADI_LOG_INFO,"-------------------------------------\n".
								 "END OF BULK IMPORT\n".
								 date('Y-m-d / H:i:s')."\n".
								 "-------------------------------------\n");		

		return true;
	}
		
}

define('ADINTEGRATION_DEBUG', true);

if (class_exists('ADIntegrationPlugin')) {
	$ADI = new BulkImportADIntegrationPlugin();
} else {
	die('Plugin missing.');
}

// Log Level
if (isset($_REQUEST['debug'])) {
	$ADI->setLogLevel(ADI_LOG_DEBUG);
} else {
	$ADI->setLogLevel(ADI_LOG_INFO);
}

?>
<html>
	<head>
		<title>ADI Bulk Import</title>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<style type="text/css">
			h1 {
				font-size: 14pt;
			}
			#output {
				border: 1px solid #eee;
				background-color: #f9f9f9;
				font-family: consolas, courier, monospace;
				font-size: 10pt;
				white-space:pre; 
			}
			
			.debug {
				color: #606060;
			}
			
			.info {
				color: #000000;
			}
			
			.notice {
				color: #0000A0;
			}
			
			.warn {
				color: #f08000;
			}
			
			.error {
				color: #f04020;
			}
			
			.fatal  {
				color: #ff0000;
				font-weight: bold;
			}

		</style>
		
	</head>
	<body>
		<h1 style="font-size: 14pt">AD Integration Bulk Import</h1>
		
<?php 
if (function_exists('ldap_connect')) {
	echo "openLDAP installed\n";
} else {
	die('openLDAP not installed');
}
?>
		<div id="output">
<?php


// Let's go!
$result = $ADI->bulkimport($_REQUEST['auth']);

?>
		</div>
<?php
if ($result) { 
	echo 'Bulk Import returned no error.';
} else {
	echo 'Error on Bulk Import.';
}

?>

	</body>
</html>