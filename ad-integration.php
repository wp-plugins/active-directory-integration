<?php

/*
Plugin Name: Active Directory Integration 
Version: 0.9.8-dev
Plugin URI: http://blog.ecw.de/wp-ad-integration
Description: Allows WordPress to authenticate, authorize, create and update users through Active Directory
Author: Christoph Steindorff, ECW GmbH
Author URI: http://blog.ecw.de/

The work is derived from version 1.0.5 of the plugin Active Directory Authentication:
OriginalPlugin URI: http://soc.qc.edu/jonathan/wordpress-ad-auth
OriginalDescription: Allows WordPress to authenticate users through Active Directory
OriginalAuthor: Jonathan Marc Bearak
OriginalAuthor URI: http://soc.qc.edu/jonathan
*/

/*
	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/


if (!class_exists('ADIntegrationPlugin')) {
class ADIntegrationPlugin {
	
	// version of needed DB table structure
	const DB_VERSION = "0.9";
	
	// name of our own table
	const TABLE_NAME = 'adintegration';
	
	// is the user authenticated?
	public $_authenticated = false;
	
	protected $_minium_WPMU_version = '2.8';
	protected $_minium_WP_version = '2.8';
	
	// adLDAP-object
	protected $_adldap;
	
	// Should a new user be created automatically if not already in the WordPress database?
	protected $_auto_create_user = false; 
	
	// Should the users be updated in the WordPress database everytime they logon? (Works only if automatic user creation is set.
	protected $_auto_update_user = false;

	// Account Suffix (will be appended to all usernames created in WordPress, as well as used in the Active Directory authentication process
	protected $_account_suffix = ''; 
	
	// Should the account suffix be appended to the usernames created in WordPress?
	protected $_append_suffix_to_new_users = false;

	// Domain Controllers (separate with semicolons)
	protected $_domain_controllers = '';
	
	// LDAP/AD BASE DN
	protected $_base_dn = '';
	
	// Role Equivalent Groups (wp-role1=ad-group1;wp-role2=ad-group2;...)
	protected $_role_equivalent_groups = '';
	
	// Default Email Domain (eg. 'domain.tld')
	protected $_default_email_domain = '';
	
	// Port on which AD listens (default 389)
	protected $_port = 389;
	
	// Username for non-anonymous requests to AD
	protected $_bind_user = ''; 
	
	// Password for non-anonymous requests to AD
	protected $_bind_pwd = '';
	
	// Secure the connection between the Drupal and the LDAP servers using TLS.
	protected $_use_tls = false; 
	
	// Check Login authorization by group membership
	protected $_authorize_by_group = false;
	
	// Group name for authorization.
	protected $_authorization_group = '';
	
	// Maximum number of failed login attempts before the account is blocked
	protected $_max_login_attempts = 3;
	
	// Number of seconds an account is blocked after the maximum number of failed login attempts is reached.
	protected $_block_time = 30;
	
	// Send email to user if his account is blocked.
	protected $_user_notification = false;
	
	// Send email to admin if a user account is blocked.
	protected $_admin_notification = false;
	
	// Administrator's e-mail address(es) where notifications should be sent to.		
	protected $_admin_email = '';
	
	// Set user's display_name to an AD attribute or to username if left blank
	// Possible values: description, displayname, mail, sn, cn, givenname, samaccountname
	protected $_display_name = '';
	
	// Enable/Disable password changes 
	protected $_enable_password_change = false;

	// All options and its types 
	protected $_all_options = array(
			array(name => 'AD_Integration_account_suffix', type => 'string'),
			array(name => 'AD_Integration_auto_create_user', type => 'bool'),
			array(name => 'AD_Integration_auto_update_user', type => 'bool'),
			array(name => 'AD_Integration_append_suffix_to_new_users', type => 'bool'),
			array(name => 'AD_Integration_domain_controllers', type => 'string'),
			array(name => 'AD_Integration_base_dn', type => 'string'),
			array(name => 'AD_Integration_role_equivalent_groups', type => 'string'),
			array(name => 'AD_Integration_default_email_domain', type => 'string'),
			array(name => 'AD_Integration_port', type => 'int'),
			array(name => 'AD_Integration_bind_user', type => 'string'),
			array(name => 'AD_Integration_bind_pwd', type => 'string'),
			array(name => 'AD_Integration_use_tls', type => 'bool'),
			array(name => 'AD_Integration_authorize_by_group', type => 'bool'),
			array(name => 'AD_Integration_authorization_group', type => 'string'),
			array(name => 'AD_Integration_max_login_attempts', type => 'int'),
			array(name => 'AD_Integration_block_time', type => 'int'),
			array(name => 'AD_Integration_user_notification', type => 'bool'),
			array(name => 'AD_Integration_admin_notification', type => 'bool'),
			array(name => 'AD_Integration_admin_email', type => 'string'),
			array(name => 'AD_Integration_display_name', type => 'string'),
			array(name => 'AD_Integration_enable_password_fields', type => 'bool')
		);

	/**
	 * Constructor
	 */
	public function __construct() {
		global $wp_version, $wpmu_version, $wpdb, $wpmuBaseTablePrefix;
		
		define('IS_WPMU', ($wpmu_version != ''));
		
		// define folder constant  
		define('ADINTEGRATION_FOLDER', basename(dirname(__FILE__)));

		// Load up the localization file if we're using WordPress in a different language
		// Place it in this plugin's folder and name it "ad-auth-[value in wp-config].mo"
		load_plugin_textdomain( 'ad-integration', WP_PLUGIN_URL.'/'.ADINTEGRATION_FOLDER, ADINTEGRATION_FOLDER );

		// Load Options
		$this->_load_options();
				
		if (isset($_GET['activate']) and $_GET['activate'] == 'true') {
			add_action('init', array(&$this, 'initialize_options'));
		}
		
		add_action('admin_menu', array(&$this, 'add_options_page'));
		add_filter('contextual_help', array(&$this, 'contextual_help'), 10, 2);
		
		// DO WE HAVE LDAP SUPPORT?
		if (function_exists('ldap_connect')) {
			if (version_compare($wp_version, '2.8', '>=')) {
				add_filter('authenticate', array(&$this, 'authenticate'), 10, 3);
			} else {
				add_action('wp_authenticate', array(&$this, 'authenticate'), 10, 2);
			}
			
			add_action('lost_password', array(&$this, 'disable_function'));
			add_action('retrieve_password', array(&$this, 'disable_function'));
			add_action('password_reset', array(&$this, 'disable_function'));
		    add_action('admin_print_styles', array(&$this, 'load_styles'));
			add_action('check_passwords', array(&$this, 'generate_password'), 10, 3);
			
			add_filter('check_password', array(&$this, 'override_password_check'), 10, 4);
			
			if (!$this->_enable_password_change) {
				add_filter('show_password_fields', array(&$this, 'disable_password_fields'));
			}
			
			if (!class_exists('adLDAP')) {
				require 'ad_ldap/adLDAP.php';
			}
		}
	}
	
	
	public function load_styles() {
		 
		wp_register_style('adintegration', WP_PLUGIN_URL.'/'.ADINTEGRATION_FOLDER.'/css/adintegration.css',false, '1.7.1', 'screen');
		wp_enqueue_style('adintegration');
		//die(PLUGINDIR.'/'.ADINTEGRATION_FOLDER.'/css/adintegration.css');
	}
	

	/*************************************************************
	 * Plugin hooks
	 *************************************************************/
	
	/**
	 * Add options for this plugin to the database.
	 */
	public function initialize_options() {
		
		if (IS_WPMU) {
			if (is_site_admin()) {
				add_site_option('AD_Integration_account_suffix', '', 'Account Suffix (will be appended to all usernames created in WordPress, as well as used in the Active Directory authentication process');
				add_site_option('AD_Integration_auto_create_user', false, 'Should a new user be created automatically if not already in the WordPress database?');
				add_site_option('AD_Integration_auto_update_user', false, 'Should the users be updated in the WordPress database everytime they logon? (Works only if automatic user creation is set.)');
				add_site_option('AD_Integration_append_suffix_to_new_users', '', false, 'Should the account suffix be appended to the usernames created in WordPress?');
				add_site_option('AD_Integration_domain_controllers', '', 'Domain Controllers (separate with semicolons)');
				add_site_option('AD_Integration_base_dn', '', 'Base DN');
				add_site_option('AD_Integration_role_equivalent_groups', '', 'Role Equivalent Groups');
				add_site_option('AD_Integration_default_email_domain', '', 'Default Email Domain');
				add_site_option('AD_Integration_port', '389', 'Port on which AD listens (default 389).');
				add_site_option('AD_Integration_bind_user', '', 'Username for non-anonymous requests to AD.');
				add_site_option('AD_Integration_bind_pwd', '', 'Password for non-anonymous requests to AD.');
				add_site_option('AD_Integration_use_tls', false, 'Secure the connection between the Drupal and the LDAP servers using TLS.');
				add_site_option('AD_Integration_authorize_by_group', false, 'Check Login authorization by group membership.');
				add_site_option('AD_Integration_authorization_group', '', 'Group name for authorization.');
				add_site_option('AD_Integration_max_login_attempts', '3', 'Maximum number of failed login attempts before the account is blocked.');
				add_site_option('AD_Integration_block_time', '30', 'Number of seconds an account is blocked after the maximum number of failed login attempts is reached.');
				add_site_option('AD_Integration_user_notification', false, 'Send email to user if his account is blocked.');
				add_site_option('AD_Integration_admin_notification', false, 'Send email to admin if a user account is blocked.');
				add_site_option('AD_Integration_admin_email', '', "Administrator's email address where notifications should be sent to.");
				add_site_option('AD_Integration_display_name', '', "Set user's display_name to an AD attribute or to username if left blank.");
				add_site_option('AD_Integration_enable_password_change', false, 'Enable the ability of the users to change their WP passwords.');
			}
		} else {
			if (current_user_can('manage_options')) {
				add_option('AD_Integration_account_suffix', '', 'Account Suffix (will be appended to all usernames created in WordPress, as well as used in the Active Directory authentication process');
				add_option('AD_Integration_auto_create_user', false, 'Should a new user be created automatically if not already in the WordPress database?');
				add_option('AD_Integration_auto_update_user', false, 'Should the users be updated in the WordPress database everytime they logon? (Works only if automatic user creation is set.)');
				add_option('AD_Integration_append_suffix_to_new_users', '', false, 'Should the account suffix be appended to the usernames created in WordPress?');
				add_option('AD_Integration_domain_controllers', '', 'Domain Controllers (separate with semicolons)');
				add_option('AD_Integration_base_dn', '', 'Base DN');
				add_option('AD_Integration_role_equivalent_groups', '', 'Role Equivalent Groups');
				add_option('AD_Integration_default_email_domain', '', 'Default Email Domain');
				add_option('AD_Integration_port', '389', 'Port on which AD listens (default 389).');
				add_option('AD_Integration_bind_user', '', 'Username for non-anonymous requests to AD.');
				add_option('AD_Integration_bind_pwd', '', 'Password for non-anonymous requests to AD.');
				add_option('AD_Integration_use_tls', false, 'Secure the connection between the Drupal and the LDAP servers using TLS.');
				add_option('AD_Integration_authorize_by_group', false, 'Check Login authorization by group membership.');
				add_option('AD_Integration_authorization_group', '', 'Group name for authorization.');
				add_option('AD_Integration_max_login_attempts', '3', 'Maximum number of failed login attempts before the account is blocked.');
				add_option('AD_Integration_block_time', '30', 'Number of seconds an account is blocked after the maximum number of failed login attempts is reached.');
				add_option('AD_Integration_user_notification', false, 'Send email to user if his account is blocked.');
				add_option('AD_Integration_admin_notification', false, 'Send email to admin if a user account is blocked.');
				add_option('AD_Integration_admin_email', '', "Administrator's email address where notifications should be sent to.");
				add_option('AD_Integration_display_name', '', "Set user's display_name to an AD attribute or to username if left blank.");
				add_option('AD_Integration_enable_password_change', false, 'Enable or disabled the ability to the change user WP passwords.');
			}
		}
	}
	
	
	

	/**
	 * Add an options pane for this plugin.
	 */
	public function add_options_page() {
	
		if (IS_WPMU && is_site_admin()) {
			// WordPress MU
			if (function_exists('add_submenu_page')) {
				add_submenu_page('wpmu-admin.php', __('Active Directory Integration'), __('Active Directory Integration'), 'manage_options', __FILE__, array(&$this, '_display_options_page'));
			}
		}

		if (!IS_WPMU) {
			// WordPress Standard
			if (function_exists('add_options_page')) {
				add_options_page('Active Directory Integration', 'Active Directory Integration', 9, __FILE__, array(&$this, '_display_options_page'));
			}
		}
	}

	/**
	 * Wrapper
	 * 
	 * @param $arg1 WP_User or username
	 * @param $arg2 username or password
	 * @param $arg3 passwprd or empty
	 * @return WP_User
	 */
	public function authenticate($arg1 = NULL, $arg2 = NULL, $arg3 = NULL) {
		global $wp_version, $wpmu_version;
		
		if (IS_WPMU) {
			$version = $wpmu_version;
		} else {
			$version = $wp_version;
		}
		
		if (version_compare($version, '2.8', '>=')) {
			return $this->ad_authenticate($arg1, $arg2, $arg3); 
		} else {
			return $this->ad_authenticate(NULL, $arg1, $arg2);
		}
	}
	

	
	/**
	 * If the REMOTE_USER evironment is set, use it as the username.
	 * This assumes that you have externally authenticated the user.
	 */
	public function ad_authenticate($user = NULL, $username = '', $password = '') {

		$user_id = NULL;
		
		$this->_authenticated = false;
		
		// IMPORTANT!
		$username = strtolower($username);
		
		// Load options from WordPress-DB.
		$this->_load_options();
		
		// Connect to Active Directory			
		$this->_adldap = new adLDAP(array(
					"account_suffix" => $this->_account_suffix,
					"base_dn" => $this->_base_dn, 
					"domain_controllers" => explode(';', $this->_domain_controllers),
					"ad_username" => $this->_bind_user,      // AD Bind User
					"ad_password" => $this->_bind_pwd,       // password
					"ad_port" => $this->_port,               // AD port
					"use_tls" => $this->_use_tls             // secure?
					));
		
		// Check for maximum login attempts
		if ($this->_max_login_attempts > 0) {
			$failed_logins = $this->_get_failed_logins_within_block_time($username);
			if ($failed_logins >= $this->_max_login_attempts) {
				$this->_authenticated = false;

				// e-mail notfications if user is blocked
				if ($this->_user_notification) {
					$this->_notify_user($username);
				}
				if ($this->_admin_notification) {
					$this->_notify_admin($username);
				}
				
				// Show the blocking page to the user
				$this->_display_blocking_page($username);
				die(); // important !
			} 
		}
		
		// This is where the action is.
		if ( $this->_adldap->authenticate($username, $password) )
		{	
			$this->_authenticated = true;
		}

		if ( $this->_authenticated == false )
		{
			$this->_authenticated = false;
			$this->_store_failed_login($username);
			return false;			
		}
		
		// Cleanup old database entries 
		$this->_cleanup_failed_logins($username); 

		// Check the authorization
		if ($this->_authorize_by_group) {
			if ($this->_check_authorization_by_group($username)) {
				$this->_authenticated = true;
			} else {
				$this->_authenticated = false;
				return false;	
			}
		}
		
		$ad_username = $username;
		
		// should the account suffix be used for the new username?
		if ($this->_append_suffix_to_new_users) {
			$username .= $this->_account_suffix;
		}
		
		// Create new users automatically, if configured
		$user = get_userdatabylogin($username);
		
		if (! $user OR ($user->user_login != $username)) {
			$user_role = $this->_get_user_role_equiv($ad_username);
			if ($this->_auto_create_user || $user_role != '' ) {
					// create user
					$userinfo = $this->_adldap->user_info($ad_username, array('sn', 'givenname', 'mail', 'displayName', 'description', 'cn'));
					$userinfo = $userinfo[0];
					$email = $userinfo['mail'][0];
					$first_name = $userinfo['givenname'][0];
					$last_name = $userinfo['sn'][0];
					$display_name = $this->_get_display_name_from_AD($username, $userinfo);
					$user_id = $this->_create_user($ad_username, $email, $first_name, $last_name, $display_name, $user_role);


			} else {
				// Bail out to avoid showing the login form
				return new WP_Error('invalid_username', __('<strong>ERROR</strong>: This user exists in Active Directory, but has not been granted access to this installation of WordPress.'));
			}
		} else {
			
			//  update known users if configured
			if ($this->_auto_create_user AND $this->_auto_update_user) {
				// Update users role
				$user_role = $this->_get_user_role_equiv($ad_username);
				$userinfo = $this->_adldap->user_info($ad_username, array('sn', 'givenname', 'mail', 'displayName', 'description', 'cn'));
				$userinfo = $userinfo[0];
				
				$email = $userinfo['mail'][0];
				$first_name = $userinfo['givenname'][0];
				$last_name = $userinfo['sn'][0];
				$common_name = $userinfo['cn'][0];
				$display_name = $this->_get_display_name_from_AD($username, $userinfo);
				$user_id = $this->_update_user($ad_username, $email, $first_name, $last_name, $display_name, $user_role);
			}
		}
		
		// load user object
		if (!$user_id) {
			require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR .'registration.php'); 
			$user_id = username_exists($username);
		}
		$user = new WP_User($user_id);

		return $user;
	}	
	

	

	/*
	 * Skip the password check, since we've externally authenticated.
	 */
	public function override_password_check($check, $password, $hash, $user_id) {
		if ( $this->_authenticated == true ) 
		{
			return true;
		}
		else
		{
			return $check;
		}
	}

	/*
	 * Generate a password for the user. This plugin does not
	 * require the user to enter this value, but we want to set it
	 * to something nonobvious.
	 */
	public function generate_password($username, $password1, $password2) {
		$password1 = $password2 = $this->_get_password();
	}

	/*
	 * Used to disable certain display elements, e.g. password
	 * fields on profile screen.
	 */
	public function disable_password_fields($show_password_fields) {
		return false;
	}

	/*
	 * Used to disable certain login functions, e.g. retrieving a
	 * user's password.
	 */
	public function disable_function() {
		die('Disabled');
	}
	
	/**
	 * Shows the contexual help on the options/admin screen.
	 * 
	 * @param $help
	 * @param $screen
	 * @return string help message
	 */
	public function contextual_help ($help, $screen) {
		if ($screen == 'settings_page_' . ADINTEGRATION_FOLDER . '/ad-integration'
		                 || $screen == 'wpmu-admin_page_' . ADINTEGRATION_FOLDER . '/ad-integration') {
			$help .= '<h5>' . __('Active Directory Integration Help','ad-integration') . '</h5><div class="metabox-prefs">';
			$help .= '<a href="http://blog.ecw.de/wp-ad-integration">'.__ ('Overview','ad-integration').'</a><br/>';
			$help .= '<a href="http://wordpress.org/extend/plugins/active-directory-integration/faq/">'.__ ('FAQ', 'ad-integration').'</a><br/>';
			$help .= '<a href="http://wordpress.org/extend/plugins/active-directory-integration/changelog/">'.__ ('Changelog', 'ad-integration').'</a><br/>';
			$help .= '<a href="http://wordpress.org/tags/active-directory-integration">'.__ ('Support-Forum', 'ad-integration').'</a><br/>';
			
			$help .= '</div>';
		}
		return $help;
	}	
	
	/****************************************************************
	 * STATIC FUNCTIONS
	 ****************************************************************/

	/**
	 * Determine global table prefix, usually "wp_".
	 * 
	 * @return string table prefix
	 */
	public static function global_db_prefix() {
		global $wpmu_version, $wpdb, $wpmuBaseTablePrefix;
		
		// define table prefix
		if ($wpmu_version != '') {
			return $wpmuBaseTablePrefix;
		} else {
			return $wpdb->prefix;
		}
	}

	
	/**
	 * Adding the needed table to database and store the db version in the
	 * options table on plugin activation.
	 */
	public static function activate() {
		global $wpdb, $wpmu_version;
		
		//$table_name = $wpdb->prefix . ADIntegrationPlugin::TABLE_NAME;
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		
		if ($wpmu_version != '') {
			$db_version = get_site_option('AD_Integration_db_version');
		} else {
			$db_version = get_option('AD_Integration_db_version');
		}
		
		if (($wpdb->get_var("show tables like '$table_name'") != $table_name) OR ($db_version != ADIntegrationPlugin::DB_VERSION)) { 
	      
	    	$sql = 'CREATE TABLE ' . $table_name . ' (
		  			id bigint(20) NOT NULL AUTO_INCREMENT,
		  			user_login varchar(60),
		  			failed_login_time bigint(11),
		  			UNIQUE KEY id (id)
				  );';
	
			require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
	      	dbDelta($sql);
	      
	   		// store db version in the options
	      	if ($wpmu_version != '') {
	      		add_site_option('AD_Integration_db_version', ADIntegrationPlugin::DB_VERSION, 'Version of the table structure');
	      	} else {
		   		add_option('AD_Integration_db_version', ADIntegrationPlugin::DB_VERSION, 'Version of the table structure');
	      	}
	   }
	}
	
	
	/**
	 * Delete the table from database and delete the db version from the
	 * options table on plugin deactivation.
	 */
	public static function deactivate() {
		global $wpdb, $wpmu_version;
		
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		
		// drop table
		$wpdb->query('DROP TABLE IF EXISTS '.$table_name);
		
		// delete option
		if ($wpmu_version != '') {
			delete_site_option('AD_Integration_db_version');
		} else {
			delete_option('AD_Integration_db_version');
		}
	}	
	
	
	/**
	 * removes the plugin options from options table.
	 */
	public static function uninstall($echo=false) {
		foreach($this->_all_options as $option) {
			$delete_setting = delete_option($option['name']);
			if ($echo) {
				if($delete_setting) {
					echo '<font color="green">';
					printf(__('Setting Key \'%s\' has been deleted.', 'MiniMetaWidget'), "<strong><em>{$option['name']}</em></strong>");
					echo '</font><br />';
				} else {
					echo '<font color="red">';
					printf(__('Error deleting Setting Key \'%s\'.', 'MiniMetaWidget'), "<strong><em>{$option['name']}</em></strong>");
					echo '</font><br />';
				}
			}
		}
	}
	
	



	/*************************************************************
	 * Functions
	 *************************************************************/
	
	
	
	/**
	 * Loads the options from WordPress-DB
	 */
	protected function _load_options() {
		if (IS_WPMU) {
			$this->_auto_create_user 			= (bool)get_site_option('AD_Integration_auto_create_user');
			$this->_auto_update_user 			= (bool)get_site_option('AD_Integration_auto_update_user');
			$this->_account_suffix		 		= get_site_option('AD_Integration_account_suffix');
			$this->_append_suffix_to_new_users 	= get_site_option('AD_Integration_append_suffix_to_new_users');
			$this->_domain_controllers 			= get_site_option('AD_Integration_domain_controllers');
			$this->_base_dn						= get_site_option('AD_Integration_base_dn');
			$this->_bind_user 					= get_site_option('AD_Integration_bind_user');
			$this->_bind_pwd 					= get_site_option('AD_Integration_bind_pwd');
			$this->_port 						= get_site_option('AD_Integration_port');
			$this->_use_tls 					= get_site_option('AD_Integration_use_tls');
			$this->_default_email_domain 		= get_site_option('AD_Integration_default_email_domain');
			$this->_authorize_by_group 			= (bool)get_site_option('AD_Integration_authorize_by_group');
			$this->_authorization_group 		= get_site_option('AD_Integration_authorization_group');
			$this->_role_equivalent_groups 		= get_site_option('AD_Integration_role_equivalent_groups');
			$this->_max_login_attempts 			= (int)get_site_option('AD_Integration_max_login_attempts');
			$this->_block_time 					= (int)get_site_option('AD_Integration_block_time');
			$this->_user_notification	  		= (bool)get_site_option('AD_Integration_user_notification');
			$this->_admin_notification			= (bool)get_site_option('AD_Integration_admin_notification');
			$this->_admin_email					= get_site_option('AD_Integration_admin_email');
			$this->_display_name				= get_site_option('AD_Integration_display_name');
			$this->_enable_password_change     = get_site_option('AD_Integration_enable_password_change');
		} else {
			$this->_auto_create_user 			= (bool)get_option('AD_Integration_auto_create_user');
			$this->_auto_update_user 			= (bool)get_option('AD_Integration_auto_update_user');
			$this->_account_suffix		 		= get_option('AD_Integration_account_suffix');
			$this->_append_suffix_to_new_users 	= get_option('AD_Integration_append_suffix_to_new_users');
			$this->_domain_controllers 			= get_option('AD_Integration_domain_controllers');
			$this->_base_dn						= get_option('AD_Integration_base_dn');
			$this->_bind_user 					= get_option('AD_Integration_bind_user');
			$this->_bind_pwd 					= get_option('AD_Integration_bind_pwd');
			$this->_port 						= get_option('AD_Integration_port');
			$this->_use_tls 					= get_option('AD_Integration_use_tls');
			$this->_default_email_domain 		= get_option('AD_Integration_default_email_domain');
			$this->_authorize_by_group 			= (bool)get_option('AD_Integration_authorize_by_group');
			$this->_authorization_group 		= get_option('AD_Integration_authorization_group');
			$this->_role_equivalent_groups 		= get_option('AD_Integration_role_equivalent_groups');
			$this->_max_login_attempts 			= (int)get_option('AD_Integration_max_login_attempts');
			$this->_block_time 					= (int)get_option('AD_Integration_block_time');
			$this->_user_notification	  		= (bool)get_option('AD_Integration_user_notification');
			$this->_admin_notification			= (bool)get_option('AD_Integration_admin_notification');
			$this->_admin_email					= get_option('AD_Integration_admin_email');
			$this->_display_name				= get_option('AD_Integration_display_name');
			$this->_enable_password_change     = get_option('AD_Integration_enable_password_change');
		}
	}
	
	
	/**
	 * Saves the options to the sitewide options store. This is only needed for WPMU.
	 * 
	 * @param $arrPost the POST-Array with the new options
	 * @return unknown_type
	 */
	protected function _save_wpmu_options($arrPost) {
		if (IS_WPMU) {
			update_site_option('AD_Integration_auto_create_user', (bool)$arrPost['AD_Integration_auto_create_user']);
			update_site_option('AD_Integration_auto_update_user', (bool)$arrPost['AD_Integration_auto_update_user']);
			update_site_option('AD_Integration_account_suffix', $arrPost['AD_Integration_account_suffix']);
			update_site_option('AD_Integration_append_suffix_to_new_users', $arrPost['AD_Integration_append_suffix_to_new_users']);
			update_site_option('AD_Integration_domain_controllers', $arrPost['AD_Integration_domain_controllers']);
			update_site_option('AD_Integration_base_dn', $arrPost['AD_Integration_base_dn']);
			update_site_option('AD_Integration_bind_user', $arrPost['AD_Integration_bind_user']);
			update_site_option('AD_Integration_bind_pwd', $arrPost['AD_Integration_bind_pwd']);
			update_site_option('AD_Integration_port', $arrPost['AD_Integration_port']);
			update_site_option('AD_Integration_use_tls', $arrPost['AD_Integration_use_tls']);
			update_site_option('AD_Integration_default_email_domain', $arrPost['AD_Integration_default_email_domain']);
			update_site_option('AD_Integration_authorize_by_group', (bool)$arrPost['AD_Integration_authorize_by_group']);
			update_site_option('AD_Integration_authorization_group', $arrPost['AD_Integration_authorization_group']);
			update_site_option('AD_Integration_role_equivalent_groups', $arrPost['AD_Integration_role_equivalent_groups']);
			update_site_option('AD_Integration_max_login_attempts', (int)$arrPost['AD_Integration_max_login_attempts']);
			update_site_option('AD_Integration_block_time', (int)$arrPost['AD_Integration_block_time']);
			update_site_option('AD_Integration_user_notification', (bool)$arrPost['AD_Integration_user_notification']);
			update_site_option('AD_Integration_admin_notification', (bool)$arrPost['AD_Integration_admin_notification']);
			update_site_option('AD_Integration_admin_email', $arrPost['AD_Integration_admin_email']);
			update_site_option('AD_Integration_display_name', $arrPost['AD_Integration_display_name']);
			update_site_option('AD_Integration_enable_password_change', $arrPost['AD_Integration_enable_password_change']);
			
			// let�s load the new values
			$this->_load_options();
		}
	}
	
	/**
	 * Determine the display_name to be stored in WP database.
	 * @param $username  the username used to login
	 * @param $userinfo  the array with data returned from AD
	 * @return string  display_name
	 */
	protected function _get_display_name_from_AD($username, $userinfo) {
		if (($this->_display_name == '') OR ($this->_display_name == 'sAMAccountName')) {
			return $username;
		}
		$display_name = $userinfo[$this->_display_name][0];
		if ($display_name == '') {
			return $username;
		} else {
			return $display_name;
		}
	}
	
	/**
	 * Stores the username and the current time in the db.
	 * 
	 * @param $username
	 * @return unknown_type
	 */
	protected function _store_failed_login($username) {
		global $wpdb;
		//$table_name = $wpdb->prefix . $this->table_name;
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		
		$sql = "INSERT INTO $table_name (user_login, failed_login_time) VALUES ('" . $wpdb->escape($username)."'," . time() . ")";
		$result = $wpdb->query($sql);
		
	}
	
	
	/**
	 * Determines the number of failed login attempts of specific user within a specific time from now to the past.
	 * 
	 * @param $username
	 * @param $seconds number of seconds
	 * @return number of failed login attempts  
	 */
	protected function _get_failed_logins_within_block_time($username) {
		global $wpdb;
		//$table_name = $wpdb->prefix . $this->table_name;
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		$time = time() - (int)$this->_block_time;
		
		$sql = "SELECT count(*) AS count from $table_name WHERE user_login = '".$wpdb->escape($username)."' AND failed_login_time >= $time";
		return $wpdb->get_var($sql);
	}
	
	
	/**
	 * Deletes entries from store where the time of failed logins is more than the specified block time ago.
	 * Deletes also all entries of a user, if its username is given . 
	 *  
	 * @param $username
	 * @return 
	 */
	protected function _cleanup_failed_logins($username = NULL) {
		global $wpdb;
		//$table_name = $wpdb->prefix . $this->table_name;
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		$time = time() - $this->_block_time;
		
		$sql = "DELETE FROM $table_name WHERE failed_login_time < $time";
		if ($username != NULL) {
			$sql .= " OR user_login = '".$wpdb->escape($username)."'"; 
		}
		
		$results = $wpdb->query($sql);
	}

	
	/**
	 * Get the rest of the time an account is blocked. 
	 * 
	 * @param $username
	 * @return int seconds the account is blocked, or 0
	 */
	protected function _get_rest_of_blocking_time($username) {
		global $wpdb;
		//$table_name = $wpdb->prefix . $this->_table_name;
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		
		$sql = "SELECT max(failed_login_time) FROM $table_name WHERE user_login = '".$wpdb->escape($username)."'";
		$max_time = $wpdb->get_var($sql);
		
		if ($max_time == NULL ) {
			return 0;
		}
		return ($max_time + $this->_block_time) - time();
		
	}
	

	/**
	 * Generate a random password.
	 * 
	 * @param int $length Length of the password
	 * @return password as string
	 */
	protected function _get_password($length = 10) {
		return substr(md5(uniqid(microtime())), 0, $length);
	}

	
	/**
	 * Create a new WordPress account for the specified username.
	 * @param $username
	 * @param $email
	 * @param $first_name
	 * @param $last_name
	 * @param $display_name
	 * @param $role
	 * @return integer user_id
	 */
	protected function _create_user($username, $email, $first_name, $last_name, $display_name = '', $role = '') {
		$password = $this->_get_password();
		
		if ( $email == '' ) 
		{
			$email = $username . '@' . $this->_default_email_domain;
		}
		
		// append account suffix to new users? 
		if ($this->_append_suffix_to_new_users) {
			$username .= $this->_account_suffix;
		}
		
		
		require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
		wp_create_user($username, $password, $email);
		$user_id = username_exists($username);
		if ( !$user_id ) {
			die("Error creating user!");
		} else {
			update_usermeta($user_id, 'first_name', $first_name);
			update_usermeta($user_id, 'last_name', $last_name);
			
			// set display_name
			if ($display_name != '') {
				wp_update_user(array('ID' => $user_id, 'display_name' => $display_name));
			}
			
			// set role
			if ( $role != '' ) 
			{
				wp_update_user(array("ID" => $user_id, "role" => $role));
			}
		}
		return $user_id;
	}
	
	
	/**
	 * Updates a specific Wordpress user account
	 * 
	 * @param $username
	 * @param $email
	 * @param $first_name
	 * @param $last_name
	 * @param $display_name
	 * @param $role
	 * @return integer user_id
	 */
	protected function _update_user($username, $email, $first_name, $last_name, $display_name='', $role = '') {
		
		if ( $email == '' ) 
		{
			$email = $username . '@' . $this->_default_email_domain;
		}
		
		if ($this->_append_suffix_to_new_users) {
			$username .= $this->_account_suffix;
		}
		
		require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
		$user_id = username_exists($username);
		if ( !$user_id ) {
			die('Error updating user!');
		} else {
			update_usermeta($user_id, 'first_name', $first_name);
			update_usermeta($user_id, 'last_name', $last_name);
			
			// set display_name
			if ($display_name != '') {
				wp_update_user(array('ID' => $user_id, 'display_name' => $display_name));
			}
			
			// set role
			if ( $role != '' ) 
			{
				wp_update_user(array('ID' => $user_id, 'role' => $role));
			}
		}
		return $user_id;
	}
	
	
	/**
	 * Checks if the user is member of the group allowed to login
	 * 
	 * @param $username
	 * @return boolean
	 */
	protected function _check_authorization_by_group($username) {
		if ($this->_authorize_by_group) {
			return $this->_adldap->user_ingroup($username, $this->_authorization_group, true);
		} else {
			return true;
		}
	}
	
	
	/**
	 * Get the first matching role from the list of role equivalent groups the user belongs to.
	 * 
	 * @param $ad_username 
	 * @return string matching role
	 */
	protected function _get_user_role_equiv($ad_username) {
		
		$role_equiv_groups = explode(';', $this->_role_equivalent_groups);
		
		$user_role = '';
		foreach ($role_equiv_groups as $whatever => $role_group)
		{
				$role_group = explode('=', $role_group);
				if ( count($role_group) != 2 )
				{
					next;
				}
				$ad_group = $role_group[0];
				
				$corresponding_role = $role_group[1];
				if ( $this->_adldap->user_ingroup($ad_username, $ad_group, true ) )
				{
					$user_role = $corresponding_role;
					break;
				}
		}
		return $user_role;
	}
	
	
	/**
	 * Send an email to the user who's account is blocked
	 * 
	 * @param $username string
	 * @return unknown_type
	 */
	protected function _notify_user($username)
	{
		// if auto creation is enabled look for the user in AD 
		if ($this->_auto_create_user) {
			
			$userinfo = $this->_adldap->user_info($username, array("sn", "givenname", "mail"));
			if ($userinfo) {
				$userinfo = $userinfo[0];
				$email = $userinfo['mail'][0];
				$first_name = $userinfo['givenname'][0];
				$last_name = $userinfo['sn'][0];	
			} else { 
				return false;
			}
		} else {
			// auto creation is disabled, so look for the user in local database
			require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
			$user_id = username_exists($username);
			if ($user_id) {
				$user_info = get_userdata($user_id);
				$last_name = $user_info->last_name;
				$first_name = $user_info->first_name;
				$email = $user_info->user_email;
			} else {
				return false;
			}
		}

		// do we have a correct email address?
		if (is_email($email)) { 
			$blog_url = get_bloginfo('url');
			$blog_name = get_bloginfo('name');
			$blog_domain = preg_replace ('/^(http:\/\/)(.+)\/.*$/i','$2', $blog_url);
			

			$subject = '['.$blog_name.'] '.__('Account blocked','ad-integration');
			$body = sprintf(__('Someone tried to login to %s (%s) with your username (%s) - but in vain. For security reasons your account is now blocked for %d seconds.','ad-integration'), $blog_name, $blog_url, $username, $this->_block_time);
			$body .= "\n\r";
			$body .= __('THIS IS A SYSTEM GENERATED E-MAIL, PLEASE DO NOT RESPOND TO THE E-MAIL ADDRESS SPECIFIED ABOVE.','ad-integration');
			
			$header = 'From: "WordPress" <wordpress@'.$blog_domain.">\r\n";
			return wp_mail($email, $subject, $body, $header);
		} else {
			return false;
		}
	}

	/**
	 * Notify administrator(s) by e-mail if an account is blocked
	 * 
	 * @param $username username of the blocked account
	 * @return boolean false if no e-mail is sent, true on success
	 */
	protected function _notify_admin($username)
	{
		$arrEmail = array(); // list of recipients
		
		if ($this->_admin_notification) {
			$email = $this->_admin_email;
			
			// Should we use Blog-Administrator's e-mail
			if (trim($email) == '') {
				// Is this an e-mail address?
				if (is_email($email)) {
					$arrEmail[0] = trim(get_bloginfo('admin_email '));
				}
			} else {
				// Using own list of notification recipients
				$arrEmail = explode(";",$email);
				
				// remove wrong e-mail addresses from array
				for ($x=0; $x < count($arrEmail); $x++) {
					$arrEmail[$x] = trim($arrEmail[$x]); // remove possible whitespaces
					if (!is_email($arrEmail[$x])) {
						unset($arrEmail[$x]);
					}
				}
				
			}
			
			// Do we have valid e-mail addresses?
			if (count($arrEmail) > 0) {
				
				if ($this->_auto_create_user) {

					// auto creation is enabled, so look for the user in AD						
					$userinfo = $this->_adldap->user_info($username, array("sn", "givenname", "mail"));
					if ($userinfo) {
						$userinfo = $userinfo[0];
						$first_name = $userinfo['givenname'][0];
						$last_name = $userinfo['sn'][0];	
					} else { 
						return false;
					}
				} else {
					
					// auto creation is disabled, so look for the user in local database
					require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
					$user_id = username_exists($username);
					if ($user_id) {
						$user_info = get_userdata($user_id);
						$last_name = $user_info->last_name;
						$first_name = $user_info->first_name;
					} else {
						return false;
					}
				}
			
				$blog_url = get_bloginfo('url');
				$blog_name = get_bloginfo('name');
				$blog_domain = preg_replace ('/^(http:\/\/)(.+)\/.*$/i','$2', $blog_url);

				$subject = '['.$blog_name.'] '.__('Account blocked','ad-integration');
				$body = sprintf(__('Someone tried to login to %s (%s) with the username "%s" (%s %s) - but in vain. For security reasons this account is now blocked for %d seconds.','ad-integration'), $blog_name, $blog_url, $username, $first_name, $last_name, $this->_block_time);
				$body .= "\n\r";
				$body .= sprintf(__('The login attempt was made from IP-Address: %s','ad-integration'), $_SERVER['REMOTE_ADDR']);
				$body .= "\n\r";
				$body .= __('THIS IS A SYSTEM GENERATED E-MAIL, PLEASE DO NOT RESPOND TO THE E-MAIL ADDRESS SPECIFIED ABOVE.','ad-integration');
				$header = 'From: "WordPress" <wordpress@'.$blog_domain.">\r\n";
				
			
				// send e-mails
				$blnSuccess = true;
				foreach($arrEmail AS $email)  {
					$blnSuccess = ($blnSuccess AND wp_mail($email, $subject, $body, $header));
				}
				return $blnSuccess;
				
				
			} else {
				return false;
			}
		} else {
			return false;
		}
		
		return true;
	} 
	
	
		
		
		
	/**
	 * Show a blocking page for blocked accounts.
	 * 
	 * @param $username
	 */
	protected function _display_blocking_page($username) {
		$seconds = $this->_get_rest_of_blocking_time($username);
			
				?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" <?php language_attributes(); ?>>
<head>
	<title><?php bloginfo('name'); ?> &rsaquo; <?php echo $title; ?></title>
	<meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php bloginfo('charset'); ?>" />
	<script type="text/javascript">
	var seconds = <?php echo $seconds;?>;
	function setTimer()	{
		var aktiv = window.setInterval("countdown()", 1000);
	}	

	function countdown() {
		seconds = seconds - 1;
		if (seconds > 0) {
			document.getElementById('secondsleft').innerHTML = seconds;
		} else {
			window.location.href = '<?php echo $_SERVER['REQUEST_URI']; ?>';
		}
	}
	</script>
	<?php
	wp_admin_css( 'login', true );
	wp_admin_css( 'colors-fresh', true );
	do_action('login_head'); ?>
</head>
<body class="login" onload="setTimer()">

<div id="login"><h1><a href="<?php echo apply_filters('login_headerurl', 'http://wordpress.org/'); ?>" title="<?php echo apply_filters('login_headertitle', __('Powered by WordPress')); ?>"><?php bloginfo('name'); ?></a></h1>
<div id="login_error">
<?php _e('Account blocked for','ad-integration');?> <span id="secondsleft"><?php echo $seconds;?></span> <?php _e('seconds','ad-integration');?>.
</div>
</div>
</body>
</html>
<?php 
		die(); // IMPORTANT
	
	}
	
	
	
	/*
	 * Display the options for this plugin.
	 */
	function _display_options_page() {
		
		if (IS_WPMU && !is_site_admin()) {
			_e('Access denied.', 'ad-integration');
		}
		
		
		// form send?
		if (IS_WPMU && $_POST['action'] == 'update') {
			$this->_save_wpmu_options($_POST);
		} else {
			$this->_load_options();
		}
		
		// Since we have no plugin activation hook for WPMU,
		// we do it here (everytime the admin/options page is shown).
		if (IS_WPMU) {
			$this->activate();
		}

?>

<div class="wrap" style="background-image: url('<?php if (IS_WPMU) { echo WPMU_PLUGIN_URL; } else { echo WP_PLUGIN_URL; } echo '/'.basename(dirname(__FILE__)); ?>/ad-integration.png'); background-repeat: no-repeat; background-position: right 50px;">

  <div id="icon-options-general" class="icon32">
   		<br/>
  </div>
  <h2><?php if (IS_WPMU) { 
  	_e('Active Directory Integration', 'ad-integration');
  } else {
  	_e('Options › Active Directory Integration', 'ad-integration');
  }?></h2>
  

  <div class="wrap">
  
  	<?php 
  	if (!function_exists('ldap_connect')) {
  		echo '<h3>' . __('ATTENTION: You have no LDAP support. This plugin won´t work.', 'ad-integration') . '</h3>';
  	}
	?>
  

	<form action="<?php if (!IS_WPMU)echo 'options.php'; ?>" method="post">
		<input type="hidden" name="action" value="update" />
    	<input type="hidden" name="page_options" value="AD_Integration_auto_create_user,AD_Integration_base_dn,AD_Integration_account_suffix,AD_Integration_domain_controllers,AD_Integration_role_equivalent_groups,AD_Integration_default_email_domain,AD_Integration_port,AD_Integration_bind_user,AD_Integration_bind_pwd,AD_Integration_use_tls,AD_Integration_append_suffix_to_new_users,AD_Integration_authorization_group,AD_Integration_authorize_by_group,AD_Integration_auto_update_user,AD_Integration_max_login_attempts,AD_Integration_block_time,AD_Integration_admin_notification,AD_Integration_user_notification,AD_Integration_admin_email,AD_Integration_display_name,AD_Integration_enable_password_change" />
    	<?php if (function_exists('wp_nonce_field')): wp_nonce_field('update-options'); endif; ?>

	    <table class="form-table">
      		<tbody>
      			<tr>
					<td colspan="2"><h2 style="font-size: 150%; font-weight: bold;"><?php _e('Active Directory Server', 'ad-integration'); ?></h2></td>
  				</tr>
     
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_domain_controllers"><?php _e('Domain Controllers', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_domain_controllers" id="AD_Integration_domain_controllers" class="regular-text" value="<?php echo $this->_domain_controllers; ?>" /><br />
			          <?php _e('Domain Controllers (separate with semicolons, e.g. "dc1.domain.tld;dc2.domain.tld")', 'ad-integration'); ?>
			        </td>
			      </tr>

			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_port"><?php _e('Port', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_port" id="AD_Integration_port" class="regular-text" 
			          value="<?php echo $this->_port; ?>" /><br />
			          <?php _e('Port on which the AD listens (defaults to "389")', 'ad-integration'); ?>
			        </td>
			      </tr>
      
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_use_tls"><?php _e('Use TLS', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="checkbox" name="AD_Integration_use_tls" id="AD_Integration_use_tls"<?php if ($this->_use_tls) echo ' checked="checked"' ?> value="1" />
			          <?php _e('Secure the connection between the WordPress and the Active Directory Servers using TLS. Note: To use TLS, you must set the LDAP Port to 389.', 'ad-integration'); ?>
			        </td>
			      </tr>
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_bind_user"><?php _e('Bind User', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_bind_user" id="AD_Integration_bind_user" class="regular-text" 
			          value="<?php echo $this->_bind_user; ?>" />
					  <?php _e('Username for non-anonymous requests to AD (e.g. "ldapuser@domain.tld"). Leave empty for anonymous requests.', 'ad-integration'); ?>
			        </td>
			      </tr>
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_bind_pwd"><?php _e('Bind User Password', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="password" name="AD_Integration_bind_pwd" id="AD_Integration_bind_pwd" class="regular-text" 
			          value="<?php echo $this->_bind_pwd; ?>" />
					  <?php _e('Password for non-anonymous requests to AD', 'ad-integration'); ?>
			        </td>
			      </tr>
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_base_dn"><?php _e('Base DN', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_base_dn" id="AD_Integration_base_dn" class="regular-text" 
			          value="<?php echo $this->_base_dn; ?>" />
					  <?php _e('Base DN (e.g., "ou=unit,dc=domain,dc=tld")', 'ad-integration'); ?>
			        </td>
			      </tr>
			    
			      <tr>
					 <td colspan="2"><h2 style="font-size: 150%; font-weight: bold;"><?php _e('User specific settings','ad-integration'); ?></h2></td>
				  </tr>
			    
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_auto_create_user"><?php _e('Automatic User Creation', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="checkbox" name="AD_Integration_auto_create_user" id="AD_Integration_auto_create_user" <?php if ($this->_auto_create_user) echo ' checked="checked"' ?> value="1" />
			          <?php _e('Should a new user be created automatically if not already in the WordPress database?','ad-integration'); ?>
			          <br />
			          <?php _e('Created users will obtain the role defined under "New User Default Role" on the <a href="options-general.php">General Options</a> page.', 'ad-integration'); ?>
			          <br/>
			          <?php _e('This setting is separate from the Role Equivalent Groups option, below.', 'ad-integration'); ?>
			          <br />
					  
			          <?php _e("<b>Users with role equivalent groups will be created even if this setting is turned off</b> (because if you didn't want this to happen, you would leave that option blank.)", 'ad-integration'); ?>
			        </td>
			      </tr>
			
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_auto_update_user"><?php _e('Automatic User Update', 'ad-integration'); ?></label></th>
			        <td>
					  <input type="checkbox" name="AD_Integration_auto_update_user" id="AD_Integration_auto_update_user" <?php if ($this->_auto_update_user) echo ' checked="checked"' ?> value="1" />          
					  <?php _e('Should the users be updated in the WordPress database everytime they logon?<br /><b>Works only if Automatic User Creation is turned on.</b>', 'ad-integration'); ?>          
			        </td>
			      </tr>
			      
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_default_email_domain"><?php _e('Default email domain', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_default_email_domain" id="AD_Integration_default_email_domain" class="regular-text" value="<?php echo $this->_default_email_domain; ?>" /><br />
					  <?php _e("If the Active Directory attribute 'mail' is blank, a user's email will be set to username@whatever-this-says", 'ad-integration'); ?>
			        </td>
			      </tr>
				  
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_account_suffix"><?php _e('Account Suffix', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_account_suffix" id="AD_Integration_account_suffix" class="regular-text" value="<?php echo $this->_account_suffix; ?>" /><br />
			          <?php _e('Account Suffix (will be appended to all usernames in the Active Directory authentication process; e.g., "@domain.tld".)', 'ad-integration'); ?>
					  <br />
					  <br />
					  <input type="checkbox" name="AD_Integration_append_suffix_to_new_users" id="AD_Integration_append_suffix_to_new_users"<?php if ($this->_append_suffix_to_new_users) echo ' checked="checked"' ?> value="1" />
			          <label for="AD_Integration_append_suffix_to_new_users"><?php _e('Append account suffix to new created usernames. If checked, the account suffix (see above) will be appended to the usernames of new created users.', 'ad-integration'); ?></label>
			        </td>
			      </tr>
			      
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_display_name"><?php _e('Display name', 'ad-integration'); ?></label></th>
			        <td>
			          <select name="AD_Integration_display_name" id="AD_Integration_display_name">
			            <?php _e('LDAP Attribute: ','ad-integration');?>
			            <option value="samaccountname"<?php if (($this->_display_name == 'samaccountname') OR ($this->_display_name == '')) echo ' selected="selected"' ?>><?php _e('sAMAccountName (the username)', 'ad-integration'); ?></option>
			            <option value="displayname"<?php if ($this->_display_name == 'displayname') echo ' selected="selected"' ?>><?php _e('displayName', 'ad-integration'); ?></option>
			            <option value="description"<?php if ($this->_display_name == 'description') echo ' selected="selected"' ?>><?php _e('description', 'ad-integration'); ?></option>
			            <option value="givenname"<?php if ($this->_display_name == 'givenname') echo ' selected="selected"' ?>><?php _e('givenName (firstname)', 'ad-integration'); ?></option>
			            <option value="sn"<?php if ($this->_display_name == 'sn') echo ' selected="selected"' ?>><?php _e('SN (lastname)', 'ad-integration'); ?></option>
			            <option value="cn"<?php if ($this->_display_name == 'cn') echo ' selected="selected"' ?>><?php _e('CN (Common Name, the whole name)', 'ad-integration'); ?></option>
			            <option value="mail"<?php if ($this->_display_name == 'mail') echo ' selected="selected"' ?>><?php _e('mail', 'ad-integration'); ?></option>
			          </select>
			          <?php _e("Choose user's Active Directory attribute to be used as display name.", 'ad-integration'); ?>
			        </td>
			      </tr>

			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_enable_password_change"><?php _e('Enable local password changes', 'ad-integration'); ?></label></th>
			        <td>
					  <input type="checkbox" name="AD_Integration_enable_password_change" id="AD_Integration_enable_password_change" <?php if ($this->_enable_password_change) echo ' checked="checked"' ?> value="1" />          
					  <label for="AD_Integration_enable_password_change"><?php _e('Allow users to change their local (<strong>non AD</strong>) WordPress password', 'ad-integration'); ?>
					  <br/>
					  <?php _e('<strong>If activated, a password change will update the local WordPress database only. No changes in Active Directory will be made.</strong>', 'ad-integration'); ?>
					  </label>          
			        </td>
			      </tr>
			      
			      <tr>
				   <td scope="col" colspan="2"><h2 style="font-size: 150%; font-weight: bold;"><?php _e('Authorization','ad-integration'); ?></h2></td>
				  </tr>
			      
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_authorize_by_group"><?php _e('Authorize by group membership','ad-integration'); ?></label></th>
			        <td>
			          <input type="checkbox" name="AD_Integration_authorize_by_group" id="AD_Integration_authorize_by_group"<?php if ($this->_authorize_by_group) echo ' checked="checked"' ?> value="1" />
			          <?php _e('Users are authorized for login only when they are members of a specific AD group.','ad-integration'); ?>
			          <br />
			          <label for="AD_Integration_authorization_group"><?php _e('Group','ad-integration'); ?>: </label>
			          <input type="text" name="AD_Integration_authorization_group" id="AD_Integration_authorization_group" class="regular-text"
			                    value="<?php echo $this->_authorization_group; ?>" /><?php _e('(e.g., "WP-Users")', 'ad-integration'); ?>
			          
			        </td>
			      </tr>
			      
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_role_equivalent_groups"><?php _e('Role Equivalent Groups', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_role_equivalent_groups" id="AD_Integration_role_equivalent_groups" class="regular-text" 
			          value="<?php echo $this->_role_equivalent_groups; ?>" /><br />
					  <?php _e('List of Active Directory groups which correspond to WordPress user roles.', 'ad-integration'); ?><br/>
					  <?php _e('When a user is first created, his role will correspond to what is specified here.<br/>Format: AD-Group1=WordPress-Role1;AD-Group1=WordPress-Role1;...<br/> E.g., "Soc-Faculty=faculty" or "Faculty=faculty;Students=subscriber"<br/>A user will be created based on the first math, from left to right, so you should obviously put the more powerful groups first.', 'ad-integration'); ?><br/>
					  <?php _e('NOTES', 'ad-integration'); ?>
					  <ol style="list-style-type:decimal; margin-left:2em;font-size:11px;">
					    <li><?php _e('WordPress stores roles as lower case ("Subscriber" is stored as "subscriber")', 'ad-integration'); ?></li>
					    <li><?php _e('Active Directory groups are case-sensitive.', 'ad-integration'); ?></li>
					    <li><?php _e('Group memberships cannot be checked across domains.  So if you have two domains, instr and qc, and qc is the domain specified above, if instr is linked to qc, I can authenticate instr users, but not check instr group memberships.', 'ad-integration'); ?></li>
					  </ol>
			        </td>
			      </tr>
			      
			      <tr>
				   <td scope="col" colspan="2">
				     <h2 style="font-size: 150%; font-weight: bold;"><?php _e('Brute Force Protection','ad-integration'); ?></h2>
				     <?php _e('For security reasons you can use the following options to prevent brute force attacks on your user accounts.','ad-integration'); ?>
				   </td>
				  </tr>
				  
			     <tr valign="top">
			        <th scope="row"><label for="AD_Integration_max_login_attempts"><?php _e('Maximum number of allowed login attempts', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_max_login_attempts" id="AD_Integration_max_login_attempts"  
			          value="<?php echo $this->_max_login_attempts; ?>" /><br />
					  <?php _e('Maximum number of failed login attempts before a user account is blocked. If empty or "0" Brute Force Protection is turned off.', 'ad-integration'); ?>
				    </td>
				  </tr>
			 
			      <tr valign="top">
			        <th scope="row"><label for="AD_Integration_block_time"><?php _e('Blocking Time', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="text" name="AD_Integration_block_time" id="AD_Integration_block_time"  
			          value="<?php echo $this->_block_time; ?>" /><br />
					  <?php _e('Number of seconds an account is blocked after the maximum number of failed login attempts is reached.', 'ad-integration'); ?>
				    </td>
				  </tr>
			
				  <tr valign="top">
			        <th scope="row"><label for="AD_Integration_user_notification"><?php _e('User Notification', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="checkbox" name="AD_Integration_user_notification" id="AD_Integration_user_notification"<?php if ($this->_user_notification) echo ' checked="checked"' ?> value="1" />  
					  <?php _e('Notify user by e-mail when his account is blocked.', 'ad-integration'); ?>
				    </td>
				  </tr>
			
				  <tr valign="top">
			        <th scope="row"><label for="AD_Integration_admin_notification"><?php _e('Admin Notification', 'ad-integration'); ?></label></th>
			        <td>
			          <input type="checkbox" name="AD_Integration_admin_notification" id="AD_Integration_admin_notification"<?php if ($this->_admin_notification) echo ' checked="checked"' ?> value="1" />  
					  <?php _e('Notify admin(s) by e-mail when an user account is blocked.', 'ad-integration'); ?>
					  <br />
			          <?php _e('E-mail addresses for notifications:','ad-integration');?>
			          <input type="text" name="AD_Integration_admin_email" id="AD_Integration_admin_email" class="regular-text"  
			          value="<?php echo $this->_admin_email; ?>" />
			          <br />
			          <?php _e('Seperate multiple addresses by semicolon (e.g. "admin@domain.tld;me@mydomain.tld"). If left blank, notifications will be sent to the blog-administrator only.', 'ad-integration'); ?>
				    </td>
				  </tr>
      	      </tbody>
    	</table>
    	<p class="submit">
      		<input type="submit" class="button-primary" name="Submit" value="<?php _e("Save Changes"); ?>" />
    	</p>
  	</form>

</div>
<?php
	}

} // END OF CLASS
} // ENDIF



// create the needed tables on plugin activation
register_activation_hook(__FILE__,'ADIntegrationPlugin::activate');

// delete the tables on plugin deactivation
register_deactivation_hook(__FILE__,'ADIntegrationPlugin::deactivate');

// uninstall hook
if (function_exists('register_uninstall_hook')) {
	register_uninstall_hook(__FILE__, 'ADIntegrationPlugin::uninstall');
}

// Load the plugin hooks, etc.
$AD_Integration_plugin = new ADIntegrationPlugin();
?>
