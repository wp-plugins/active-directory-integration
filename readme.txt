=== Active Directory Integration ===
Contributors: glatze
Tags: authentication, active directory, ldap, authorization, security, windows
Requires at least: 3.0
Tested up to: 4.0
Stable tag: 1.1.5

Allows WordPress to authenticate, authorize, create and update users against Active Directory


== Description ==

This Plugin allows WordPress to authenticate, authorize, create and update users against an Active Directory Domain.

It is very easy to set up. Just activate the plugin, type in a domain controller, and you're done. But there are many more Features:

* authenticate against more than one AD Server
* authorize users by Active Directory group memberships
* auto create and update users that can authenticate against AD
* mapping of AD groups to WordPress roles
* use TLS (or LDAPS) for secure communication to AD Servers (recommended)
* use non standard port for communication to AD Servers
* protection against brute force attacks
* user and/or admin e-mail notification on failed login attempts
* multi-language support (English, German, Norwegian and Belorussian included)
* determine WP display name from AD attributes (sAMAccountName, displayName, description, SN, CN, givenName or mail)
* setting of user meta data to any possible AD attribute
* show selected AD attributes (see above) in user profile
* tool for testing with detailed debug informations
* enable/disable password changes for local (non AD) WP users
* set users local WordPress password on first and/or on every successfull login
* WordPress 3 compatibility, including *Multisite* (work in progress) 
* SyncBack - write changed "Additional User Attributes" back to Active Directory if you want.
* Bulk Import - import and update users from Active Directory, for example by cron job.
* Support for multiple account suffixes.
* Using LDAP_OPT_NETWORK_TIMEOUT (default 5 seconds) to fall back to local authorization when your Active Directory Server is unreachable.
* Bulk SyncBack to manually write all "Additional User Attributes" back to Active Directory.
* Disable user accounts in WordPress if they are disabled in Active Directory. 
* Option to disable fallback to local (WordPress) authentication.
* **NEW** Support for large groups (>1000 user) in Bulk Import with PHP 5.4.0 and above.

The latest major release 1.1 was sponsored by [VARA](http://vara.nl). Many thanks to Bas Ruijters.

*Active Directory Integration* is based upon Jonathan Marc Bearak's [Active Directory Authentication](http://wordpress.org/extend/plugins/active-directory-authentication/) and Scott Barnett's [adLDAP](http://adldap.sourceforge.net/), a very useful PHP class.


= Requirements =

* WordPress since 3.0
* PHP 5
* LDAP support
* OpenSSL Support for TLS (recommended)


= Known Issues =
There are some issues with MultiSite. This is tracked [here](http://bt.ecw.de/view.php?id=4) and [here](http://bt.ecw.de/view.php?id=11).


== Frequently Asked Questions ==

= Is it possible to use TLS with a self-signed certificate on the AD server? =
Yes, this works. But you have to add the line `TLS_REQCERT never` to your ldap.conf on your web server.
If yout don't already have one create it. On Windows systems the path should be `c:\openldap\sysconf\ldap.conf`.
Another and even simpler way is to add LDAPTLS_REQCERT=never to your environment settings. 

= Can I use LDAPS instead of TLS? =
Yes, you can. Just put "ldaps://" in front of the server in the option labeled "Domain Controller" (e.g. "ldaps://dc.domain.tld"), enter 636 as port and deactivate the option "Use TLS". But have in mind, that 

= Is it possible to get more informations from the Test Tool? =
Yes. Since 1.0-RC1 you get more informations from the Test Tool by setting WordPress into debug mode. Simply add DEFINE('WP_DEBUG',true); to your wp-config.php.

= Where are the AD attributes stored in WordPress? =
If you activate "Automatic User Creation" and "Automatic User Update" you may store any AD attribute to the table wp_usermeta. You can set the meta key as you like or use the default behavior, where the meta key is set to `adi_<attribute>` (e.g. `adi_physicaldeliveryofficename` for the Office attribute). You can find a list of common attributes on the "User Meta" tab.

= Is there an official bug tracker for ADI? =
Yes. You'll find the bug tracker at http://bt.ecw.de/. You can report issues anonymously but it is recommended to create an account. This is also the right place for feature requests.

= I'm missing some functionality. Where can I submit a feature request? =
Use the [bug tracker](http://bt.ecw.de/) (see above) at http://bt.ecw.de/.

= Authentication is successfull but the user is not authorized by group membership. What is wrong? =
A common mistake is that the Base DN is set to a wrong value. If the user resides in an Organizational Unit (OU) that is not "below" the Base DN the groups the user belongs to can not be determined. A quick solution is to set the Base DN to something like `dc=mydomain,dc=local` without any OU.
Another common mistake is to use `ou=users,dc=mydomain,dc=local` instead of `cn=users,dc=mydomain,dc=local` as Base DN. Do you see the difference? I recommend to use tools like [ADSIedit](http://technet.microsoft.com/en-us/library/cc773354(WS.10).aspx) to learn more about your Active Directory.  

= I want to use Sync Back but don't want to use a Global Sync User. What can I do? =
You must give your users the permission to change their own attributes in Active Directory. To do so, you must give write permission on "SELF" (internal security principal). Run ADSIedit.msc, right click the OU or CN all your users belong to, choose "Properties", go on tab "Security", add the user "SELF" and give him the permission to write.  

= I use the User Meta feature. Which type I should use for which attribute? =
Not all attribute types from the Active Directory schema are supported and there are some special types. Types marked as SyncBack can be synced back to AD (if the attribute is writeable).

* string: **Unicode String**s like "homePhone" - SyncBack
* list: a list of **Unicode String**s like "otherHomePhone" - SyncBack
* integer: **Integer**s or **Large Integer** attributes like "logonCount" - SyncBack
* bool: **Boolean**s use it from boolean attributes like "fromEntry"
* octet: **Octet String**s like  "jpegPhoto"
* time: **UTC Coded Time** like "whenCreated"
* timestamp: **Integer**s which store timestamps (not the unix ones) like "lastLogon"
* cn: **Common Name** extracts the CN part and drops everthing else - use it with "manager"

= Why will no users be imported if I'm using "Domain Users" as security group for Bulk Import? =
Here we have a special problem with the builtin security group "Domain Users". In detail: the security group "Domain Users" is usually the primary group of all users. In this case the members of this security group are not listed in the members attribute of the group. To import all users of the security group "Domain Users" you must set the option "Import members of security groups" to "**Domain Users;id:513**". The part "id:513" means "Import all users whos primaryGroupID is 513." And as you might have guessed, 513 is the ID of the security group "Domain Users".

= I have problems with accounts that have special characters in the username. What can I do? =
It is never a good idea to allow special characters in usernames! For ADI it won't be a problem, but in Wordpress only lowercase letters (a-z) and numbers are allowed. The only option is to change the usernames in AD. Hey! Stop! Don't shoot the messenger.   

= I'm interested in the further development of ADI. How to keep up to date? =
* Follow the development on [Twitter](http://twitter.com/#!/adintegration).
* Go to http://blog.ecw.de
* See the bug tracker on http://bt.ecw.de 

== Screenshots ==

1. Server settings 
2. User specific settings
3. Settings for authorization
4. Security related stuff
5. User Meta settings
6. Bulk Import settings
7. Test Tool
8. Sample output of the Test Tool
9. User Profile Page with additional informations from Active Directory (see User Meta)
10. List of user with status information (ADI User, disabled) 

== Installation ==

1. Login as an existing user, such as admin.
1. Upload the folder named `active-directory-integration` to your plugins folder, usually `wp-content/plugins`.
1. Activate the plugin on the Plugins screen.
1. Configure the plugin via Settings >> Active Directory Integration
1. Enable SSL-Admin-Mode by adding the line `define('FORCE_SSL_ADMIN', true);` to your wp-config.php so that your passwords are not sent in plain-text.


== Changelog ==

= 1.1.5 =
* ADD: LDAP paging support for Bulk Import on PHP 5.4.0 so more than 1000 users per group can be imported. (Issue #0058. Thanks to billrod for the bug report.)
* ADD: Added new attribute type "cn" for user meta. (Issue #0080. Feature Request by Réda Sehili.)
* UPD: Language Norwegian (nb_NO) updated. (Many thanks to Audun Wangen.)
* FIX: Replaced deprecated $wpdb->escape() by $wpdb->prepare(). (Documented in issue #0078. Thanks to marshalld for the bug report.)
* FIX: User Meta not loaded if "Append account suffix to new created usernames." is checked. (Issue #0081. Thanks to Réda Sehili for the bug report and the solution.)
* Fix: Added network_timeout setting to wpmu settings.
* Fix: Bulk Import didn't work correctly if account suffix is appended to username. (Issue #0076. Thanks to Stephen Rice for the bug report.)
* Change: Moved class BulkSyncBackADIntegrationPlugin() from syncback.php to BulkSyncBackADIntegrationPlugin.class.php (Recommendation by nic0tin. Issue #0075.)
 

= 1.1.4 =
* ADD: Option to (re-)enable lost password recovery. (Feature Request by Jonathan Shapiro. Issue #0074.)
* CHANGE: Only set role of user if the role already exists in WordPress. (Issue #0051)
* CHANGE: Now using POST instead of GET in Test Tool, so user and password are not shown in server log files (Change Request by Aren Cambre. Issue #0054.)
* CHANGE: The roles in Role Equivalent Groups are now always stored in lower case. (Issue #0055)
* FIX: ADI produces warnings due to deprecated use of id instead of ID (Issue #0062. Thanks to Liam Gladdy for the bug report.)

= 1.1.3 =
* CHANGE: **WordPress versions lower 3.0 are not supported anymore.**
* ADD: Disable users by Bulk Import (or manually) who are not imported anymore or are disabled in Active Directory. (Issue #0045. Feature Request by Bas Ruijters.)
* ADD: Option to show on user list if a user was authenticated (or imported) from Active Directory and the disabled state of user. (Related to issue #0045.)
* ADD: Option to choose whether ADI should fallback to local (WordPress) password check if authentication against Active Directory fails. You should deactivate this for security reasons. (Issue #0050.)
* ADD: Option to prevent users from changing their email. (Issue #0049. Feature Request by Bas Ruijters.)
* FIX: Username is handled as case sensitive on Bulk Import but this is a wrong behavior. (Issue #0041)
* FIX: Options page won't load on WP 3.3. (Issue #0048)

= 1.1.2 =
* ADD: Allow logon of users with domains different from Account Suffix. (Issue #0043. Feature Request by Greg Fenton.)
* ADD: Manually sync of locally modified attributes (for example after manipulating the database) back to Active Directory. (Issue #0046. Feature Request by Bas Ruijters.)
* FIX: Option AD_Integration_version was not removed from options table on unintall. (Issue #0047) 

= 1.1.1 =
* FIX: Password with special characters not accepted for SyncBack if Global SyncBack User is not used. (Issue #0036)

= 1.1 (VARA Edition) =
* ADD: SyncBack feature to write Additional User Attributes back to Active Directory. (Issue #0015. Thanks to Bas Ruijters for the feature request and testing.)
* ADD: Bulk Import feature to import and update users from Active Directory (for use in cron jobs). (Issue #0012. Thanks to Bas Ruijters for the feature request and testing.)
* ADD: Support for multiple account suffixes so users like user1@emea.company.com, user2@africa.company.com and user3@company.com can log on. (Issue #0018. Feature Request by DonChino.)
* ADD: Logging to file <plugindir>/adi.log if WordPress is in debug mode (WP_DEBUG is true). Don't forget to delete it in production environments.
* ADD: Using LDAP_OPT_NETWORK_TIMEOUT (default 5 seconds) to fall back to local authorization when your Active Directory Server is unreachable (only PHP 5.3.0 and above). (Issue #0020.)
* ADD: You can use "givenName SN" as display name now. (Issue #0029. Feature request by Aren Cambre.) 
* CHANGE: adLDAP 3.3.2 extended for SyncBack and Bulk Import features (see above).
* CHANGE: Passwords are not logged anymore even if WP_DEBUG is true.
* CHANGE: Active Directory authentication for admin user (ID 1) is not used anymore. Fall back to local authentication. (Issue #0024)
* CHANGE: Removed the Bind User. It is not needed any more.
* FIX: Including registration.php is deprecated/obsolete since WP 3.1. (Issue #0017)
* FIX: Language files were not loaded. (Issue #0030)
* FIX: "Email Address Conflict Handling" not secure by default. (Issue #0032. Thanks to Aren Cambre for the bug report.)

= 1.0.1 (unreleased version) =
This version was not released.

= 1.0 =
* ADD: New language Dutch (nl_NL) added. (Issue #0002. Thanks to Bas Ruijters.)
* ADD: Store AD attribute in WordPress DB (table usermeta) and show them on users profile page without any additional plugin.
* ADD: More debug information from Test Tool. You have to set WP_DEBUG to true in wp_config.php for extra debug information from the Test Tool.
* ADD: Set users local WordPress password on first and/or on every successfull login. (Issue #0006. Thanks to Eduardo Ribeiro for the feature request.)
* CHANGE: Now using an extended version of adLDAP 3.3.2 which should fix some authentication and authorization issues.
* FIX: Authentication fails if user has special characters like an apostrophe (') in password. (Issue #0016. Thanks to Bas Ruijters for the bug report.)
* FIX: Account suffix was accidently used for bind user. Fixed in adLDAP.php. (Issue #0009. Thanks to Tobias Bochmann for the bug report.) 
* FIX: Uninstall crashed. (Issue #0007. Thanks to z3c from hosthis.org for the bug report.)
* FIX: Bug in adLDAP->recursive_groups() fixed.
* FIX: The stylesheet was loaded by http not https even if you use https in admin mode. (Thanks to Curtiss Grymala for the bug report and fix.)
* FIX: On activation add_option() was used with the deprecated parameter description. (Issue #0008.)
* FIX: Fixed problem with wrong updated email addresses when option "Email Address Conflict Handling" was set to "create".
* FIX: The way of saving settings is deprecated since WP 2.7. Now using register_settings() and settings_fields(). Moved code for options page to admin.php.

= 0.9.9.9 =
* FIX: Automatic User Creation failed in WordPress 3.0 (Thanks to d4b for the bug report and testing.)
* ADD: New option "Email Address Conflict Handling" (relates to the fix above). 
* FIX: Some minor fixes in adintegration.php und adLDAP.php.

= 0.9.9.8 =
* FIX: Some fixes relating to WPMU contributed by Tim (mrsharumpe).
* ADD: WordPress 3.0 compatibility, including Multisite

= 0.9.9.7 =
* FIX: Problem with generating of email addresses fixed. (Thanks to Lisa Barker for the bug report.)
* ADD: WordPress 3.0 Beta 1 compatibility.
* FIX: Little typo fixed.
* FIX: Fixed a bug in adLDAP.php so the primary user group will be determined correctly.(Thanks to Matt for the bug report.) 

= 0.9.9.6 =
* FIX: If the option "Enable local password changes" is unchecked, it was not possible to manually add users. (Thanks to <a href="http://wordpress.org/support/profile/660906">kingkong954</a> for the bug report.)

= 0.9.9.5 =
* ADD: Translation to Belorussian by <a href="http://www.fatcow.com">FatCow</a>.

= 0.9.9.4 =
* FIX: Local passwords were always set to random ones, so it was impossible to logon with a password stored/changed in the local WordPress database after the activation of the plugin.(Thanks to Vincent Lubbers for the bug report.)

= 0.9.9.3 =
* FIX: Test Tool did not work with passwords including special characters. (Thanks to Bruno Grossniklaus for the bug report.)

= 0.9.9.2 =
**If you have 0.9.9.1 installed, it is highly recommended to update.**

* FIX: SECURITY RELEVANT - Added security checks to the Test Tool in test.php.
* NEW: German translation for the Test Tool.
* CHANGE: Improved debug informations in the Test Tool.

= 0.9.9.1 =
* NEW: testing und debugging tool
* CHANGE: tabbed interface for options  

= 0.9.8 =
* NEW: Deactivate Plugin if LDAP support is not installed.
* NEW: New Option "Allow users to change their local WordPress password."
* NEW: Multiple authorization groups (as requested by Lori Dabbs).
* FIX: Added missing CSS file (Thanks to ajay and BagNin for the bug report).
* FIX: Users e-mail address was never updated (Thanks to Marc Cappelletti for the bug report).

= 0.9.7 =
It is highly recommended to update to this version, because of a security vulnerability.
 
* FIX: SECURITY RELEVANT - TLS was not used if you have chosen this option. (Thanks to Jim Carrier for the bug report.)
* NEW: First WordPress MU prototype. Read mu/readme_wpmu.txt for further informations.
* FIX: Usernames will be converted to lower case, because usernames are case sensitive in WordPress but not in Active Directory. (Thanks to Robert Nelson for the bug report.)

= 0.9.6 =
* FIX: With WP 2.8 login screen shows a login error even if there wasn't an attempt zu login and you can not login with local user, as admin.(Thanks to Alexander Liesch and shimh for the bug report.)

= 0.9.5 =
* FIX: "Call to undefined function username_exists()..." fixed, which occurs under some circustances. (Thanks to Alexander Liesch for the bug report.)

= 0.9.4 =
* FIX: XMLRPC now works with WP 2.8 and above. XMLRPC won't work with earlier versions. (Thanks to Alexander Liesch for the bug report.)

= 0.9.3 =
* NEW: determine WP display name from AD attributes
* NEW: added template for your own translation (ad-integration.pot)

= 0.9.2 =
* NEW: drop table on deactivation
* NEW: remove options on plugin uninstall
* NEW: contextual help
* colors of logo changed
* code cleanup and beautification

= 0.9.1 =
* NEW: email notification of user and/or admin when a user account is blocked
* object-orientation redesign
* code cleanup
* some minor changes 

= 0.9.0 =
* first published version 