=== Active Directory Integration ===
Contributors: glatze
Tags: authentication, active directory, ldap, authorization, security
Requires at least: 2.7.1
Tested up to: 3.1
Stable tag: 0.9.9.9

Allows WordPress to authenticate, authorize, create and update users against Active Directory

== Description ==

This Plugin allows WordPress to authenticate, authorize, create and update users against an Active Directory Domain.

It is very easy to set up. Just activate the plugin, type in a domain controller, and you're done. But there are more Features:

* authenticate against more than one AD Server
* authorize users by Active Directory group memberships
* auto create and update users that can authenticate against AD
* mapping of AD groups to WordPress roles
* use TLS (or LDAPS) for secure communication to AD Servers (recommended)
* use non standard port for communication to AD Servers
* protection against brute force attacks
* user and/or admin e-mail notification on failed login attempts
* multi-language support (English, German and Belorussian included)
* determine WP display name from AD attributes (sAMAccountName, displayName, description, SN, CN, givenName or mail)
* tool for testing with detailed debug informations
* enable/disable password changes for local (non AD) WP users
* WordPress 3 compatibility, including *Multisite* 

*Active Directory Integration* is based upon Jonathan Marc Bearak's great plugin [Active Directory Authentication](http://wordpress.org/extend/plugins/active-directory-authentication/) and Scott Barnett's [adLDAP](http://adldap.sourceforge.net/), a very useful PHP class.

= Requirements =

* WordPress since 2.8 (or higher)
* PHP 5
* LDAP support
* OpenSSL Support for TLS (recommended)

= Known Issues =
* XMLRPC will only work with WordPress 2.8 and above.
 

== Frequently Asked Questions ==

= Is it possible to use TLS with a self-signed certificate on the AD server? =
Yes, this works. But you have to add the line `TLS_REQCERT never` to your ldap.conf on your web server.
If yout don't already have one create it. On Windows systems the path should be `c:\openldap\sysconf\ldap.conf`.

= Can I use LDAPS instead of TLS? =
Yes, you can. Just put "ldaps://" in front of the server in the option labeled "Domain Controller" (e.g. "ldaps://dc.domain.tld"), enter 636 as port and deactivate the option "Use TLS".

= Is it possible to get more informations from the Test Tool? =
Yes. Since 1.0-RC1 you get more informations from the Test Tool by setting WordPress into debug mode. Simply add DEFINE('WP_DEBUG',true); to your wp-config.php.

= Is there an official bug tracker for ADI? =
Yes. You'll find the bug tracker at http://bt.ecw.de/. You can report issues anonymously but it is recommended to create an account.
    

== Screenshots ==

1. Server Settings 
2. User specific settings
3. Settings for authorization
4. Security related stuff
5. Test Tool
6. Output of Test Tool


== Installation ==

1. Login as an existing user, such as admin.
1. Upload the folder named `active-directory-integration` to your plugins folder, usually `wp-content/plugins`.
1. Activate the plugin on the Plugins screen.
1. Enable SSL-Admin-Mode by adding the line `define('FORCE_SSL_ADMIN', true);` to your wp-config.php so that your passwords are not sent in plain-text.

== Changelog ==

= 1.0-RC2 =
* ADD: More debug information from Test Tool. You have to set WP_DEBUG to true in wp_config.php for extra debug information from the Test Tool.
* CHANGE: Now using an extended version of adLDAP 3.3.2
* FIX: Uninstall crashed. (Thanks to z3c from hosthis.org for the bug report.)
* FIX: Bug in adLDAP->recursive_groups() fixed.
* FIX: The stylesheet was loaded by http not https even if you use https in admin mode. (Thanks to Curtiss Grymala for the bug report and fix.)
* FIX: On activation add_option() was used with the deprecated parameter description.

= 1.0-RC1 =
* CHANGE: Now using an extended version of adLDAP 3.3.1 which should fix some authentication and authorization issues.
* FIX: Fixed problem with wrong updated email addresses when option "Email Address Conflict Handling" was set to "create".

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
**If you have 0.9.9.1 installed, it is highly recommended to update to 0.9.9.2.**

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