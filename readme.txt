=== Active Directory Integration ===
Contributors: glatze
Tags: authentication, active directory, ldap, authorization, security
Requires at least: 2.7.1
Tested up to: 2.8.0
Stable tag: 0.9.1

Allows WordPress to authenticate, authorize, create and update users against Active Directory

== Description ==

This Plugin allows WordPress to authenticate, authorize, create and update against an Active Directory Domain.

It is very easy to set up. Just activate the plugin, type in a domain controller, and you're done. But there are more Features:

* authenticate against more than one AD Server
* authorize users by Active Directory group membership
* auto create and update users that can authenticate against AD
* mapping of AD groups to WordPress roles
* use TLS for secure communication to AD Servers (recommended)
* use non standard port for communication to AD Servers
* protection against brute force attacks
* user and/or admin e-mail notification on failed login attempts
* multi-language support (english and german included)


"Active Directory Integration" is based upon Jonathan Marc Bearak's great plugin "Active Directory Authentication" (http://wordpress.org/extend/plugins/active-directory-authentication/) and Scott Barnett's "adLDAP", a very useful PHP class (http://adldap.sourceforge.net/).

= Requirements =

* WordPress since 2.7.1 
* PHP 5
* LDAP support
* OpenSSL Support for TLS (recommended) 

== Frequently Asked Questions ==

None... so far.

  
== Installation ==

1. Login as an existing user, such as admin.
1. Upload the folder named `active-directory-integration` to your plugins folder, usually `wp-content/plugins`.
1. Activate the plugin on the Plugins screen.
1. Enable SSL-Admin-Mode by adding the line `define('FORCE_SSL_ADMIN', true);` to your wp-config.php so that your passwords are not sent in plain-text.

== Changelog ==

= 0.9.1 =
* NEW: email notification of user and/or admin when a user account is blocked
* object-orientation redesign
* code clean up
* some minor changes 

= 0.9.0 =
* first published version 