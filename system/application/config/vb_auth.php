<?php if (!defined('BASEPATH')) exit('No direct script access allowed'); 
/**
 * Config options for vb_auth library
 *	
 */

$config['vb_auth'] = array();

/**
 * vBulletin License Key
 * this is needed for cookie authenication
 */
$config['vb_auth']['vblicense'] = 'YOUR VB LINCESE KEY'; 

 
/**
 * vBulletin Forum URL
 * used for composing proper urls for login/logout/register actions 
 */

$config['vb_auth']['forum_url'] = 'http://your.domain.com/forums/';
	
/** 
 * Groups Definition
 * 
 * TODO: sync with vBulletin
 *
 */
$config['vb_auth']['groups'] = array(
						'admin'     	=> array(6),
						'moderator' 	=> array(5, 7),
						'user'      	=> array(2),
						'banned'    	=> array(8),
						'guest'     	=> array(3)
						);
						
						
/**
 * vBulletin Cookie Prefix
 *
 */ 
$config['vb_auth']['cookieprefix']  = 'bb'; // TODO: get this from vB db

/** 
 *	Cookie timeout in seconds
 * 
 */
$config['vb_auth']['cookietimeout'] = 1800; // TODO: get this from vB db
	
/** 
 * User table Column Selection
 *
 * defines the columns to be retrieved from vb's user table when the session is authenticated 
 * Add here more fields if you need them.
 *
 */
$config['vb_auth']['selectcolumns'] = array(
								'userid', 
								'username', 
								'usergroupid', 
								'membergroupids', 
								'email', 
								'salt',
								);
?>
