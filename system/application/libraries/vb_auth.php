<?php if (!defined('BASEPATH')) exit('No direct script access allowed'); 
/**
 * vb_auth
 *  
 * Authentication library for vBulletin user sessions
 * 
 * Inspired by Pat Andrew's vBuser package
 *	
 * Last	Modified:	3/17/2010
 * Author: MiklosK (http://codeigniter.com/forums/member/155463/)
 * 
 */
 
class 	Vb_auth	{
	/**
	 * CI Database Object
	 * @var		object
	 */
	var $db;

	/**
	 * CI Table Prefix
	 * @var		string
	 */
	var $dbprefix;
	
	/**
	 * vBulletin's cookie prefix
	 * @var		string
	 */
	var $cookie_prefix;
	
	/**
	 * vBulletin's cookie timeout  (seconds)
	 * @var		integer
	 */
	var $cookie_timeout;
	
	/**
	 * vBulletin user columns to fetch for $userinfo array
	 * @var		array
	 */
	var $select_columns;
	
	/**
	 * Default $userinfo data if no user record is found
	 * @var		array
	 */
	var $default_user = array(
		'userid' => 0,
		'username' => 'unregistered',
		'usergroupid' => 3,
		'membergroupids' => '',
		'sessionhash' => '',
		'salt' => ''
	);
	
	/**
	 * Userinfo data to be used throughout application
	 * @var		array
	 */
	var $info;
			
	/** 
	 *	vBulletin License Key
	 */	
	var $license;
		
	/** 
	 *	Forum Base URL
	 */     	
	var $forum_url;
	
	/**
	 *   Constructor; 
	 *   loads all dependencies from CI
     *   then tries to authenticate current session against vB 
	 */
	 
	function Vb_auth()  {
	    
	    $CI =& get_instance();
	    
	    /* ATTENTION: 
        
        1. you have to have a vbulletin database configured in your config/database.php
        2. make sure you don't use persistent db connections 
        
        something like this:
        
        $db['vbulletin']['hostname'] = "localhost";
        $db['vbulletin']['username'] = "username";
        $db['vbulletin']['password'] = "password";
        $db['vbulletin']['database'] = "database";
        $db['vbulletin']['dbdriver'] = "mysql";
        $db['vbulletin']['dbprefix'] = "vb_";
        $db['vbulletin']['pconnect'] = FALSE;           // don't use persistent db connections
        $db['vbulletin']['db_debug'] = TRUE;
        $db['vbulletin']['cache_on'] = FALSE;
        $db['vbulletin']['cachedir'] = "";
        $db['vbulletin']['char_set'] = "utf8";
        $db['vbulletin']['dbcollat'] = "utf8_general_ci";
         
        
        */
	    		
		$this->db =& $CI->load->database('vbulletin', true);
		$this->dbprefix =& $this->db->dbprefix;
		
		$CI->config->load('vb_auth',true);
        $this->config = $CI->config->item('vb_auth','vb_auth');
		
		$this->license        = $this->config['vblicense'];
		$this->cookie_prefix  = $this->config['cookieprefix'];  // TODO: get this from vB db
		$this->cookie_timeout = $this->config['cookietimeout']; // TODO: get this from vB db
		$this->select_columns = $this->config['selectcolumns'];
		$this->groups         = $this->config['groups'];
		$this->forum_url      = $this->config['forum_url'];
				
		$this->set_userinfo($this->default_user);
		
		$this->authenticate_session();
	}

	/**
	 * Checks cookies for a valid session hash, and queries session table to
	 * see if user is already logged in.  Sets $info value to queried result
	 * 
	 * @return	boolean		true = the user is logged in
	 */
	function authenticate_session()
	{	    
		// check bbuser cookies (stored when 'remember me' checked)
		$userid = @$_COOKIE[$this->cookie_prefix .'userid'];
		$password = @$_COOKIE[$this->cookie_prefix .'password'];
		
		//check sessionhash
		$vb_sessionhash =  @$_COOKIE[$this->cookie_prefix . 'sessionhash'];
		
		if((!empty($userid) && !empty($password))) {
		    
			// we have a remembered user
			$user = $this->is_valid_cookie_user($userid, $password);
			
			if(!empty($user)) {
			    
				// create user session
				$vb_sessionhash = $this->create_session($userid); 
			} else {
			    
			    // invalid userid and password in cookie: authentication failed, force login
				return false;
			}			
		}
						
		// Logged in vB via session
		if (!empty($vb_sessionhash))
		{
		    $sql = "
				SELECT *
				FROM {$this->dbprefix}session
				WHERE 
					sessionhash = " . $this->db->escape($vb_sessionhash) . " and
					idhash      = " . $this->db->escape($this->fetch_id_hash()) . "
					and lastactivity > " . (time() - $this->cookie_timeout);

			$result = $this->db->query($sql);
			
			$session = $result->row_array();
			
			if (empty($session))
			{
				return false;
			}
				
			if ($session and $session['host'] == substr($_SERVER['REMOTE_ADDR'], 0, 15))
			{
				$result = $this->db->query("
					SELECT " . implode(', ', $this->select_columns) . "
					FROM {$this->dbprefix}user
					WHERE userid = $session[userid]
				");
				
				$userinfo = $result->result_array();
				$userinfo[0]['sessionhash'] = $session['sessionhash'];
								
				if (empty($userinfo))
				{
					return false;
				}
				
				$userinfo[0]['sessionhash'] = $session['sessionhash'];
				
				// cool, session is authenticated

				$this->set_userinfo($userinfo[0]);
				
				// now let's inform vB what this user is just doing
				
        		$update_session = array(
        			'lastactivity' => time(),
        			'location'     => $_SERVER['REQUEST_URI'],
        		);
		
                $this->db->update('session', $update_session, array('sessionhash'=>$session['sessionhash']),1);
                return true;				
			}
		}
		
		return false;
	}
	
	/**
	 * Checks to see if $userid and hashed $password are valid credentials.
	 * 
	 * @return	integer		0 = false; X > 1 = Userid
	 */
	function is_valid_cookie_user($userid, $password)
	{
	    $sql = "
			SELECT username
			FROM {$this->dbprefix}user
			WHERE 
				userid = " . $this->db->escape($userid) . " and
				md5(concat(password,'".$this->license."')) = '$password'
		";

		$result = $this->db->query($sql);
		
		$user = $result->result_array();
		
		if (empty($user))
		{
			return false;
		}
		
		return intval($userid);
	}
	
	/**
	 * Checks to see if $username and $password are valid credentials.
	 * 
	 * @return	integer		0 = false; X > 1 = Userid
	 */
	function is_valid_login($username, $password)
	{
		
		$result = $this->db->query("
			SELECT userid
			FROM {$this->dbprefix}user
			WHERE 
				username = " . $this->db->escape($username) . " and
				password = md5(concat(md5(" . $this->db->escape($password) . "), salt))
		");
		$user = $result->result_array();
		
		if (empty($user))
		{
			return false;
		}
		
		return intval($user[0]['userid']);
	}
	
	/**
	 *	Sets the cookies for a cookie user.  Call on login process ('remember me' option)
	 *	Sets cookie timeout to 1 year from now
	 *
	 *	@return  null;
	 */	 
	function create_cookie_user($userid, $password) {
	
        setcookie($this->cookie_prefix . 'userid', $userid, time() + 31536000, '/');
			
        setcookie($this->cookie_prefix . 'password', md5($password . $this->license), time() + 31536000, '/');
	}
	
	/**
	 * Creates a session for $userid (logs them into vBulletin) by creating
	 * both a cookie and an entry in the session table.
	 * 
	 * @param	integer		Userid to log in
	 */
	function create_session($userid)
	{
		$hash = md5(microtime() . $userid . $_SERVER['REMOTE_ADDR']);

		$timeout = time() + $this->cookie_timeout;
		
		setcookie($this->cookie_prefix . 'sessionhash', $hash, $timeout, '/');

		$session = array(
			'userid'       => $userid,
			'sessionhash'  => $hash,
			'host'         => $_SERVER['REMOTE_ADDR'],
			'idhash'       => $this->fetch_id_hash(),
			'lastactivity' => time(),
			'location'     => $_SERVER['REQUEST_URI'],
			'useragent'    => $_SERVER['HTTP_USER_AGENT'],
			'loggedin'     => 1
		);
		
		$this->db->insert('session', $session);
		
		return $hash;
	}
	
	/**
	 * Deletes the users session by expiring the cookie and removing the
	 * entry from the session table.
	 */
	function delete_session()
	{
		setcookie($this->cookie_prefix . 'sessionhash', '', time() - 3600);
		setcookie($this->cookie_prefix . 'userid', '', time() - 3600);
		setcookie($this->cookie_prefix . 'password', '', time() - 3600);
		
		$this->db->delete(
			'session', 
			array('sessionhash' => $this->info['sessionhash'])
		);
	}
	
	/**
	 * Sets the userinfo array to be used
	 * @param	array		User record data
	 */
	function set_userinfo($userinfo)
	{
		$CI =& get_instance();
		$this->info = $userinfo;
	}
	
	/**
	 * Checks to see if the current user is a member of $group ('admin', for ex)
	 * Name to ID mapping is in config file.
	 * 
	 * @param	string		Group varname
	 * @return	boolean		True = in group; false not in group
	 */
	function is($group)
	{
		if (empty($this->groups[$group]))
		{
			die("$group is invalid");
		}
		
		static $my_groups;
		
		if (!is_array($my_groups))
		{
			$my_groups = array($this->info['usergroupid']);
			
			foreach (explode(',', $this->info['membergroupids']) as $id)
			{
				if ($id)
				{
					$my_groups[] = intval($id);
				}
			}
		}
		
		return (bool)count(array_intersect($my_groups, $this->groups[$group]));
		
	}
	
	/**
	 * Fetches the "id_hash" (vbulletin; see class_core.php)
	 * 
	 * @return	string		Hashed user agent + shortened IP address
	 */
	function fetch_id_hash()
	{
		return md5($_SERVER['HTTP_USER_AGENT'] . $this->fetch_substr_ip($this->fetch_alt_ip()));
	}
	
	/**
	 * Fetches the "substr_ip" (vbulletin; see class_core.php)
	 * 
	 * @return	string		IP address
	 */
	function fetch_substr_ip($ip, $length = null)
	{
		if ($length === null OR $length > 3)
		{
			$length = 1;
		}
		return implode('.', array_slice(explode('.', $ip), 0, 4 - $length));
	}
	
	/**
	 * Fetches the users "alt_ip" (vbulletin; see class_core.php)
	 * 
	 * @return	string		IP address
	 */
	function fetch_alt_ip()
	{
		$alt_ip = $_SERVER['REMOTE_ADDR'];

		if (isset($_SERVER['HTTP_CLIENT_IP']))
		{
			$alt_ip = $_SERVER['HTTP_CLIENT_IP'];
		}
		elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR']) AND preg_match_all('#\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#s', $_SERVER['HTTP_X_FORWARDED_FOR'], $matches))
		{
			// make sure we dont pick up an internal IP defined by RFC1918
			foreach ($matches[0] AS $ip)
			{
				if (!preg_match("#^(10|172\.16|192\.168)\.#", $ip))
				{
					$alt_ip = $ip;
					break;
				}
			}
		}
		elseif (isset($_SERVER['HTTP_FROM']))
		{
			$alt_ip = $_SERVER['HTTP_FROM'];
		}

		return $alt_ip;
	}
    		
	/**
	 * Checks if the current user is logged in to vB
	 * 
	 * @return	bool    true if valid vb user, false if anonym visitor
	 */
	function is_logged_in() 
    {
        return (isset($this->info['userid'])  && !empty($this->info['userid']));
    }
    
	/**
	 * Checks if the current user is a vB administrator
	 * 
	 * @return	bool
	 */
	 
	function is_admin() 
    {
        return (isset($this->info['userid'])  && !empty($this->info['userid']) && $this->info['usergroupid'] == 6);
    }
	/**
	 * Compose a logout url for remote logout links
	 * 
	 * @return	string
	 */
    function logout_url() 
    {
    	$securitytoken_raw = sha1($this->info['userid'] . sha1($this->info['salt']) . sha1($this->license));
    	$securitytoken = time() . '-' . sha1(time() . $securitytoken_raw);    	    	
    
        $logout_url    = $this->forum_url.'login.php?do=logout&logouthash='.$securitytoken;
        
        return $logout_url;
    }    
	/** 
	 * 	PHP 5 __GET()
	 *
	 */ 
	 public function __get($var) {
	 	return $this->info["$var"];
	 }
}
?>