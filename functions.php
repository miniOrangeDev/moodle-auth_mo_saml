<?php
// This file is part of miniOrange moodle plugin
//
// This plugin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * This library is miniOrange Authentication Service.
 *
 * Gives result of saml response.
 *
 * @copyright   2017  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     mo_saml
 */
defined('MOODLE_INTERNAL') || die();
$config = get_config('auth/mo_saml');
// Config provide access to all data saved in database of mld_config table.
function mo_saml_show_test_result($firstnamee, $lastnamee, $useremail, $groupnamee, $attrs) {
    ob_end_clean();
    echo '<div style="font-family:Calibri;padding:0 3%;">';
    if (!empty($useremail)) {
        echo '<div style="color: #3c763d;
                background-color: #dff0d8;
                padding:2%;
                margin-bottom:20px;
                text-align:center;
                border:1px solid #AEDB9A;
                font-size:18pt;">TEST SUCCESSFUL</div>
                <div style="display:block;
                text-align:center;
                margin-bottom:4%;"><img style="width:15%;"src="'. 'images/green_check.png"></div>';
    } else {
        echo '<div style="color: #a94442;
                background-color: #f2dede;
                padding: 15px;
                margin-bottom: 20px;
                text-align:center;
                border:1px solid #E6B3B2;
                font-size:18pt;">TEST FAILED</div>
                <div style="color: #a94442;
                font-size:14pt;
                margin-bottom:20px;">WARNING: Some Attributes Did Not Match.</div>
                <div style="display:block;
                text-align:center;
                margin-bottom:4%;"><img style="width:15%;"src="'. 'images/wrong.png"></div>';
    }
        echo '<span style="font-size:14pt;">
                <b>Hello</b>, '.$useremail.'</span><br/>
                <p style="font-weight:bold;
                font-size:14pt;margin-left:1%;">ATTRIBUTES RECEIVED:</p>
                <table style="border-collapse:collapse;
                border-spacing:0;
                display:table;width:100%;
                font-size:14pt;
                background-color:#EDEDED;">
                <tr style="text-align:center;"><td style="font-weight:bold;
                border:2px solid #949090;
                padding:2%;">ATTRIBUTE NAME</td><td style="font-weight:bold;
                padding:2%;border:2px solid #949090; word-wrap:break-word;">ATTRIBUTE VALUE</td></tr>';
    if (!empty($attrs)) {
        foreach ($attrs as $key => $value) {
            echo "<tr><td style='font-weight:bold;
                        border:2px solid #949090;
                        padding:2%;'>" .$key . "</td><td style='padding:2%;
                        border:2px solid #949090;
                        word-wrap:break-word;'>" .implode("<hr/>", $value). "</td></tr>";
        }
    } else {
        echo "No Attributes Received.";
    }
    echo '</table></div>';
    echo '<div style="margin:3%;
            display:block;
            text-align:center;"><input style="padding:1%;
            width:100px;
            background: #0091CD none repeat scroll 0% 0%;
            cursor: pointer;font-size:15px;
            border-width: 1px;
            border-style: solid;
            border-radius: 3px;
            white-space: nowrap;
            box-sizing: border-box;
            border-color: #0073AA;
            box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;
            color: #FFF;"type="button" value="Done" onClick="self.close();"></div>';
    exit;
}
function create_authn_request($acsurl, $issuer, $forceauthn = 'false') {

    $requestxmlstr = '<?xml version="1.0" encoding="UTF-8"?>' .
                    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="' . generate_id() .
                    '" Version="2.0" IssueInstant="' . generate_timestamp() . '"';
    if ( $forceauthn == 'true') {
        $requestxmlstr .= ' ForceAuthn="true"';
    }
    $requestxmlstr .= ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="' . $acsurl .
                    '" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' . $issuer . '</saml:Issuer>
                    </samlp:AuthnRequest>';
    $deflatedstr = gzdeflate($requestxmlstr);
    $baseencodedstr = base64_encode($deflatedstr);
    $urlencoded = urlencode($baseencodedstr);
    return $urlencoded;
}
function auth_mo_saml_authenticate_user_login($accountmatcher, $userssaml, $samlcreate=false, $samlupdate=false) {
    global $CFG, $DB;
    $authsenabled = get_enabled_auth_plugins();
    $password = get_random_password();
    $created = false;
    // It is show user already created means false or new user means true after creating new user record.
    // Below $user array returns all posible attributes which can be update for user.
    // If user already exists then $user->id will non-zero number.
    // User- auth return way of user creation.(manual or any pluginname).
    if ($user = get_complete_user_data($accountmatcher, $userssaml[$accountmatcher])) {
        if ($user->auth == 'manual') {
            $samlupdate = 'false';
        }
        $auth = empty($user->auth) ? 'manual' : $user->auth;
        // If here no authentication plugin enabled then then it will show an error.
        if ($auth == 'nologin' or !is_enabled_auth($auth)) {
            $errormsg = '[client '.getremoteaddr().'] '.$CFG->wwwroot.'  --->  DISABLED_LOGIN: '.$userssaml[$accountmatcher];
            print_error($errormsg);
            return false;
        }
    } else {
        // If account matcher queryconditions detected 1 get_field of user and id return true means user already logedin.
        $queryconditions[$accountmatcher] = $userssaml[$accountmatcher];
        $queryconditions['deleted'] = 1;
        if ($DB->get_field('user', 'id', $queryconditions)) {
            $errormsg = '[client '.$_SERVER['REMOTE_ADDR'].'] '.  $CFG->wwwroot.'  --->  ALREADY LOGEDIN:
            '.$userssaml[$accountmatcher];
            print_error($errormsg);
            return false;
        }

        $auths = $authsenabled;
        $user = new stdClass();
        $user->id = 0;
    }
    // Selecting our mo_saml plugin for updating user data.
    $auth = 'mo_saml';
    $authplugin = get_auth_plugin($auth);
    if (!$authplugin->user_login($userssaml[$accountmatcher], $password)) {
        return;
    }
    if (!$user->id) {
        // For non existing user we create account here and make $created true.
        if ($samlcreate) {
            $user = create_user_record($userssaml[$accountmatcher], $password, $auth);
            $authplugin->sync_roles($user);
            // Synchronizing the role of user here.
            $created = true;
            // For new user created is true.
        }
    }
    // If user is created then we check its auth type, if user auth is not intialized then we created default mo_saml type.
    // We only update mo_saml auth type user .
    // For already created user no need to sync_roles of the user.
    // For help 'https://docs.moodle.org/dev/Data_manipulation_API'.
    if ($user->id && !$created) {
        if (empty($user->auth)) {
            $queryconditions['id'] = $user->id;
            $DB->set_field('user', 'auth', $auth, $queryconditions);
            $user->auth = $auth;
        }
        if ($samlupdate && $user->auth == 'mo_saml') {
            // Updating the attributes data coming into SAML response. If $samlupdate is true. only for idp user.
            if (empty($user->firstaccess)) {
                $queryconditions['id'] = $user->id;
                $DB->set_field('user', 'firstaccess', $user->timemodified, $queryconditions);
                $user->firstaccess = $user->timemodified;
            }
            if (!empty($userssaml['username']) && $user->username != $userssaml['username']) {
                $queryconditions['id'] = $user->id;
                $DB->set_field('user', 'username', $userssaml['username'], $queryconditions);
                $user->username = $userssaml['username'];
            }
            if (!empty($userssaml['email'])  && $user->email != $userssaml['email']) {
                $queryconditions['id'] = $user->id;
                $DB->set_field('user', 'email', $userssaml['email'], $queryconditions);
                $user->email = $userssaml['email'];
            }
            if (!empty($userssaml['firstname']) && $user->firstname != $userssaml['firstname']) {
                $queryconditions['id'] = $user->id;
                $DB->set_field('user', 'firstname', $userssaml['firstname'], $queryconditions);
                $user->firstname = $userssaml['firstname'];
            }
            if (!empty($userssaml['lastname']) && $user->lastname != $userssaml['lastname']) {
                $queryconditions['id'] = $user->id;
                $DB->set_field('user', 'lastname', $userssaml['lastname'], $queryconditions);
                $user->lastname = $userssaml['lastname'];
            }
            // If you want to Update role of already exiting user. Need to Uncomment below line;
            // Authplugin sync_roles user .
        }
    }

    foreach ($authsenabled as $authe) {
        $authes = get_auth_plugin($authe);
        $authes->user_authenticated_hook($user, $userssaml[$accountmatcher], $password);
    }
    if (!$user->id && !$samlcreate) {
        print_error("New coming User ". ' "'. $userssaml[$accountmatcher] . '" '
        . "not exists in moodle and auto-create is disabled");
        return false;
    }
    return $user;
}
// Get_random_password is method which generates random password for every non-manual user.
function get_random_password() {
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
    $pass = array();
    $alphalength = strlen($alphabet) - 1;
    for ($i = 0; $i < 7; $i++) {
        $n = rand(0, $alphalength);
        $pass[] = $alphabet[$n];
    }
    return implode($pass);
}
// Timestamp for instant issuer.
function generate_timestamp($instant = null) {
    if ($instant === null) {
        $instant = time();
    }
    return gmdate('Y-m-d\TH:i:s\Z', $instant);
}
// Id for saml request.
function generate_id() {
    return '_' .string_to_hex(generate_random_bytes(21));
}
// Value conversion method for string_to_hex.
function string_to_hex($bytes) {
    $ret = '';
    for ($i = 0; $i < strlen($bytes); $i++) {
        $ret .= sprintf('%02x', ord($bytes[$i]));
    }
    return $ret;
}
// Generate_random_bytes produce random bytes of given length.
function generate_random_bytes($length, $fallback = true) {
    assert('is_int($length)');
    return openssl_random_pseudo_bytes($length);
}
// Here we are checking Mapping attributes in plugin to coming saml attributes.
function mo_saml_checkmapping($attrs, $relaystate, $sessionindex) {
    try {
        $emailattribute = $config->emailmap;
        $usernameattribute = $config->usernamemap;
        $firstnamee = $config->firstnamemap;
        $lastnamee = $config->lastnamemap;
        $groupnamee = $config->defaultrolemap;
        $checkifmatchby = $config->accountmatcher;
        $useremail = '';
        $username = '';
        // Attribute mapping.
        // Check if Match or Create user is by username or email.
        if (!empty($attrs)) {
            if (!empty($firstnamee) && array_key_exists($firstnamee, $attrs)) {
                $firstnamee = $attrs[$firstnamee][0];
            } else {
                $firstnamee = '';
            }

            if (!empty($lastnamee) && array_key_exists($lastnamee, $attrs)) {
                $lastnamee = $attrs[$lastnamee][0];
            } else {
                $lastnamee = '';
            }

            if (!empty($usernameattribute) && array_key_exists($usernameattribute, $attrs)) {
                $username = $attrs[$usernameattribute][0];
            } else {
                $username = $attrs['NameID'][0];
            }
            if (!empty($emailattribute) && array_key_exists($emailattribute, $attrs)) {
                $useremail = $attrs[$emailattribute][0];
            } else {
                $useremail = $attrs['NameID'][0];
            }
            if (!empty($groupnamee) && array_key_exists($groupnamee, $attrs)) {
                $groupnamee = $attrs[$groupnamee];
            } else {
                $groupnamee = array();
            }

            if (empty($checkifmatchby)) {
                $checkifmatchby = 'email';
            }
            mo_saml_show_test_result($firstnamee, $lastnamee, $useremail, $groupnamee, $attrs);
            // It will change with version.
        }
    } catch (Exception $e) {
        echo sprintf('An error occurred while processing the SAML Response.');
        exit;
    }
}