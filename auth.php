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
 * This library is contain overridden moodle method.
 *
 * Contains authentication method.
 *
 * @copyright   2017  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     mo_saml
 */

global $CFG;
require_once('functions.php');
require_once('customer.php');
require_once($CFG->libdir.'/authlib.php');
/**
 * This class contains authentication plugin method
 *
 * @package    mo_saml
 * @category   authentication
 * @copyright  2017 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class auth_plugin_mo_saml extends auth_plugin_base {
    // Checking the value coming into this method is valid and empty.
    public function mo_saml_check_empty_or_null( $value ) {
        if ( ! isset( $value ) || empty( $value ) ) {
            return true;
        }
        return false;
    }
    // Constructor which has authtype, roleauth, and config variable initialized.
    public function __construct() {
        $this->authtype = 'mo_saml';
        $this->roleauth = 'auth_mo_saml';
        $this->config = get_config('auth/mo_saml');
    }
    // Checking curl installed or not. Return 1 if if present otherwise 0.
    public function mo_saml_is_curl_installed() {
        if (in_array  ('curl', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // Checking openssl installed or not. Return 1 if if present otherwise 0.
    public function mo_saml_is_openssl_installed() {
        if (in_array  ('openssl', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // Checking mcrypt installed or not. Return 1 if if present otherwise 0.
    public function mo_saml_is_mcrypt_installed() {
        if (in_array  ('mcrypt', get_loaded_extensions())) {
            return 1;
        } else {
            return 0;
        }
    }
    // User login return boolean value after checking username and password combination.
    public function user_login($username, $password) {
        global $SESSION;
        if (isset($SESSION->mo_saml_attributes)) {
            return true;
        }
        return false;
    }
    /*
    *function get_userinfo() called from index.php
    *Its purpose to rectify attributes coming froms saml with mapped attributes.
    *$samlattributes variable assigned by $SESSION->mo_saml_attributes which priviously saved in SESSION variable in index.php
    *get_attributes() method called to get all attributes variable mapped in plugin.
    *It will return $user array in which all attributes value according to mapped value.
    */
    public function get_userinfo($username = null) {
        global $SESSION;
        $samlattributes = $SESSION->mo_saml_attributes;
        // Reading saml attributes from session varible assigned before.
        $nameid = $SESSION->mo_saml_nameID;
        $mapping = $this->get_attributes();
        // Plugin attributes mapped values coming from get_attributes method of this class.
        if (empty($samlattributes)) {
            $username = $nameid;
            $email = $username;
        } else {
            // If saml is not empty.
            $usernamemapping = $mapping['username'];
            $mailmapping = $mapping['email'];
            if (!empty($usernamemapping) &&
            isset($samlattributes[$usernamemapping]) &&
            !empty($samlattributes[$usernamemapping][0])) {
                $username = $samlattributes[$usernamemapping][0];
            } else {
                $username = $samlattributes['NameID'][0];
                // If attribute mapping is possible for username then default username mapped with NameID.
            }
            if (!empty($mailmapping) && isset($samlattributes[$mailmapping]) && !empty($samlattributes[$mailmapping][0])) {
                $email = $samlattributes[$mailmapping][0];
            } else {
                $email = $samlattributes['NameID'][0];
                // If attribute mapping is possible for email then default email mapped with NameID.
            }
        }
        $user = array();
        // This array contain and return the value of attributes which are mapped.
        if (!empty($username)) {
            $user['username'] = $username;
        }
        if (!empty($email)) {
            $user['email'] = $email;
        }
        $firstnamemapping = $mapping['firstname'];
        // Plugin mapped variable firstname.
        $lastnamemapping = $mapping['lastname'];
        // Plugin mapped variable lastname.
        if (!empty($firstnamemapping) &&
        isset($samlattributes[$firstnamemapping]) &&
        !empty($samlattributes[$firstnamemapping][0])) {
            $user['firstname'] = $samlattributes[$firstnamemapping][0];
            // Assigning the value in user array by attribute value coming from saml response.
        }
        if (!empty($lastnamemapping) && isset($samlattributes[$lastnamemapping]) && !empty($samlattributes[$lastnamemapping][0])) {
            $user['lastname'] = $samlattributes[$lastnamemapping][0];
        }
        $accountmatcher = 'email';
        if (empty($accountmatcher)) {
            // Saml account matcher define which attribute is responsible for account creation.
            $accountmatcher = 'email';
            // Saml matcher is email if not selected.
        }
        if (($accountmatcher == 'username' && empty($user['username']) ||
            ($accountmatcher == 'email' && empty($user['email'])))) {
            $user = false;
        }
        return $user;
    }
    // Function get_attributes() called when we want mapped attributes variables in plugin.
    public function get_attributes() {
        $firstname = array_key_exists('firstnamemap', $this->config) ? $this->config->firstnamemap : '';
        $lastname = array_key_exists('lastnamemap', $this->config) ? $this->config->lastnamemap : '';

        $attributes = array (
            "username" => 'NameID',
            // NameID.
            "email" => 'NameID',
            // NameID.
            "firstname" => $firstname,
            "lastname" => $lastname,
        );
        return $attributes;
    }
    // Here we are assigning  role to user which is selected in role mapping.
    public function obtain_roles() {
        global $SESSION;
        $roles = 'Manager';
        if (!empty($this->config->defaultrolemap) && isset($this->config->defaultrolemap)) {
            $roles = $this->config->defaultrolemap;
        }
        return $roles;
    }
    // Sync roles assigne the role for new user if role mapping done in default role.
    public function sync_roles($user) {
        global $CFG, $DB;
        $newrole = $this->obtain_roles();

        if ('siteadmin' == $newrole) {

            $siteadmins = explode(',', $CFG->siteadmins);
            if (!in_array($user->id, $siteadmins)) {
                $siteadmins[] = $user->id;
                $newadmins = implode(',', $siteadmins);
                set_config('siteadmins', $newadmins);
            }
        }
        $role = $newrole;
        $syscontext = context_system::instance();

        $assignedrole = $DB->get_record('role', array('shortname' => $role), '*', MUST_EXIST);
        role_assign($assignedrole->id, $user->id, $syscontext);
    }
    // Returns true if this authentication plugin is internal.
    // Internal plugins use password hashes from Moodle user table for authentication.
    public function is_internal() {
        return false;
    }
    // Indicates if password hashes should be stored in local moodle database.
    // This function automatically returns the opposite boolean of what is_internal() returns.
    // Returning true means MD5 password hashes will be stored in the user table.
    // Returning false means flag 'not_cached' will be stored there instead.
    public function prevent_local_passwords() {
        return true;
    }
    // Returns true if this authentication plugin can change users' password.
    public function can_change_password() {
        return false;
    }
    // Returns true if this authentication plugin can edit the users' profile.
    public function can_edit_profile() {
        return true;
    }
    // Hook for overriding behaviour of login page.
    public function loginpage_hook() {
        global $CFG;
        $CFG->nolastloggedin = true;
            ?>
            <script src='../auth/mo_saml/includes/js/jquery.min.js'></script>
            <script>$(document).ready(function(){
                $('<a class = "btn btn-primary btn-block m-t-1" href="<?php echo $CFG->wwwroot.'/auth/mo_saml/index.php';
                ?>">Login with <?php echo($this->config->identityname); ?> </a>').insertAfter('#loginbtn')
            });</script>
            <?php

    }
    // Hook for overriding behaviour of logout page.
    public function logoutpage_hook() {
        global $SESSION, $CFG;
        $logouturl = $CFG->wwwroot.'/login/index.php?saml_sso=false';
        require_logout();
        set_moodle_cookie('nobody');
        redirect($logouturl);
    }
    // Prints a form for configuring this authentication plugin.
    // It's called from admin/auth.php, and outputs a full page with a form for configuring this plugin.
    public function config_form($config, $err, $userfields) {
        include('config.html');
        // Including page for setting up the plugin data.
    }
    // Validate form data.
    public function validate_form($form, &$err) {
        // Registeration of plugin also submitting a form which is validating here.
        if (isset($_POST['option']) and $_POST[ 'option' ] == 'mo_saml_register_customer') {
            if ( $this->mo_saml_check_empty_or_null( $_POST['email'] ) ||
                $this->mo_saml_check_empty_or_null( $_POST['password'] ) ||
                $this->mo_saml_check_empty_or_null( $_POST['confirmpassword'] ) ||
                $this->mo_saml_check_empty_or_null( $_POST['company'] )) {
                $err['requiredfield'] = 'Please enter the required fields.';
            } else if ( strlen( $_POST['password'] ) < 6 || strlen( $_POST['confirmpassword'] ) < 6) {
                $err['passwordlengtherr'] = 'Choose a password with minimum length 6.';
            }
        }
        // Service provider tab data validate here.
        if (isset($_POST['option']) and $_POST[ 'option' ] == 'save') {
            if (empty($form->samlissuer)) {
                $err['issuerurlempty'] = 'Please enter the IdP Entity ID or Issuer field.';
            }
            if (empty($form->loginurl)) {
                $err['targeturlempty'] = 'Please enter the SAML Login URL field.';
            }
        }
        // Attribute /Role mapping data are validate here.
        if (isset($_POST['option']) and $_POST[ 'option' ] == 'opt') {
            if (empty($form->firstnamemap)) {
                $err['saml_firstname_map_err'] = 'Please enter the FirstName field.';
            }
            if (empty($form->lastnamemap)) {
                $err['saml_lastname_map_err'] = 'Please enter the LastName field.';
            }
            if (empty($form->defaultrolemap)) {
                $err['saml_default_role_map_err'] = 'Please enter the Default Role field.';
            }
        }
    }
    // Processes and stores configuration data for this authentication plugin.
    public function process_config($config) {
        global $CFG;
        // CFG contain base url for the moodle.
        $config = get_config('auth/mo_saml');
        set_config('hostname', 'https://auth.miniorange.com', 'auth/mo_saml');
        // Set host url here for rgister and login purpose of plugin.
        $actuallink = $_SERVER['HTTP_REFERER'];
        if (isset($_POST['option']) and $_POST[ 'option' ] == 'mo_saml_register_customer') {
            if (!isset($_POST['email'])) {
                $config->email = '';
            }
            if (!isset($_POST['company'])) {
                $config->company = '';
            }
            if (!isset($_POST['regfirstname'])) {
                $config->regfirstname = '';
            }
            if (!isset($_POST['reglastname'])) {
                $config->reglastname = '';
            }
            if (!isset($_POST['phone'])) {
                $config->phone = '';
            }
            if (!isset($_POST['password'])) {
                $config->password = '';
            }
            if (!isset($_POST['confirmpassword'])) {
                $config->confirmpassword = '';
            }
            if (!isset($config->transactionid)) {
                $config->transactionid = '';
            }
            if (!isset($config->registrationstatus)) {
                $config->registrationstatus = '';
            }
            set_config('email', $_POST['email'], 'auth/mo_saml');
            set_config('company', $_POST['company'], 'auth/mo_saml');
            set_config('regfirstname', $_POST['regfirstname'], 'auth/mo_saml');
            set_config('reglastname', $_POST['reglastname'], 'auth/mo_saml');
            set_config('phone', $_POST['phone'], 'auth/mo_saml');
            if ( strcmp( $_POST['password'], $_POST['confirmpassword']) == 0 ) {
                set_config('password', $_POST['password'], 'auth/mo_saml');
                $customer = new customer_saml();
                $content = json_decode($customer->check_customer(), true);
                if ( strcasecmp( $content['status'], 'CUSTOMER_NOT_FOUND') == 0 ) {
                    $content = json_decode($customer->send_otp_token($config->email, ''), true);
                    if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                        set_config('transactionid', $content['txId'], 'auth/mo_saml');
                        set_config('registrationstatus', 'MO_OTP_DELIVERED_SUCCESS_EMAIL', 'auth/mo_saml');
                    } else {
                        set_config('registrationstatus', 'MO_OTP_DELIVERED_FAILURE_EMAIL', 'auth/mo_saml');
                    }
                } else {
                    $this->get_current_customer();
                }

            } else {
                set_config('verifycustomer', '', 'auth/mo_saml');
            }
            redirect($actuallink);
            return true;
        }
        if (isset($_POST['option']) and $_POST['option'] == 'mo_saml_validate_otp') {
            // Validation and sanitization.
            $otptoken = '';
            if ( $this->mo_saml_check_empty_or_null( $_POST['otp_token'] ) ) {
                echo('registrationstatus-MO_OTP_VALIDATION_FAILURE');
                return;
            } else {
                $otptoken = $_POST['otp_token'];
            }
            $customer = new customer_saml();
            $content = json_decode($customer->validate_otp_token($config->transactionid, $otptoken ), true);
            if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                $this->create_customer();
            } else {
                // Invalid one time passcode. Please enter a valid otp.
                echo('registrationstatus-MO_OTP_VALIDATION_FAILURE');
            }
            redirect($actuallink);
            return true;
        }
        if ( isset( $_POST['option'] ) and $_POST['option'] == 'verifycustomer' ) {
            if (!isset($config->email)) {
                $config->email = '';
            }
            if (!isset($config->password)) {
                $config->password = '';
            }
            set_config('email', trim($_POST['email']), 'auth/mo_saml');
            set_config('password', trim($_POST['password']), 'auth/mo_saml');
            $config = get_config('auth/mo_saml');
            $customer = new customer_saml();
            $content = $customer->get_customer_key();
            $customerkey = json_decode( $content, true );
            if ( json_last_error() == JSON_ERROR_NONE ) {
                set_config( 'admincustomerkey', $customerkey['id'] , 'auth/mo_saml');
                set_config( 'adminapikey', $customerkey['apiKey'], 'auth/mo_saml' );
                set_config( 'customertoken', $customerkey['token'] , 'auth/mo_saml');
                set_config( 'mo_saml_admin_phone', $customerkey['phone'], 'auth/mo_saml' );
                $certificate = $config->samlxcertificate;
                if (empty($certificate)) {
                    set_config( 'freeversion', 1 , 'auth/mo_saml');
                }
                set_config('mo_saml_admin_password', '', 'auth/mo_saml');
                set_config('registrationstatus', 'Existing User', 'auth/mo_saml');
                set_config('verifycustomer', '', 'auth/mo_saml');
            } else {
                // Invalid username or password. Please try again.
                echo('code for showing message');
            }
            set_config('mo_saml_admin_password', '', 'auth/mo_saml');
            redirect($actuallink);
            return true;
        } else if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_saml_contact_us_query_option' ) {
            // Contact Us query.
            $email = $_POST['mo_saml_contact_us_email'];
            $phone = $_POST['mo_saml_contact_us_phone'];
            $query = $_POST['mo_saml_contact_us_query'];
            $customer = new customer_saml();
            if ( $this->mo_saml_check_empty_or_null( $email ) || $this->mo_saml_check_empty_or_null( $query ) ) {
                redirect($actuallink);
            } else {
                $submited = $customer->submit_contact_us( $email, $phone, $query );
                if ( $submited == false ) {
                    echo('Error During Query Submit');exit;
                } else {
                    echo('Query Submitted By You...');
                    redirect($CFG->wwwroot.'/admin/auth_config.php?auth=mo_saml&tab=config');
                    return true;
                }
            }
        } else if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_saml_resend_otp_email') {
            $email = $config->email;
            $customer = new customer_saml();
            $content = json_decode($customer->send_otp_token($email, ''), true);
            if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                    set_config('transactionid', $content['txId'], 'auth/mo_saml');
                    set_config('registrationstatus', 'MO_OTP_DELIVERED_SUCCESS_EMAIL', 'auth/mo_saml');
            } else {
                    set_config('registrationstatus', 'MO_OTP_DELIVERED_FAILURE_EMAIL', 'auth/mo_saml');
            }
            redirect($actuallink);
            return true;
        } else if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_saml_resend_otp_phone' ) {
            $phone = $config->phone;
            $customer = new customer_saml();
            $content = json_decode($customer->send_otp_token('', $phone, false, true), true);
            if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                    set_config('transactionid', $content['txId'], 'auth/mo_saml');
                    set_config('registrationstatus', 'MO_OTP_DELIVERED_SUCCESS_PHONE', 'auth/mo_saml');
            } else {
                    set_config('registrationstatus', 'MO_OTP_DELIVERED_FAILURE_PHONE', 'auth/mo_saml');
            }
            redirect($actuallink);
            return true;
        }
        if (isset( $_POST['option'] ) and $_POST['option'] == 'mo_saml_go_back' ) {
            set_config('registrationstatus', '', 'auth/mo_saml');
            set_config('verifycustomer', '', 'auth/mo_saml');
            set_config('newregistration', '', 'auth/mo_saml');
            set_config('adminemail', '', 'auth/mo_saml');
            set_config('mo_saml_admin_phone', '', 'auth/mo_saml');
            redirect($actuallink);
            return true;
        } else if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_saml_register_with_phone_option' ) {
            $phone = $_POST['phone'];
            $phone = str_replace(' ', '', $phone);
            $phone = str_replace('-', '', $phone);
            set_config('phone', $phone, 'auth/mo_saml');
            $customer = new customer_saml();
            $content = json_decode($customer->send_otp_token('', $phone, false, true), true);
            if (strcasecmp($content['status'], 'SUCCESS') == 0) {
                set_config('transactionid', $content['txId'], 'auth/mo_saml');
                set_config('registrationstatus', 'MO_OTP_DELIVERED_SUCCESS_PHONE', 'auth/mo_saml');
            } else {
                set_config('registrationstatus', 'MO_OTP_DELIVERED_FAILURE_PHONE', 'auth/mo_saml');
            }
            redirect($actuallink);
            return true;
        }
        if (isset( $_POST['option'] ) and $_POST[ 'option' ] == 'save') {
            if (!isset($config->identityname)) {
                $config->identityname = '';
            }
            if (!isset($config->loginurl)) {
                $config->loginurl = '';
            }
            if (!isset($config->samlissuer)) {
                $config->samlissuer = '';
            }
            if (!isset($config->samlxcertificate)) {
                $config->samlxcertificate = '';
            }
            $certificatex = trim($_POST['samlxcertificate']);
            $certificatex = $this->sanitize_certificate($_POST['samlxcertificate']);
            set_config('identityname', trim($_POST['identityname']), 'auth/mo_saml');
            set_config('admincustomerkey', '', 'auth/mo_saml');
            set_config('loginurl', trim($_POST['loginurl']), 'auth/mo_saml');
            set_config('samlissuer', trim($_POST['samlissuer']), 'auth/mo_saml');
            set_config('samlxcertificate', trim($certificatex), 'auth/mo_saml');
            redirect($actuallink);
            return true;
        }
        if ( isset( $_POST['option'] ) and $_POST['option'] == 'general') {
            if (!isset($config->saml_auto_create_users)) {
                $config->saml_auto_create_users = 'on';
            }
            if (!isset($config->saml_auto_update_users)) {
                $config->saml_auto_update_users = 'on';
            }
            if (!isset($config->enablebackdoor)) {
                $config->enablebackdoor = 'on';
            }
            if (!isset($config->enableloginredirect)) {
                $config->enableloginredirect = '';
            }

            set_config('saml_auto_create_users', trim($_POST['saml_auto_create_users']), 'auth/mo_saml');
            set_config('enablebackdoor', trim($_POST['enablebackdoor']), 'auth/mo_saml');
            set_config('enableloginredirect', trim($_POST['mo_saml_enable_login_redirec']), 'auth/mo_saml');
            set_config('saml_auto_update_users', trim($_POST[$config->saml_auto_update_users]), 'auth/mo_saml');
            redirect($actuallink);
            return true;
        }
        if (isset( $_POST['option'] ) and $_POST[ 'option' ] == 'opt') {
            if (!isset($config->accountmatcher)) {
                $config->accountmatcher = 'email';
            }
            if (!isset($config->usernamemap)) {
                $config->usernamemap = 'NameID';
            }
            if (!isset($config->emailmap)) {
                $config->emailmap = 'NameID';
            }
            if (!isset($config->firstnamemap)) {
                $config->firstnamemap = '';
            }
            if (!isset($config->lastnamemap)) {
                $config->lastnamemap = '';
            }
            if (!isset($config->rolemap)) {
                $config->rolemap = 'owner';
            }
            if (!isset($config->defaultrolemap)) {
                $config->defaultrolemap = '';
            }
            set_config('accountmatcher', trim($_POST['accountmatcher']), 'auth/mo_saml');
            set_config('usernamemap', 'NameID', 'auth/mo_saml');
            set_config('emailmap', 'NameID', 'auth/mo_saml');
            set_config('firstnamemap', trim($_POST['firstnamemap']), 'auth/mo_saml');
            set_config('lastnamemap', trim($_POST['lastnamemap']), 'auth/mo_saml');
            set_config('defaultrolemap', trim($_POST['defaultrolemap']), 'auth/mo_saml');
            redirect($actuallink);
            return true;
        }
        return true;
    }
    public function sanitize_certificate( $certificate ) {
        $certificate = preg_replace("/[\r\n]+/", '', $certificate);
        $certificate = str_replace( "-", '', $certificate );
        $certificate = str_replace( "BEGIN CERTIFICATE", '', $certificate );
        $certificate = str_replace( "END CERTIFICATE", '', $certificate );
        $certificate = str_replace( " ", '', $certificate );
        $certificate = chunk_split($certificate, 64, "\r\n");
        $certificate = "-----BEGIN CERTIFICATE-----\r\n" . $certificate . "-----END CERTIFICATE-----";
        return $certificate;
    }
    public function create_customer() {
        global $CFG;
        $customer = new customer_saml();
        $customerkey = json_decode( $customer->create_customer(), true );
        if ( strcasecmp( $customerkey['status'], 'CUSTOMER_USERNAME_ALREADY_EXISTS') == 0 ) {
                    $this->get_current_customer();
        } else if ( strcasecmp( $customerkey['status'], 'SUCCESS' ) == 0 ) {
            set_config( 'admincustomerkey', trim($customerkey['id']), 'auth/mo_saml' );
            set_config( 'adminapikey', $customerkey['apiKey'], 'auth/mo_saml');
            set_config( 'customertoken', $customerkey['token'], 'auth/mo_saml');
            set_config( 'freeversion', 1, 'auth/mo_saml' );
            set_config('password', '', 'auth/mo_saml');
            set_config('registrationstatus', '', 'auth/mo_saml');
            set_config('verifycustomer', '', 'auth/mo_saml');
            set_config('newregistration', '', 'auth/mo_saml');
            redirect($CFG->wwwroot.'/admin/auth_config.php?auth=mo_saml&tab=config');
        }
        set_config('password', '', 'auth/mo_saml');
    }
    // Getting customer which is already created at host for login purpose.
    public function get_current_customer() {
        global $CFG;
        $customer = new customer_saml();
        $content = $customer->get_customer_key();
        $customerkey = json_decode( $content, true );
        if ( json_last_error() == JSON_ERROR_NONE ) {
            set_config( 'admincustomerkey', trim($customerkey['id']), 'auth/mo_saml' );
            set_config( 'adminapikey', $customerkey['apiKey'] , 'auth/mo_saml');
            set_config( 'customertoken', $customerkey['token'] , 'auth/mo_saml');
            set_config('password', '', 'auth/mo_saml');
            $certificate = $this->config->samlxcertificate;
            if (empty($certificate)) {
                set_config( 'freeversion', 1, 'auth/mo_saml' );
            }
            set_config('verifycustomer', '', 'auth/mo_saml');
            set_config('newregistration', '', 'auth/mo_saml');
            redirect($CFG->wwwroot.'/admin/auth_config.php?auth=mo_saml&tab=config');
        } else {
            set_config('verifycustomer', 'true', 'auth/mo_saml');
            set_config('newregistration', '', 'auth/mo_saml');
        }
    }
    // The page show in test configuration page.
    public function test_settings() {
        global $CFG;
        echo ' <iframe style="width: 690px;height: 790px;" src="'
        .$CFG->wwwroot.'/auth/mo_saml/index.php/?option=testConfig"></iframe>';
    }
}