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
 * Contains important method for customer registration.
 *
 * @copyright   2017  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     mo_saml
 */
 defined('MOODLE_INTERNAL') || die();
/**
 * Auth external functions
 *
 * @package    mo_saml
 * @category   registration
 * @copyright  2017 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class customer_saml {
    public $email;
    /** @var $email contains email of admin.*/
    public $phone;
    /** @var $phone contains phone number of admin.*/
    /*
     * * Initial values are hardcoded to support the miniOrange framework to generate OTP for email.
     * * We need the default value for creating the first time,
     * * As we don't have the Default keys available before registering the user to our server.
     * * This default values are only required for sending an One Time Passcode at the user provided email address.
     */
    private $defaultcustomerkey = '16555';
    /** @var $defaultcustomerkey contains default customer key of admin.*/
    private $defaultapikey = 'fFd2XcvTGDemZvbw1bcUesNJWEqKbbUq';
    /** @var $defaultapikey contains default api key of admin.*/

    public function create_customer() {
        $config = get_config('auth/mo_saml');
        $url = $config->hostname.'/moas/rest/customer/add';
        $ch = curl_init ( $url );
        $this->email = $config->email;
        $this->phone = $config->phone;
        $password = $config->password;
        $regfirstname = $config->regfirstname;
        $reglastname = $config->reglastname;
        $company = $config->company;
        $fields = array (
                'companyName' => $company,
                'areaOfInterest' => 'Moodle miniOrange SAML 2.0 SSO Plugin',
                'firstname' => $regfirstname,
                'lastname' => $reglastname,
                'email' => $this->email,
                'phone' => $this->phone,
                'password' => $password
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF - 8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function get_customer_key() {
        $config = get_config('auth/mo_saml');
        $url = $config->hostname.'/moas/rest/customer/key';
        $ch = curl_init ( $url );
        $email = $config->email;
        $password = $config->password;
        $fields = array (
                'email' => $email,
                'password' => $password
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF - 8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function check_customer() {
        $config = get_config('auth/mo_saml');
        $url = $config->hostname.'/moas/rest/customer/check-if-exists';
        $ch = curl_init ( $url );
        $email = $config->email;
        $fields = array (
                'email' => $email
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF - 8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );

        return $content;
    }
    public function send_otp_token($email, $phone, $sendtoemail = true, $sendtophone = false) {
        $config = get_config('auth/mo_saml');
        $url = $config->hostname.'/moas/api/auth/challenge';
        $ch = curl_init ( $url );
        $customerkey = $this->defaultcustomerkey;
        $apikey = $this->defaultapikey;
        // Current time in milliseconds since midnight, January 1, 1970 UTC.
        $currenttimeinmillis = round ( microtime ( true ) * 1000 );
        // Creating the Hash using SHA-512 algorithm.
        $stringtohash = $customerkey . number_format ( $currenttimeinmillis, 0, '', '' ) . $apikey;
        $hashvalue = hash ( 'sha512', $stringtohash );
        $customerkeyheader = 'Customer-Key: ' . $customerkey;
        $timestampheader = 'Timestamp: ' . number_format ( $currenttimeinmillis, 0, '', '' );
        $authorizationheader = 'Authorization: ' . $hashvalue;
        if ($sendtoemail) {
            $fields = array (
                    'customerKey' => $customerkey,
                    'email' => $email,
                    'authType' => 'EMAIL',
                    'transactionName' => 'Moodle miniOrange SAML 2.0 SSO Plugin'
            );
        } else {
            $fields = array (
                    'customerKey' => $customerkey,
                    'phone' => $phone,
                    'authType' => 'SMS',
                    'transactionName' => 'Moodle miniOrange SAML 2.0 SSO Plugin'
            );
        }
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                $customerkeyheader,
                $timestampheader,
                $authorizationheader
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function validate_otp_token($transactionide, $otptoken) {
        $config = get_config('auth/mo_saml');
        $url = $config->hostname.'/moas/api/auth/validate';
        $ch = curl_init ( $url );
        $customerkey = $this->defaultcustomerkey;
        $apikey = $this->defaultapikey;
        $username = $config->email;
        // Current time in milliseconds since midnight, January 1, 1970 UTC.
        $currenttimeinmillis = round ( microtime ( true ) * 1000 );
        // Creating the Hash using SHA-512 algorithm.
        $stringtohash = $customerkey . number_format ( $currenttimeinmillis, 0, '', '' ) . $apikey;
        $hashvalue = hash ( 'sha512', $stringtohash );
        $customerkeyheader = 'Customer-Key: ' . $customerkey;
        $timestampheader = 'Timestamp: ' . number_format ( $currenttimeinmillis, 0, '', '' );
        $authorizationheader = 'Authorization: ' . $hashvalue;
        $fields = '';
        // Check for otp over sms/email.
        $fields = array (
                'txId' => $transactionide,
                'token' => $otptoken
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                $customerkeyheader,
                $timestampheader,
                $authorizationheader
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function submit_contact_us($email, $phone, $query) {
        $config = get_config('auth/mo_saml');
        $query = '[MOODLE SAML 2.0 SP SSO Plugin] ' . $query;
        $fields = array (
                'firstname' => $config->regfirstname,
                'lastname' => $config->reglastname,
                'company' => $_SERVER ['SERVER_NAME'],
                'email' => $email,
                'phone' => $phone,
                'query' => $query
        );
        $fieldstring = json_encode ( $fields );
        $url = $config->hostname.'/moas/rest/customer/contact-us';
        $ch = curl_init ( $url );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF-8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );

        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            return false;
        }
        curl_close ( $ch );
        return true;
    }
    public function save_external_idp_config() {
        global $CFG;
        $config = get_config('auth/mo_saml');
        $url = $config->hostname.'/moas/rest/saml/save-configuration';
        $ch = curl_init ( $url );
        $this->email = $config->email;
        $this->phone = $config->phone;
        $idptype = 'saml';
        $identifier = $config->identityname;
        $acsurl = $url;
        $password = $config->password;
        $custid = $config->admincustomerkey;
        $samlloginurl = $config->loginurl;
        $samlissuer = $config->samlissuer;
        $samlx509certificate = $config->samlxcertificate;
        $assertionsigned = 'true';
        $responsesigned = 'false';
        $fields = array (
                'customerId' => $custid,
                'idpType' => $idptype,
                'identifier' => $identifier,
                'samlLoginUrl' => $samlloginurl,
                'samlLogoutUrl' => $samlloginurl,
                'idpEntityId' => $samlissuer,
                'samlX509Certificate' => $samlx509certificate,
                'assertionSigned' => $assertionsigned,
                'responseSigned' => $responsesigned,
                'overrideReturnUrl' => 'true',
                'returnUrl' => $CFG->wwwroot. '/?option=readsamllogin'
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                'charset: UTF - 8',
                'Authorization: Basic'
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
    public function mo_saml_forgot_password($email) {
        $config = get_config('auth/mo_saml');
        $url = $config->hostname.'/moas/rest/customer/password-reset';
        $ch = curl_init ( $url );
        // The customer Key provided to you.
        $customerkey = $config->admincustomerkey;
        // The customer API Key provided to you.
        $apikey = $config->adminapikey;
        // Current time in milliseconds since midnight, January 1, 1970 UTC.
        $currenttimeinmillis = round ( microtime ( true ) * 1000 );
        // Creating the Hash using SHA-512 algorithm.
        $stringtohash = $customerkey . number_format ( $currenttimeinmillis, 0, '', '' ) . $apikey;
        $hashvalue = hash ( 'sha512', $stringtohash );
        $customerkeyheader = 'Customer-Key: ' . $customerkey;
        $timestampheader = 'Timestamp: ' . number_format ( $currenttimeinmillis, 0, '', '' );
        $authorizationheader = 'Authorization: ' . $hashvalue;
        $fields = '';
        // Check for otp over sms/email.
        $fields = array (
                'email' => $email
        );
        $fieldstring = json_encode ( $fields );
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, '' );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
        // Required for https urls.
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
                'Content-Type: application/json',
                $customerkeyheader,
                $timestampheader,
                $authorizationheader
        ) );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fieldstring );
        curl_setopt ( $ch, CURLOPT_CONNECTTIMEOUT, 5 );
        curl_setopt ( $ch, CURLOPT_TIMEOUT, 20 );
        $content = curl_exec ( $ch );
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }
        curl_close ( $ch );
        return $content;
    }
}