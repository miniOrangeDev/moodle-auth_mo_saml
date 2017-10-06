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
 * This library is miniOrange Dictionary Service.
 *
 * Contains language oriented things.
 *
 * @copyright   2017  miniOrange
 * @category    dictionary
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     mo_saml
 */
$string['auth_mo_samltitle'] = 'miniOrange SAML SSO for moodle';
$string['auth_mo_samldescription'] = '';
$string['auth_mo_saml_form_has_errors'] = "The SAML settings form has errors";
$string['auth_mo_saml_create_or_update_warning'] = "When auto-provisioning or auto-update is enable,";
$string['auth_mo_saml_empty_required_value'] = "is a required attribute, provide a valid value";
$string['retriesexceeded'] = 'Maximum number of SAML connection retries exceeded  - there must be a problem with the Identity Service.<br />Please try again in a few minutes.';
$string['pluginauthfailed'] = 'The miniOrange SAML authentication plugin failed - user $a disallowed (no user auto-creation?) or dual login disabled.';
$string['pluginauthfailedusername'] = 'The miniOrange SAML authentication plugin failed - user $a disallowed due to invalid username format.';
$string['auth_mo_saml_username_email_error'] = 'The identity provider returned a set of data that does not contain the SAML username/email mapping field. Once of this field is required to login. <br />Please check your Username/Email Address Attribute Mapping configuration.';
$string['pluginname'] = 'miniOrange SAML 2.0 SSO';