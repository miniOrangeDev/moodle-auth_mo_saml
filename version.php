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
 * Contains version related information.
 *
 * @copyright   2017  miniOrange
 * @category    document
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     mo_saml
 */
defined('MOODLE_INTERNAL') || die();
$plugin->requires = 2015040500;   // Requires Moodle 2.9 or less.
$plugin->release = 'v1.0-r2';
$plugin->component = 'auth_mo_saml';
$plugin->version = 2017100501;    // YYYYMMDDXX.
$plugin->cron = 0;     // Time in sec.
$plugin->maturity = MATURITY_STABLE;