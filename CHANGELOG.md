# Changelog

## [0.1.0dev4] - 2016-12-10
[Full Changelog](https://github.com/nahun/pfweb/compare/v0.1.0dev3...v0.1.0dev4)

### Added
- Session lifetime
- Direction icons in rules list
- Table name validation
- States details popover for each rule
- Table details popover in rules list
- Allow IPv6 NAT and RDR rules
- Interface selection for source and destination

### Fixed
- Fix default values in form fields
- Error 400 page receives username
- Fix reading interface media on dashboard
- Fix default answer in create_user script
- Fix IPv6 prefix length of 32 not showing

### Changed
- Formatting on dashboard for numbers
- Rename pfweb.py to app.py
- Show deprecated IPv6 addresses in dashboard
- Combine source and destination fields in states
- Only allow NAT when direction is set to out

## [0.1.0dev3] - 2016-11-29
[Full Changelog](https://github.com/nahun/pfweb/compare/0.1.0.dev2...v0.1.0dev3)

### Added
- Support for rdr-to and nat-to rules
- Initial support for global PF options in config file. State-policy is first.

### Fixed
- Fix save order button being enabled even when no row was selected
- Fix glyphicon font files not being installed with setuptools
- Some formatting and sorting when listing states
- Fix a previous fix of bootstrap css as now CSS and JS use their own directories

### Changed
- Disable and enable the port fields. Easier to remember to change the port type.

## [0.1.0dev2] - 2016-11-25
[Full Changelog](https://github.com/nahun/pfweb/compare/b6f7396...0.1.0.dev2)

### Added
- Ability to change the order of rules
- PF information on dashboard
- pf.conf is now saved after each change making them persistent
- Status menu items. Lists out entire PF info and the PF state table.

### Fixed
- Fix setting ICMP type to ANY

### Changed
- Autofocus on username field
- Move to all local JS and CSS files instead of CDNs

## [0.1.0dev1] - 2016-11-21
- Initial Release

[0.1.0dev4]: https://github.com/nahun/pfweb/tree/v0.1.0dev4
[0.1.0dev3]: https://github.com/nahun/pfweb/tree/v0.1.0dev3
[0.1.0dev2]: https://github.com/nahun/pfweb/tree/0.1.0.dev2
[0.1.0dev1]: https://github.com/nahun/pfweb/commit/b6f7396