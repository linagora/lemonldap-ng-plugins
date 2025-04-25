# How to update manager files

To update manager after applying a patch, use the following command _(adapt paths if needed)_:

```shell
$ perl -MLemonldap::NG::Manager::Build -e 'Lemonldap::NG::Manager::Build->run(
      structFile   => "/usr/share/lemonldap-ng/manager/htdocs/static/struct.json",
      confTreeFile => "/usr/share/lemonldap-ng/manager/htdocs/static/js/conftree.js",
      managerConstantsFile => "/usr/share/perl5/Lemonldap/NG/Common/Conf/ReConstants.pm",
      managerAttributesFile => "/usr/share/perl5/Lemonldap/NG/Manager/Attributes.pm",
      defaultValuesFile => "/usr/share/perl5/Lemonldap/NG/Common/Conf/DefaultValues.pm",
      confConstantsFile => "/usr/share/perl5/Lemonldap/NG/Common/Conf/Constants.pm",
      firstLmConfFile => "/var/lib/lemonldap-ng/conf/lmConf-1.json",
      reverseTreeFile => "/usr/share/lemonldap-ng/manager/htdocs/static/reverseTree.json",
      handlerStatusConstantsFile => "/usr/share/perl5/Lemonldap/NG/Handler/Lib/StatusConstants.pm",
      portalConstantsFile => "/dev/null",
      docConstantsFile => "/dev/null",
      )'
```
