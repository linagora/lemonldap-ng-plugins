# Matrix plugin

This plugin allow a Matrix client to exchange its Matrix `access_token` to
get a LLNG `access_token`. Files:

- [Lemonldap::NG::Portal::Plugins::MatrixTokenExchange](./MatrixTokenExchange.pm) with its dependency [Lemonldap::NG::Common::Matrix](./Matrix.pm)
- A [patch for the manager](./manager.patch). Then remember to rebuild other files:
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
